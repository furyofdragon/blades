#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import paramiko
import re
import time
import subprocess
import sqlite3
import json
import requests
import urllib3
import logging
import glob
import os
from collections import OrderedDict
from datetime import datetime
from pyzabbix import ZabbixAPI
from curses.ascii import isspace
from concurrent.futures import ThreadPoolExecutor

# ============= Common variables =========================
groupID = "50" # CMC (hostgroup in zabbix with M1000E or VRTX chassis)
zabbix1 = 'zabbix' # or IP
z_url = "https://zabbix/"
z_u = "api"
z_p = "<secret>"
cmc_u = "data"
cmc_p = "<secret>"
cmc_u1 = "data2"
cmc_p1 = "<secret2>"
glpi_url = 'https://glpi/glpi/apirest.php'
glpi_atoken = '<your_token>'
glpi_utoken = '<your_token>'
glpi_url_start = 'https://glpi/'
db_f = '/opt/cmcdb/blades.db'
thlimit = 20
f_log = '/var/log/blades.log'

DB_keys = ('cmc', 'slot', 'tag', 'type', 'name', 'powerstate', 'biosver', 'idracver', 'idracip', 'gen', 'bmcmac', 'nic1mac', 'nic2mac', 'glpiurl', 'glpicomm',
          'note', 'recorddate', 'recordactive')
# ========================================================


def get_current_time():
    '''
    insert all timestamps in equal format
    '''
    # return int(time.time())
    return datetime.utcfromtimestamp(int(time.time())).strftime('%Y-%m-%d %H:%M:%S')


def insert_new_data(conn, new_data):
    try:
        with conn:
            query = '''insert into blades_data (''' + ', '.join(DB_keys) + ''') values (''' + ', '.join(['' + '?' for k in DB_keys]) + ''')'''
            conn.execute(query, new_data)
    except Exception as e:
        print('Error occured: ', e, 'insert', new_data)
        logging.error(str(e) + ' insert ' + new_data)


def db_get_blade(conn, cmc, slot):
    try:
        result = conn.execute('select * from blades_data where cmc = "' + cmc + '" and slot = "' + slot + '" and recordactive = "1" order by recorddate desc')
        blades = []
        for r in result:
            blades.append([r[k] for k in DB_keys[:-3]])
        if len(blades) > 0:
            return blades[0]
        else:
            return None
    except Exception as e:
        print('Error occured: ', e, 'get cmc', cmc, 'slot', slot)
        logging.error(str(e) + ' get cmc ' + cmc + ' slot ' + slot)
        return None


def db_get_cmcblades(conn, cmc):
    try:
        res = conn.execute("select * from blades_data where cmc = '" + cmc + "' and recordactive = '1' order by slot asc")
        blades = []
        for r in res:
            blades.append([r[k] for k in DB_keys])
        if len(blades) > 0:
            return blades
        else:
            return None
    except Exception as e:
        print('Error occured: ', e, 'get cmc', cmc)
        logging.error(str(e) + ' get cmc ' + cmc)
        return None


def db_get_allcmc(conn):
    try:
        res = conn.execute("select distinct(cmc) from blades_data where recordactive = '1' order by cmc asc")
        db_cmc = []
        for r in res:
            db_cmc.append(r['cmc'])
        return db_cmc
    except Exception as e:
        print('Error occured: ', e, 'get all')
        logging.error(str(e) + ' get all')
        return None


def db_remove_cmc(conn, cmc):
    '''
    instead of real remove data duplicates all active records with current date and mark all records as inactive
    '''
    unixtime = get_current_time()
    try:
        result = [row for row in conn.execute('select * from blades_data where cmc = "' + cmc + '" and recordactive = "1"')]
        for r in result:
            new_data = []
            new_data.append([r[k] for k in DB_keys])
            # correct unixtime for 'recorddate'
            new_data[0][len(DB_keys)-2] = unixtime
            insert_new_data(conn, new_data)
        conn.execute('update blades_data set recordactive = "0" where cmc = "' + cmc + '"')
    except Exception as e:
        print('Error occured: ', e, 'remove cmc', cmc)
        logging.error(str(e) + ' remove cmc ' + cmc)


def db_remove_slot(conn, cmc, slot):
    '''
    instead of real remove data duplicates all active records with current date and mark all records as inactive
    '''
    unixtime = get_current_time()
    try:
        if slot is not None:
            result = [row for row in conn.execute('select * from blades_data where cmc = "' + cmc + '" and slot = "' + slot + '" and recordactive = "1"')]
            for r in result:
                new_data = []
                new_data.append([r[k] for k in DB_keys])
                # correct unixtime for 'recorddate'
                new_data[0][len(DB_keys)-2] = unixtime
                insert_new_data(conn, new_data)
            conn.execute('update blades_data set recordactive = "0" where cmc = "' + cmc + '" and slot = "' + slot + '"')
    except Exception as e:
        print('Error occured: ', e, 'remove cmc', cmc, 'slot', slot)
        logging.error(str(e) + ' remove cmc ' + cmc + ' slot ' + slot)


def getzabbixcmc():
    #zapi = ZabbixAPI(z_url)
    #zapi.session.verify = False
    #zapi.login(z_u, z_p)
    zapi = ZabbixAPI(url=z_url, user=z_u, password=z_p)

    hosts = zapi.do_request('host.get', {
        "groupids" : groupID,
        "output": ["host", "status"],
        "filter": {"status": "0"},
        "sortfield" : "host"
        })['result']

    res = [h['host'] for h in hosts]

    zapi.user.logout()
    return res


def getcmdoutput(client, cmd):
    try:
        stdin, stdout, stderr = client.exec_command(cmd)
    except:
        data=''
    else:
        data = stdout.read() + stderr.read()
    try:
        return data.decode('utf-8')
    except Exception as e:
        logging.error(str(e))
        return data


def cmc_connect(cmc_host, user, secret):
    retries_count = 3
    retries_sleep = 10
    retries_status = False
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    while retries_count > 0 and retries_status == False:
        try:
            client.connect(hostname = cmc_host, username = user, password = secret, port = 22)
            retries_status = True
        except Exception as e:
            print('Connecting to ', cmc_host, ' :', e)
            logging.error('Connecting to ' + cmc_host + ' : ' + str(e))
            retries_count -= 1
        time.sleep(retries_sleep)
    if retries_status == False:
        print("Can't connect to " + cmc_host)
        logging.error("Can't connect to " + cmc_host)
        return "Error"
    else:
        return client


def get_glpi_data(svcTag):
    urllib3.disable_warnings()

    # tag could be empty or N/A
    if svcTag is None or svcTag == 'N/A' or svcTag == '' or svcTag.isspace():
        GlpiComment = None
        GlpiUrl = None
    else:
        h0 = {"Content-Type": "application/json", "App-Token": glpi_atoken, "Authorization": "user_token "+glpi_utoken}
        r0 = requests.get(glpi_url + "/initSession", headers = h0, verify = False)
        glpi_session_token = json.loads(r0.content.decode('utf-8'))['session_token']

        h = {"Content-Type": "application/json", "App-Token": glpi_atoken, "Session-Token": glpi_session_token}
        r1 = requests.get(glpi_url + "/search/computer?criteria[0][link]=AND&criteria[0][itemtype]=Computer&criteria[0][searchtype]=contains&criteria[0][field]=5&criteria[0][value]=" + svcTag + "&forcedisplay[0]=1&forcedisplay[1]=16&giveItems=true", headers = h, verify = False)
        try:
            GlpiComment = json.loads(r1.content.decode('utf-8'))['data'][0]['16']
        except Exception as e:
            logging.error('glpi ST ' + svcTag + ' ' + str(e))
            GlpiComment = None
        try:
            GlpiUrl = json.loads(r1.content.decode('utf-8'))['data_html'][0]['1'].replace('/', glpi_url_start, 1)
        except Exception as e:
            logging.error('glpi ST ' + svcTag + ' ' + str(e))
            GlpiUrl = None

        r2 = requests.get(glpi_url + "/killSession", headers = h, verify = False)

    return {"GlpiComment": GlpiComment, "GlpiUrl": GlpiUrl}


def getcmcdata(cmc_host):

    if cmc_host.find('vrtx') == -1:
        client = cmc_connect(cmc_host, cmc_u, cmc_p)
        # try other account
        if client == "Error":
            client = cmc_connect(cmc_host, cmc_u1, cmc_p1)
    else:
        client = cmc_connect(cmc_host, cmc_u1, cmc_p1)
    if client == "Error":
        return {cmc_host: "Error"}

    blades=OrderedDict()
    d_keys = ['iDRAC Version', 'Blade Type', 'Gen', 'svcTag', 'PowerState', 'BmcMac', 'Nic1Mac', 'Nic2Mac', 'ServerName', 'ServerBIOS', 'GlpiComment', 'GlpiUrl', 'iDRAC IP']

    data = getcmdoutput(client, cmd='getversion')
    pattern_slot  = re.compile('^[S|s]erver-(\w+)\s+.*$')
    pattern_blade = re.compile('^[S|s]erver-(?P<slot>\w+)\s+(?P<idracver>[0-9.]+\s\(.*\))\s+(?P<bladetype>\w+.*)\s+(?P<gen>iDRAC\d+)\s+.*$')
    pattern_eql   = re.compile('^[S|s]erver-(\w+)\s+([0-9.]+)+\s+([A-Z\-0-9]+)+\s+(\w+\s?\w+)\s+.*$')
    for line in data.split('\n'):
        if line.endswith('iDRAC not ready'):
            match = re.search(pattern_slot,line)
            if match:
                if len(match.group(1)) == 1:
                    slot = "0" + match.group(1)
                else:
                    slot = match.group(1)
                blades[slot] = dict.fromkeys(d_keys)
                blades[slot]['iDRAC Version'] = 'iDRAC not ready'
        else:
            match = re.search(pattern_blade,line)
            if match:
                if len(match.groupdict()['slot']) == 1:
                    slot = "0" + match.groupdict()['slot']
                else:
                    slot = match.groupdict()['slot']
                blades[slot] = dict.fromkeys(d_keys)
                blades[slot]['iDRAC Version'] = match.groupdict()['idracver']
                blades[slot]['Blade Type'] = match.groupdict()['bladetype'].strip()
                blades[slot]['Gen'] = match.groupdict()['gen']
            match = re.search(pattern_eql,line)
            if match:
                if len(match.group(1)) == 1:
                    slot = "0" + match.group(1)
                else:
                    slot = match.group(1)
                blades[slot] = dict.fromkeys(d_keys)
                blades[slot]['iDRAC Version'] = match.group(2)
                blades[slot]['Blade Type'] = match.group(3)
                blades[slot]['Gen'] = match.group(4)

    data = getcmdoutput(client, cmd='getmodinfo')
    pattern = re.compile('^[S|s]erver-(\w+)\s+Present\s+([\w|\/]+)\s+(?:OK|Not OK|N/A)+\s+(.*)\s*$')
    for line in data.split('\n'):
        match = re.search(pattern,line)
        if match:
            if len(match.group(1)) == 1:
                slot = "0" + match.group(1)
            else:
                slot = match.group(1)
            if blades.get(slot) == None:
                blades[slot] = dict.fromkeys(d_keys)
            blades[slot]['svcTag'] = match.group(3).rstrip().split()[0]
            blades[slot]['PowerState'] = match.group(2)

    for i in blades:
        command = 'racadm getconfig -g cfgServerInfo -i ' + i.replace('0', '')
        data = getcmdoutput(client, cmd=command)
        bmcMac = re.search('cfgServerBmcMacAddress=(.*)$',data,flags=re.MULTILINE)
        nic1Mac = re.search('cfgServerNic1MacAddress=(.*)$',data,flags=re.MULTILINE)
        nic2Mac = re.search('cfgServerNic2MacAddress=(.*)$',data,flags=re.MULTILINE)
        name = re.search('cfgServerName=(.*)$',data,flags=re.MULTILINE)
        bios = re.search('cfgServerBIOS=(.*)$',data,flags=re.MULTILINE)
        svcTag = re.search('cfgServerServiceTag=(.*)$',data,flags=re.MULTILINE)

        if bmcMac:
            blades[i]['BmcMac'] = bmcMac.group(1)
        if nic1Mac:
            blades[i]['Nic1Mac'] = nic1Mac.group(1)
        if nic2Mac:
            blades[i]['Nic2Mac'] = nic2Mac.group(1)
        if name:
            blades[i]['ServerName'] = name.group(1)
        if bios:
            blades[i]['ServerBIOS'] = bios.group(1)

        if svcTag:
            glpi_data = get_glpi_data(svcTag.group(1))
            blades[i]['GlpiComment'] = glpi_data['GlpiComment']
            blades[i]['GlpiUrl'] = glpi_data['GlpiUrl']
            if svcTag.group(1) is None or svcTag.group(1) == 'N/A' or svcTag.group(1).isspace():
                logging.warning('Incorrect ST ' + str(cmc_host) + ' slot ' + str(i))

        command = 'racadm getniccfg -m server-' + i.replace('0', '')
        data = getcmdoutput(client, cmd=command)
        idracIP = re.search('IP Address\s*=\s*([0-9.]+)$',data,flags=re.MULTILINE)
        if idracIP:
            blades[i]['iDRAC IP'] = idracIP.group(1)

    client.close()
    return {cmc_host: blades}


def refresh_cmc(conn, cmc, cmcblades):
    dbblades = db_get_cmcblades(conn, cmc)
    if cmcblades is None:
        if dbblades is not None:
            if dbblades[0][1:15] is not None:
                db_remove_cmc(conn, cmc)
                time.sleep(2)
                new_data = [cmc, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, get_current_time(), "1"]
                insert_new_data(conn, new_data)
                logging.info('cmc ' + str(cmc) + ' became empty')
    elif cmcblades is "Error":
        if dbblades is not None:
            if not str(dbblades[0][15]).startswith("Can't connect"):
                db_remove_cmc(conn, cmc)
                time.sleep(2)
                new_data = [cmc, None, None, None, None, None, None, None, None, None, None, None, None, None, None, "Can't connect", get_current_time(), "1"]
                insert_new_data(conn, new_data)
        else:
            new_data = [cmc, None, None, None, None, None, None, None, None, None, None, None, None, None, None, "Can't connect", get_current_time(), "1"]
            insert_new_data(conn, new_data)
    else:
        slots = [b for b in cmcblades]
        if dbblades is not None:
            for row in dbblades:
                if row[1] not in slots:
                    # delete old record
                    db_remove_slot(conn, cmc, row[1])
                    logging.info('cmc ' + str(cmc) + ' slot ' + str(row[1]) + ' became empty')
        for b in cmcblades:
            old_data = db_get_blade(conn, cmc, b)
            new_data = []
            new_data.append(cmc)
            new_data.append(b)
            new_data.append(cmcblades[b].get('svcTag'))
            new_data.append(cmcblades[b].get('Blade Type'))
            new_data.append(cmcblades[b].get('ServerName'))
            new_data.append(cmcblades[b].get('PowerState'))
            new_data.append(cmcblades[b].get('ServerBIOS'))
            new_data.append(cmcblades[b].get('iDRAC Version'))
            new_data.append(cmcblades[b].get('iDRAC IP'))
            new_data.append(cmcblades[b].get('Gen'))
            new_data.append(cmcblades[b].get('BmcMac'))
            new_data.append(cmcblades[b].get('Nic1Mac'))
            new_data.append(cmcblades[b].get('Nic2Mac'))
            new_data.append(cmcblades[b].get('GlpiUrl'))
            new_data.append(cmcblades[b].get('GlpiComment'))
            if new_data != old_data:
                # update
                db_remove_slot(conn, cmc, b)
                time.sleep(2)
                new_data.append(None)
                new_data.append(get_current_time())
                new_data.append("1")
                insert_new_data(conn, new_data)
                logging.info('updating cmc ' + str(cmc) + ' slot ' + str(b))
            elif old_data is None:
                # insert
                new_data.append(None)
                new_data.append(get_current_time())
                new_data.append("1")
                insert_new_data(conn, new_data)
                logging.info('cmc ' + str(cmc) + ' new slot ' + str(b))
    return


if __name__ == "__main__":
    logging.basicConfig(filename = f_log, level = logging.INFO, format='%(asctime)s %(levelname)s: %(threadName)s %(name)s: %(message)s')
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    logging.info('Started')
    start_time0 = time.time()
    cmclist = getzabbixcmc()
    start_time1 = time.time()
    if len(cmclist) > 0 and cmclist is not None:
        # obtain data from all cmc
        logging.info('Fetching all cmc started')
        alldata = {}
        with ThreadPoolExecutor(max_workers = thlimit) as executor:
            result = executor.map(getcmcdata, cmclist)
            for rr in result:
                r = dict(rr)
                for k in r.keys():
                    alldata[k] = r.get(k)
        logging.info('Fetching all cmc finished in ' + str(time.time() - start_time1) + ' s')
        start_time2 = time.time()
        # TODO: check DB exists and correct
        conn = sqlite3.connect(db_f, check_same_thread = False)
        conn.row_factory = sqlite3.Row
        # remove obsolete cmc
        dbcmc = db_get_allcmc(conn)
        if dbcmc is not None:
            for cmc in dbcmc:
                if cmc not in cmclist:
                    db_remove_cmc(conn, cmc)
                    logging.info('removing obsolete cmc ' + str(cmc))
        # refresh data
        for cmc in alldata.keys():
            cmcblades = alldata.get(cmc)
            refresh_cmc(conn, cmc, cmcblades)
        conn.close()
        logging.info('DB updated in ' + str(time.time() - start_time2) + ' s')
    else:
        print('Empty input data (no cmc)')
        logging.error('Empty input data (no cmc)')
    # push info to zabbix
    for server in (zabbix1):
        command = 'zabbix_sender -z ' + server + ' -p 10051 -s cmcblades -k cmcblades.worktime -o "' + str(int(time.time() - start_time0)) + '" >/dev/null 2>&1'
        os.system(command)
    logging.info('Finished in ' + str(time.time() - start_time0) + ' s')
