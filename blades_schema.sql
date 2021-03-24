BEGIN TRANSACTION;
CREATE TABLE "blades_data" (
	`cmc`	TEXT NOT NULL,
	`slot`	TEXT,
	`tag`	TEXT,
	`type`	TEXT,
	`name`	TEXT,
	`powerstate`	INTEGER,
	`biosver`	TEXT,
	`idracver`	TEXT,
	`idracip`	TEXT,
	`gen`	INTEGER,
	`bmcmac`	TEXT,
	`nic1mac`	TEXT,
	`nic2mac`	TEXT,
	`glpiurl`	TEXT,
	`glpicomm`	TEXT,
	`note`	TEXT,
	`recorddate`	INTEGER NOT NULL,
	`recordactive`	INTEGER NOT NULL,
	PRIMARY KEY(`cmc`,`slot`,`recorddate`)
);
CREATE VIEW blades as
select cmc, slot, tag, type, name, powerstate, biosver, idracver, idracip, gen, bmcmac, nic1mac, nic2mac, glpiurl, glpicomm, note
from blades_data where recordactive = "1" order by cmc asc, slot asc;
COMMIT;
