CREATE TABLE members(id TEXT PRIMARY KEY,group_id TEXT NOT NULL,display_name TEXT NOT NULL,private_note TEXT NOT NULL);
CREATE TABLE assets(id TEXT PRIMARY KEY,group_id TEXT NOT NULL,owner TEXT NOT NULL,importance INTEGER NOT NULL,exposure INTEGER NOT NULL);
CREATE TABLE scans(id TEXT PRIMARY KEY,group_id TEXT NOT NULL,fingerprint TEXT NOT NULL,observed_at TEXT NOT NULL,source TEXT NOT NULL);
CREATE TABLE findings(id TEXT PRIMARY KEY,asset_id TEXT REFERENCES assets(id),rule TEXT NOT NULL,title TEXT NOT NULL,severity TEXT NOT NULL,status TEXT NOT NULL,assignee TEXT,last_seen TEXT NOT NULL);
CREATE TABLE observations(scan_id TEXT REFERENCES scans(id),finding_id TEXT REFERENCES findings(id),evidence TEXT NOT NULL,PRIMARY KEY(scan_id,finding_id));
CREATE TABLE retests(id TEXT PRIMARY KEY,finding_id TEXT REFERENCES findings(id),outcome TEXT NOT NULL,artifact TEXT NOT NULL,observed_at TEXT NOT NULL);
CREATE TABLE audit(id INTEGER PRIMARY KEY,actor TEXT NOT NULL,action TEXT NOT NULL,observed_at TEXT NOT NULL);
