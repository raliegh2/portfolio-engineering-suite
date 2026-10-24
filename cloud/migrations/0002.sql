CREATE TABLE telemetry(id TEXT PRIMARY KEY,group_id TEXT NOT NULL,source TEXT NOT NULL,collected INTEGER NOT NULL,rejected INTEGER NOT NULL,observed_at TEXT NOT NULL);
CREATE TABLE incidents(id TEXT PRIMARY KEY,group_id TEXT NOT NULL,rule TEXT NOT NULL,evidence_json TEXT NOT NULL,status TEXT NOT NULL,owner TEXT,disposition_evidence TEXT,observed_at TEXT NOT NULL);
