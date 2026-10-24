import { DatabaseSync } from 'node:sqlite';
import { digest, requireText, utc, transaction } from './common.js';
const severities = { low: 1, medium: 2, high: 3, critical: 4 };
export class RemediationTracker {
  constructor(file = ':memory:') {
    this.db = new DatabaseSync(file); this.db.exec(`PRAGMA foreign_keys=ON;
      CREATE TABLE IF NOT EXISTS assets(id TEXT PRIMARY KEY, owner TEXT NOT NULL, importance INTEGER NOT NULL, exposure INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS scans(id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, source TEXT NOT NULL, observed_at TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS findings(id TEXT PRIMARY KEY, asset_id TEXT REFERENCES assets(id), scanner TEXT NOT NULL, rule TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL, assignee TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS observations(scan_id TEXT REFERENCES scans(id), finding_id TEXT REFERENCES findings(id), evidence TEXT NOT NULL, PRIMARY KEY(scan_id,finding_id));
      CREATE TABLE IF NOT EXISTS retests(id INTEGER PRIMARY KEY, finding_id TEXT REFERENCES findings(id), outcome TEXT NOT NULL, artifact TEXT NOT NULL, observed_at TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS transitions(id INTEGER PRIMARY KEY, finding_id TEXT NOT NULL, action TEXT NOT NULL, observed_at TEXT NOT NULL);`);
  }
  asset(id, owner, importance = 1, exposure = 1) {
    requireText(id, 'asset'); requireText(owner, 'owner');
    if (![importance, exposure].every(n => Number.isInteger(n) && n >= 1 && n <= 3)) throw new Error('Invalid asset ranking');
    this.db.prepare('INSERT INTO assets VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET owner=excluded.owner,importance=excluded.importance,exposure=excluded.exposure').run(id, owner, importance, exposure);
  }
  importScan(scan) {
    for (const key of ['id', 'scanner', 'source']) requireText(scan[key], key);
    utc(scan.observedAt);
    if (!Array.isArray(scan.findings)) throw new Error('Expected findings');
    const identities = new Set();
    for (const finding of scan.findings) {
      for (const key of ['asset', 'rule', 'title', 'evidence']) requireText(finding[key], key, 2000);
      if (!Object.hasOwn(severities, finding.severity)) throw new Error('Invalid severity');
      if (!this.db.prepare('SELECT id FROM assets WHERE id=?').get(finding.asset)) throw new Error('Unknown asset');
      const identity = digest([finding.asset, scan.scanner, finding.rule]);
      if (identities.has(identity)) throw new Error('Duplicate finding within scan');
      identities.add(identity);
    }
    const fingerprint = digest(scan);
    const prior = this.db.prepare('SELECT fingerprint FROM scans WHERE id=?').get(scan.id);
    if (prior) {
      if (prior.fingerprint !== fingerprint) throw new Error('Scan ID reused with different content');
      return { imported: 0, duplicate: true };
    }
    return transaction(this.db, () => {
      this.db.prepare('INSERT INTO scans VALUES(?,?,?,?)').run(scan.id, fingerprint, scan.source, scan.observedAt);
      for (const finding of scan.findings) {
        const id = digest([finding.asset, scan.scanner, finding.rule]);
        const existing = this.db.prepare('SELECT * FROM findings WHERE id=?').get(id);
        if (!existing) this.db.prepare('INSERT INTO findings VALUES(?,?,?,?,?,?,?,NULL,?,?)').run(id, finding.asset, scan.scanner, finding.rule, finding.title, finding.severity, 'open', scan.observedAt, scan.observedAt);
        else if (utc(scan.observedAt) >= utc(existing.last_seen)) {
          const lastRetest = this.db.prepare('SELECT * FROM retests WHERE finding_id=? ORDER BY julianday(observed_at) DESC,id DESC LIMIT 1').get(id);
          const reopen = existing.status === 'closed' && (!lastRetest || utc(scan.observedAt) >= utc(lastRetest.observed_at));
          this.db.prepare('UPDATE findings SET last_seen=?,title=?,severity=?,status=? WHERE id=?').run(scan.observedAt, finding.title, finding.severity, reopen ? 'open' : existing.status, id);
        } else if (utc(scan.observedAt) < utc(existing.first_seen)) {
          this.db.prepare('UPDATE findings SET first_seen=? WHERE id=?').run(scan.observedAt, id);
        }
        this.db.prepare('INSERT INTO observations VALUES(?,?,?)').run(scan.id, id, finding.evidence);
      }
      return { imported: scan.findings.length, duplicate: false };
    });
  }
  assign(id, person) {
    requireText(person, 'assignee'); this.find(id);
    this.db.prepare("UPDATE findings SET assignee=?,status='in_progress' WHERE id=?").run(person, id);
  }
  find(id) {
    const finding = this.db.prepare('SELECT * FROM findings WHERE id=?').get(id);
    if (!finding) throw new Error('Unknown finding'); return finding;
  }
  retest(id, outcome, artifact, observedAt) {
    const finding = this.find(id); requireText(artifact, 'artifact', 2000); utc(observedAt);
    if (!['fixed', 'vulnerable'].includes(outcome) || utc(observedAt) < utc(finding.last_seen)) throw new Error('Invalid or stale retest');
    transaction(this.db, () => {
      this.db.prepare('INSERT INTO retests(finding_id,outcome,artifact,observed_at) VALUES(?,?,?,?)').run(id, outcome, artifact, observedAt);
      const latest = this.db.prepare('SELECT outcome FROM retests WHERE finding_id=? ORDER BY julianday(observed_at) DESC,id DESC LIMIT 1').get(id);
      if (latest.outcome === 'vulnerable') this.db.prepare("UPDATE findings SET status='open' WHERE id=?").run(id);
    });
  }
  closeFinding(id, observedAt) {
    utc(observedAt);
    return transaction(this.db, () => {
      const finding = this.find(id);
      const retest = this.db.prepare('SELECT * FROM retests WHERE finding_id=? ORDER BY julianday(observed_at) DESC,id DESC LIMIT 1').get(id);
      if (!finding.assignee || retest?.outcome !== 'fixed' || utc(retest.observed_at) < utc(finding.last_seen) || utc(observedAt) < utc(retest.observed_at)) throw new Error('Closure requires owner and current successful retest');
      this.db.prepare("UPDATE findings SET status='closed' WHERE id=?").run(id);
      this.db.prepare('INSERT INTO transitions(finding_id,action,observed_at) VALUES(?,?,?)').run(id, 'closed-after-retest', observedAt);
    });
  }
  report() {
    const findings = this.db.prepare('SELECT f.*,a.owner,a.importance,a.exposure FROM findings f JOIN assets a ON a.id=f.asset_id ORDER BY f.id').all().map(f => ({ ...f, priority: severities[f.severity] * f.importance * f.exposure }));
    findings.sort((a, b) => b.priority - a.priority || a.id.localeCompare(b.id));
    return { findings, scans: this.db.prepare('SELECT * FROM scans ORDER BY id').all(),
      observations: this.db.prepare('SELECT * FROM observations ORDER BY scan_id,finding_id').all(),
      retests: this.db.prepare('SELECT * FROM retests ORDER BY id').all(),
      summary: { total: findings.length, open: findings.filter(f => f.status !== 'closed').length, closed: findings.filter(f => f.status === 'closed').length } };
  }
  close() { this.db.close(); }
}
