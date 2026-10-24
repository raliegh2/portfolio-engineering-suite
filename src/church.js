import { DatabaseSync, backup } from 'node:sqlite';
import crypto from 'node:crypto';
import http from 'node:http';
import fs from 'node:fs/promises';
import { constants } from 'node:fs';
import { digest, requireText, transaction } from './common.js';
import { BUILD_VERSION } from './build.js';
const roles = new Set(['admin', 'staff', 'volunteer']);
function denied(message = 'Forbidden') { const error = new Error(message); error.status = 403; return error; }
export class ChurchSandbox {
  constructor(file = ':memory:') {
    this.db = new DatabaseSync(file); this.db.exec(`PRAGMA foreign_keys=ON;
      CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, role TEXT NOT NULL, group_id TEXT NOT NULL, salt TEXT NOT NULL, password_hash TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS members(id TEXT PRIMARY KEY, group_id TEXT NOT NULL, display_name TEXT NOT NULL, private_note TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, outcome TEXT NOT NULL, observed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
      CREATE TABLE IF NOT EXISTS releases(version TEXT PRIMARY KEY, source_hash TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);`);
  }
  createUser(id, password, role, group) {
    requireText(id, 'user', 100); requireText(password, 'password', 200); requireText(group, 'group', 100);
    if (password.length < 12 || !roles.has(role)) throw new Error('Invalid user');
    const salt = crypto.randomBytes(16).toString('hex');
    const hashed = crypto.scryptSync(password, salt, 32).toString('hex');
    this.db.prepare('INSERT INTO users VALUES(?,?,?,?,?)').run(id, role, group, salt, hashed);
  }
  authenticate(id, password) {
    if (typeof id !== 'string' || typeof password !== 'string' || password.length > 200) return null;
    const user = this.db.prepare('SELECT * FROM users WHERE id=?').get(id);
    const calculated = crypto.scryptSync(password, user?.salt ?? 'dummy-salt', 32);
    if (!user || !crypto.timingSafeEqual(calculated, Buffer.from(user.password_hash, 'hex'))) return null;
    return { id: user.id, role: user.role, group: user.group_id };
  }
  actor(id) {
    const user = this.db.prepare('SELECT id,role,group_id FROM users WHERE id=?').get(id);
    if (!user) throw denied(); return { id: user.id, role: user.role, group: user.group_id };
  }
  log(actor, action, target, outcome) { this.db.prepare('INSERT INTO audit(actor,action,target,outcome) VALUES(?,?,?,?)').run(actor, action, target, outcome); }
  listMembers(actorId) {
    const actor = this.actor(actorId);
    const data = actor.role === 'admin' ? this.db.prepare('SELECT * FROM members ORDER BY id').all() :
      this.db.prepare('SELECT * FROM members WHERE group_id=? ORDER BY id').all(actor.group);
    this.log(actor.id, 'list-members', actor.group, 'allowed');
    return data.map(m => actor.role === 'volunteer' ? { id: m.id, group_id: m.group_id, display_name: m.display_name } : m);
  }
  addMember(actorId, data) {
    const actor = this.actor(actorId);
    if (actor.role === 'volunteer' || (actor.role !== 'admin' && actor.group !== data.group)) {
      this.log(actor.id, 'add-member', 'redacted', 'denied'); throw denied();
    }
    for (const key of ['id', 'group', 'name']) requireText(data[key], key, 100);
    if (typeof data.note !== 'string' || data.note.length > 2000) throw new Error('Invalid note');
    transaction(this.db, () => {
      this.db.prepare('INSERT INTO members VALUES(?,?,?,?)').run(data.id, data.group, data.name, data.note);
      this.log(actor.id, 'add-member', data.id, 'allowed');
    });
  }
  audit(actorId) {
    if (this.actor(actorId).role !== 'admin') throw denied();
    return this.db.prepare('SELECT * FROM audit ORDER BY id').all();
  }
  release(version, sourceHash) {
    if (!/^[a-zA-Z0-9._-]{1,60}$/.test(version) || !/^[a-f0-9]{64}$/.test(sourceHash)) throw new Error('Invalid release');
    const prior = this.db.prepare('SELECT source_hash FROM releases WHERE version=?').get(version);
    if (prior && prior.source_hash !== sourceHash) throw new Error('Release version is immutable');
    transaction(this.db, () => {
      this.db.prepare('INSERT OR IGNORE INTO releases VALUES(?,?)').run(version, sourceHash);
      this.db.prepare("INSERT INTO settings VALUES('active-release',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(version);
    });
  }
  rollback(version) {
    if (!this.db.prepare('SELECT version FROM releases WHERE version=?').get(version)) throw new Error('Unknown release');
    this.db.prepare("UPDATE settings SET value=? WHERE key='active-release'").run(version);
  }
  activeRelease() { return this.db.prepare("SELECT value FROM settings WHERE key='active-release'").get()?.value ?? 'unreleased'; }
  logicalHash() {
    return digest(['users', 'members', 'audit', 'releases', 'settings'].map(table => this.db.prepare('SELECT * FROM ' + table + ' ORDER BY 1').all()));
  }
  async backupTo(file) { await backup(this.db, file); return { hash: this.logicalHash() }; }
  close() { this.db.close(); }
}
export async function restoreBackup(source, target) {
  const start = performance.now();
  const check = new DatabaseSync(source, { readOnly: true });
  try {
    if (check.prepare('PRAGMA integrity_check').get().integrity_check !== 'ok') throw new Error('Backup integrity failed');
    for (const table of ['users', 'members', 'audit', 'releases', 'settings']) check.prepare('SELECT count(*) AS n FROM ' + table).get();
  } finally { check.close(); }
  await fs.copyFile(source, target, constants.COPYFILE_EXCL);
  const restored = new ChurchSandbox(target);
  try { return { durationMs: performance.now() - start, logicalHash: restored.logicalHash() }; }
  finally { restored.close(); }
}
export function createChurchServer(sandbox, { secret, clock = () => Date.now(), lifetimeMs = 3600000 } = {}) {
  if (typeof secret !== 'string' || secret.length < 32) throw new Error('Session secret must be at least 32 characters');
  const attempts = new Map();
  const sign = text => crypto.createHmac('sha256', secret).update(text).digest('base64url');
  function session(id) {
    const payload = Buffer.from(JSON.stringify({ id, exp: clock() + lifetimeMs })).toString('base64url');
    return payload + '.' + sign(payload);
  }
  function identity(request) {
    const token = request.headers.authorization?.replace(/^Bearer /, '') ?? '';
    const parts = token.split('.');
    if (parts.length !== 2 || parts[1].length !== sign(parts[0]).length ||
        !crypto.timingSafeEqual(Buffer.from(parts[1]), Buffer.from(sign(parts[0])))) throw denied('Invalid session');
    let body; try { body = JSON.parse(Buffer.from(parts[0], 'base64url').toString()); } catch { throw denied('Invalid session'); }
    if (!Number.isFinite(body.exp) || body.exp <= clock() || typeof body.id !== 'string') throw denied('Expired session');
    sandbox.actor(body.id); return body.id;
  }
  async function body(request) {
    let data = ''; for await (const chunk of request) { data += chunk; if (Buffer.byteLength(data) > 16384) throw new Error('Body too large'); }
    const parsed = JSON.parse(data || '{}'); if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Invalid body'); return parsed;
  }
  return http.createServer(async (request, response) => {
    response.setHeader('content-type', 'application/json');
    response.setHeader('cache-control', 'no-store'); response.setHeader('x-content-type-options', 'nosniff');
    const send = (status, data) => { response.writeHead(status); response.end(JSON.stringify(data)); };
    try {
      if (request.method === 'GET' && request.url === '/health') return send(200, { status: 'ok', release: sandbox.activeRelease(), build: BUILD_VERSION, mode: 'synthetic-local-sandbox' });
      if (request.method === 'POST' && request.url === '/login') {
        const key = request.socket.remoteAddress ?? 'loopback';
        const recent = (attempts.get(key) ?? []).filter(t => clock() - t < 60000);
        if (recent.length >= 8) return send(429, { error: 'Rate limited' });
        recent.push(clock()); attempts.set(key, recent);
        const input = await body(request), actor = sandbox.authenticate(input.id, input.password);
        if (!actor) return send(401, { error: 'Invalid login' });
        return send(200, { token: session(actor.id) });
      }
      const actor = identity(request);
      if (request.method === 'GET' && request.url === '/members') return send(200, sandbox.listMembers(actor));
      if (request.method === 'POST' && request.url === '/members') { sandbox.addMember(actor, await body(request)); return send(201, { created: true }); }
      if (request.method === 'GET' && request.url === '/audit') return send(200, sandbox.audit(actor));
      send(404, { error: 'Not found' });
    } catch (error) { send(error.status ?? 400, { error: error.status === 403 ? error.message : 'Request rejected' }); }
  });
}
