import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
export const digest = data => crypto.createHash('sha256').update(typeof data === 'string' || Buffer.isBuffer(data) ? data : JSON.stringify(data)).digest('hex');
export function requireText(value, name, max = 500) {
  if (typeof value !== 'string' || !value.trim() || value.length > max) throw new Error('Invalid ' + name);
  return value;
}
export function utc(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(value) || !Number.isFinite(Date.parse(value))) throw new Error('Expected UTC timestamp');
  return Date.parse(value);
}
export async function writeJson(file, value) {
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(file, JSON.stringify(value, null, 2) + '\n');
}
export function transaction(db, action) {
  db.exec('BEGIN IMMEDIATE');
  try { const result = action(); db.exec('COMMIT'); return result; }
  catch (error) { db.exec('ROLLBACK'); throw error; }
}
