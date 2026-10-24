import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import dgram from 'node:dgram';
import crypto from 'node:crypto';
import { digest, writeJson } from './common.js';
const run = promisify(execFile);
const alias = (value, salt) => crypto.createHmac('sha256', salt).update(String(value ?? 'unknown')).digest('hex').slice(0, 16);
export function normalizeWindows(record, salt) {
  if (!record || !/^\d+$/.test(String(record.recordId))) throw new Error('Invalid Windows record');
  const ts = new Date(record.timeCreated).toISOString(), data = record.eventData ?? {};
  const base = { id: 'win-' + alias(record.machineName, salt) + '-' + record.recordId,
    ts, platform: 'windows', host: alias(record.machineName, salt), user: alias(data.TargetUserName ?? data.SubjectUserName, salt),
    source: 'windows-event-log', sourceEventId: Number(record.id), type: 'host_event' };
  if (Number(record.id) === 4625) base.type = 'login_failure';
  if (Number(record.id) === 4624) base.type = 'login_success';
  if ([4688, 4104].includes(Number(record.id))) {
    base.type = 'process'; base.command = String(data.CommandLine ?? data.NewProcessName ?? data.ScriptBlockText ?? 'unavailable');
  }
  if ([4728, 4732, 4756].includes(Number(record.id))) {
    // Event IDs identify membership addition, but only the privileged group SID proves admin membership.
    if (['S-1-5-32-544'].includes(data.TargetSid) || /-512$/.test(data.TargetSid ?? '')) Object.assign(base, { type: 'role_change', role: 'admin', action: 'grant' });
  }
  return base;
}
export function normalizeSyslog(message, { receivedAt = new Date().toISOString(), salt = 'local-training' } = {}) {
  if (Buffer.byteLength(message) > 16384) throw new Error('Syslog message too large');
  const parsed = message.match(/^<\d{1,3}>1 (\S+) (\S+) (\S+) (\S+) (\S+) (?:-|\[[^\]]*\]) (.*)$/);
  if (!parsed) throw new Error('Expected RFC5424 syslog');
  const [, supplied, host, app, pid, messageId, body] = parsed;
  const ts = new Date(supplied === '-' ? receivedAt : supplied).toISOString();
  const user = body.match(/(?:for (?:invalid user )?|user=)([a-zA-Z0-9._-]+)/)?.[1] ?? 'unknown';
  const event = { id: 'syslog-' + digest(message), ts, host: alias(host, salt), user: alias(user, salt), platform: 'linux', type: 'host_event', source: 'rfc5424', app };
  if (/sshd/i.test(app) && /Failed (?:password|publickey)/i.test(body)) event.type = 'login_failure';
  if (/sshd/i.test(app) && /Accepted (?:password|publickey)/i.test(body)) event.type = 'login_success';
  if (/sudo/i.test(app) && /COMMAND=/.test(body)) Object.assign(event, { type: 'process', command: body.split('COMMAND=')[1].slice(0, 4096) });
  return event;
}
export async function collectWindows(directory, { channel = 'Application', limit = 100 } = {}) {
  if (process.platform !== 'win32') throw new Error('Windows collection requires Windows');
  if (!['Application', 'System', 'Security', 'Microsoft-Windows-PowerShell/Operational'].includes(channel) || !Number.isInteger(limit) || limit < 1 || limit > 500) throw new Error('Invalid collection request');
  await fs.mkdir(directory, { recursive: true });
  const stateFile = path.join(directory, 'windows-checkpoint.json');
  const state = await fs.readFile(stateFile, 'utf8').then(JSON.parse, e => { if(e.code !== 'ENOENT') throw e; return { salt:crypto.randomBytes(32).toString('hex'),channels:{} }; });
  const script = fileURLToPath(new URL('../scripts/collect-windows.ps1', import.meta.url));
  const result = await run('powershell.exe', ['-NoProfile','-NonInteractive','-File',script,'-Channel',channel,'-Limit',String(limit)], { windowsHide:true,timeout:30000,maxBuffer:4*1024*1024 });
  const raw = JSON.parse(result.stdout.replace(/^\uFEFF/,''));
  const allRecords=(Array.isArray(raw)?raw:[raw]).filter(Boolean),priorWatermark=BigInt(state.channels[channel]??'0');
  if(allRecords.length&&priorWatermark>0n){
    const ids=allRecords.map(r=>BigInt(r.recordId)),oldest=ids.reduce((a,b)=>a<b?a:b),latest=ids.reduce((a,b)=>a>b?a:b);
    if(latest<priorWatermark)throw new Error('Event log reset detected; review and start a new checkpoint');
    if(oldest>priorWatermark+1n)throw new Error('Collector backlog gap detected; increase bounded sample before advancing checkpoint');
  }
  const records = (Array.isArray(raw) ? raw : [raw]).filter(Boolean).filter(r => BigInt(r.recordId) > BigInt(state.channels[channel] ?? '0'));
  const events = records.map(r => normalizeWindows(r,state.salt)).sort((a,b)=>a.ts.localeCompare(b.ts)||a.id.localeCompare(b.id));
  if(events.length) await fs.appendFile(path.join(directory,'windows.jsonl'),events.map(JSON.stringify).join('\n')+'\n');
  for(const record of records) if(BigInt(record.recordId)>BigInt(state.channels[channel]??'0')) state.channels[channel]=String(record.recordId);
  await writeJson(stateFile,state);
  return {source:'actual-windows-event-log',channel,collected:events.length,watermark:state.channels[channel]??'0',privacy:'host/user pseudonymized; raw records stay local',output:path.join(directory,'windows.jsonl')};
}
export async function syslogReceiver(file,{port=5514,salt='local-training'}={}) {
  await fs.mkdir(path.dirname(file),{recursive:true});
  const socket=dgram.createSocket('udp4'), stats={accepted:0,rejected:0}; let writes=Promise.resolve();
  socket.on('message',buffer=>{
    try { const event=normalizeSyslog(buffer.toString(),{salt}); writes=writes.then(()=>fs.appendFile(file,JSON.stringify(event)+'\n')); stats.accepted++; }
    catch { stats.rejected++; }
  });
  await new Promise((resolve,reject)=>{socket.once('error',reject);socket.bind(port,'127.0.0.1',resolve);});
  return {port:socket.address().port,stats,close:async()=>{await new Promise(resolve=>socket.close(resolve));await writes;}};
}
