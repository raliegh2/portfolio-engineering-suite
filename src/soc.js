import { digest, requireText, utc } from './common.js';

export function ingestJsonl(text) {
  const events = [], rejected = [], seen = new Map();
  for (const [index, line] of text.split(/\r?\n/).entries()) {
    if (!line.trim()) continue;
    try {
      if (line.length > 16384) throw new Error('Oversized event');
      const event = JSON.parse(line);
      for (const key of ['id', 'host', 'user']) requireText(event[key], key, 100);
      utc(event.ts);
      if (!['windows', 'linux'].includes(event.platform)) throw new Error('Invalid platform');
      if (!['login_failure', 'login_success', 'process', 'role_change', 'host_event'].includes(event.type)) throw new Error('Invalid event type');
      if (event.type === 'process') requireText(event.command, 'command', 4096);
      if (event.type === 'role_change' && (typeof event.role !== 'string' || !['grant', 'revoke'].includes(event.action))) throw new Error('Invalid role event');
      const fingerprint = digest(event);
      if (seen.has(event.id)) {
        if (seen.get(event.id) !== fingerprint) throw new Error('Conflicting duplicate ID');
        continue;
      }
      seen.set(event.id, fingerprint); events.push(event);
    } catch (error) { rejected.push({ line: index + 1, reason: error instanceof SyntaxError ? 'Invalid JSON' : error.message }); }
  }
  events.sort((a, b) => utc(a.ts) - utc(b.ts) || a.id.localeCompare(b.id));
  return { events, rejected };
}

export function detect(events, { windowMs = 60000, threshold = 3 } = {}) {
  if (!Number.isInteger(threshold) || threshold < 2 || !Number.isFinite(windowMs) || windowMs < 1) throw new Error('Invalid rule configuration');
  const alerts = [], windows = new Map();
  function alert(rule, event, evidence) {
    alerts.push({ id: digest([rule, evidence]).slice(0, 20), rule, host: event.host,
      user: event.user, ts: event.ts, evidence, severity: rule === 'login-burst' ? 'medium' : 'high' });
  }
  for (const event of [...events].sort((a, b) => utc(a.ts) - utc(b.ts) || a.id.localeCompare(b.id))) {
    if (event.type === 'login_failure') {
      const key = event.host + '\0' + event.user;
      const previous = windows.get(key) ?? { events: [], alerted: false };
      const recent = previous.events.filter(item => utc(event.ts) - utc(item.ts) <= windowMs);
      const alerted = recent.length ? previous.alerted : false;
      recent.push(event); windows.set(key, { events: recent, alerted });
      if (recent.length >= threshold && !alerted) {
        alert('login-burst', event, recent.map(e => e.id)); windows.get(key).alerted = true;
      }
    }
    if (event.type === 'process' && /\b(?:powershell|pwsh)(?:\.exe)?\b/i.test(event.command) && /\s-(?:enc(?:odedcommand)?|e)\s+\S+/i.test(event.command)) {
      alert('encoded-powershell', event, [event.id]);
    }
    if(event.type==='process'&&/\bcertutil(?:\.exe)?\b.*-urlcache/i.test(event.command))alert('certificate-tool-download',event,[event.id]);
    if(event.type==='process'&&/\breg(?:\.exe)?\s+add\b.*\\(?:Run|RunOnce)\b/i.test(event.command))alert('registry-startup-write',event,[event.id]);
    if(event.type==='process'&&/\brundll32(?:\.exe)?\b.*javascript:/i.test(event.command))alert('rundll32-script',event,[event.id]);
    if (event.type === 'role_change' && event.action === 'grant' && /^(?:admin|administrator|root|sudo)$/i.test(event.role)) {
      alert('privilege-grant', event, [event.id]);
    }
  }
  return alerts;
}
export function measure(alerts, labels) {
  const actual = new Set(alerts.map(a => a.rule + ':' + a.evidence.at(-1)));
  const expected = new Set(labels.map(l => l.rule + ':' + l.eventId));
  const tp = [...actual].filter(id => expected.has(id)).length;
  return { truePositive: tp, falsePositive: actual.size - tp, falseNegative: expected.size - tp,
    precision: actual.size ? tp / actual.size : 1, recall: expected.size ? tp / expected.size : 1 };
}
export function incidentReport(alerts) {
  return '# Synthetic incident timeline\n\n' + alerts.map(a =>
    `- ${a.ts}: ${a.rule} on ${a.host}, user ${a.user}; evidence ${a.evidence.join(', ')}. Investigate source context, confirm owner intent, record disposition.`).join('\n') +
    '\n\nTraining detections only. No endpoint containment was executed.\n';
}
