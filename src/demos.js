import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { ingestJsonl, detect, measure, incidentReport } from './soc.js';
import { RemediationTracker } from './remediation.js';
import { PaperExchange } from './replay.js';
import { ChurchSandbox, restoreBackup } from './church.js';
import { securityFixture, scanFixture, tradingFixture } from './fixtures.js';
import { digest, writeJson } from './common.js';
export async function allDemos(directory) {
  await fs.mkdir(directory, { recursive: true });
  const run = path.join(directory, 'runs', crypto.randomUUID()); await fs.mkdir(run, { recursive: true });
  const fixture = securityFixture(), ingested = ingestJsonl(fixture.text), alerts = detect(ingested.events);
  const soc = { events: ingested.events.length, rejected: ingested.rejected, alerts, metrics: measure(alerts, fixture.labels) };
  await writeJson(path.join(run, 'soc.json'), soc);
  await fs.writeFile(path.join(run, 'incident.md'), incidentReport(alerts));
  const tracker = new RemediationTracker(path.join(run, 'remediation.sqlite'));
  tracker.asset('lab-web-1', 'synthetic-platform-team', 3, 2);
  const firstImport = tracker.importScan(scanFixture), duplicateImport = tracker.importScan(scanFixture);
  const id = tracker.report().findings[0].id;
  tracker.assign(id, 'synthetic-analyst');
  let closureBlocked = false; try { tracker.closeFinding(id, '2026-10-24T10:01:00Z'); } catch { closureBlocked = true; }
  tracker.retest(id, 'fixed', 'fixture://successful-retest', '2026-10-24T10:02:00Z');
  tracker.closeFinding(id, '2026-10-24T10:03:00Z');
  const remediation = { firstImport, duplicateImport, closureBlocked, ...tracker.report() }; tracker.close();
  await writeJson(path.join(run, 'remediation.json'), remediation);
  await fs.writeFile(path.join(run, 'management.md'), `# Synthetic remediation summary\n\nTotal findings: ${remediation.summary.total}. Closed after verified retest: ${remediation.summary.closed}.\n`);
  const church = new ChurchSandbox(path.join(run, 'church.sqlite'));
  for (const role of ['admin', 'staff', 'volunteer']) church.createUser(role, crypto.randomBytes(24).toString('hex'), role, 'group-a');
  church.addMember('admin', { id: 'synthetic-1', group: 'group-a', name: 'Synthetic Member A', note: 'Synthetic private note' });
  church.addMember('admin', { id: 'synthetic-2', group: 'group-b', name: 'Synthetic Member B', note: 'Synthetic private note' });
  const volunteer = church.listMembers('volunteer');
  let deniedWrite = false; try { church.addMember('volunteer', { id: 'bad', group: 'group-a', name: 'Denied', note: '' }); } catch { deniedWrite = true; }
  church.release('v1', digest('synthetic-release-v1')); church.release('v2', digest('synthetic-release-v2')); church.rollback('v1');
  const backup = await church.backupTo(path.join(run, 'church-backup.sqlite'));
  const restored = await restoreBackup(path.join(run, 'church-backup.sqlite'), path.join(run, 'church-restored.sqlite'));
  const deployment = { volunteerVisibleMembers: volunteer.length, privateFieldsHidden: !Object.hasOwn(volunteer[0], 'private_note'), deniedWrite,
    restoreDurationMs: restored.durationMs, restoreHashMatches: backup.hash === restored.logicalHash, activeRelease: church.activeRelease() };
  church.close(); await writeJson(path.join(run, 'recovery.json'), deployment);
  const replay = tradingFixture(), exchange = new PaperExchange(replay.config);
  for (const event of replay.events) exchange.apply(event);
  const beforeDuplicate = exchange.hash(); exchange.apply(replay.events[1]);
  const checkpoint = path.join(run, 'checkpoint.json'); await exchange.save(checkpoint);
  const resumed = await PaperExchange.load(checkpoint), second = new PaperExchange(replay.config);
  replay.events.forEach(event => second.apply(event));
  let killBlocked = false; try { exchange.apply({ id: 'post-kill', ts: '2026-10-24T10:01:00Z', type: 'submit', orderId: 'bad', side: 'buy', quantity: 1, limitCents: 10 }); } catch { killBlocked = true; }
  const trading = { hash: exchange.hash(), repeatMatches: second.hash() === exchange.hash(), checkpointMatches: resumed.hash() === exchange.hash(), duplicateIdempotent: beforeDuplicate === exchange.hash(), killBlocked, cashCents: exchange.state.cashCents, position: exchange.state.position, ledger: exchange.state.ledger };
  await writeJson(path.join(run, 'trading.json'), trading);
  const agent = await fs.readFile(path.join(directory, 'agent-live.json'), 'utf8').then(JSON.parse, () => null);
  const summary = { observedAt: new Date().toISOString(), mode: 'local-synthetic-integration', runDirectory: run, agent, soc,
    remediation: { ...remediation.summary, duplicateImport, closureBlocked }, deployment, trading };
  if (soc.metrics.recall !== 1 || soc.metrics.precision !== 1 || !deployment.restoreHashMatches || !deployment.deniedWrite ||
      !trading.repeatMatches || !trading.checkpointMatches || !trading.killBlocked || !closureBlocked) throw new Error('Integration demo failed');
  await writeJson(path.join(directory, 'suite-report.json'), summary);
  await fs.writeFile(path.join(directory, 'dashboard.html'), dashboard(summary));
  return summary;
}
function dashboard(report) {
  const escape = value => String(value).replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]));
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Portfolio engineering evidence</title><style>body{font:17px system-ui;max-width:1000px;margin:40px auto;padding:0 24px;background:#faf8f4;color:#20201f}h1{font-size:40px}table{border-collapse:collapse;width:100%}td,th{padding:14px;text-align:left;border-bottom:1px solid #ccc}pre{white-space:pre-wrap;background:white;padding:20px}a{color:#9c4000}</style><h1>Portfolio engineering evidence</h1><p>Observed ${escape(report.observedAt)} · local synthetic integration</p><table><tr><th>Project</th><th>Observed result</th></tr><tr><td>Security detection</td><td>${report.soc.alerts.length} alerts; precision ${report.soc.metrics.precision}; recall ${report.soc.metrics.recall}</td></tr><tr><td>Remediation</td><td>${report.remediation.closed} finding closed after retest; duplicate import prevented</td></tr><tr><td>Secure database</td><td>Role denial verified; restore hash matched in ${report.deployment.restoreDurationMs.toFixed(2)} ms</td></tr><tr><td>Trading replay</td><td>Repeat/restart hashes match; kill switch blocked new order</td></tr><tr><td>AI evaluation</td><td>Run npm run agent:live for separately recorded real-model measurements</td></tr></table><h2>Incident timeline</h2><pre>${escape(incidentReport(report.soc.alerts))}</pre><p>Fixture results measure these examples only. This report does not establish production detection coverage, investment performance or hosted deployment.</p></html>`;
}
