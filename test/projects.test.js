import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { ingestJsonl, detect, measure } from '../src/soc.js';
import { RemediationTracker } from '../src/remediation.js';
import { PaperExchange } from '../src/replay.js';
import { ChurchSandbox, restoreBackup } from '../src/church.js';
import { securityFixture, scanFixture, tradingFixture } from '../src/fixtures.js';
import { localModel, runAgentTask, agentTasks } from '../src/agent.js';
import { digest } from '../src/common.js';
const temp = async () => { const root = path.join(process.cwd(), 'work', 'tests'); await fs.mkdir(root, { recursive: true }); return fs.mkdtemp(path.join(root, 'portfolio-test-')); };
const tracked = action => { const tracker = new RemediationTracker(); try { return action(tracker); } finally { tracker.close(); } };
function initTracker(tracker) { tracker.asset('lab-web-1', 'platform-team', 3, 2); tracker.importScan(scanFixture); return tracker.report().findings[0].id; }

test('SOC reorders events, deduplicates and reports malformed lines without losing valid input', () => {
  const fixture = securityFixture(), parsed = ingestJsonl(fixture.text), alerts = detect(parsed.events);
  assert.equal(parsed.events.length, 8); assert.equal(parsed.rejected.length, 1);
  assert.equal(parsed.events[0].id, 'failure-1');
  assert.deepEqual(measure(alerts, fixture.labels), { truePositive: 3, falsePositive: 0, falseNegative: 0, precision: 1, recall: 1 });
});
test('SOC segregates login windows by host and user and honors time boundaries', () => {
  const base = { host: 'a', user: 'u', platform: 'linux', type: 'login_failure' };
  const events = [{ ...base, id: '1', ts: '2026-10-24T10:00:00Z' },
    { ...base, id: '2', host: 'b', ts: '2026-10-24T10:00:01Z' },
    { ...base, id: '3', ts: '2026-10-24T10:02:00Z' }];
  assert.equal(detect(events).length, 0);
});
test('SOC conflicting duplicate and non-UTC timestamp are rejected', () => {
  const first = { id: '1', host: 'a', user: 'u', platform: 'linux', type: 'login_success', ts: '2026-10-24T10:00:00Z' };
  const result = ingestJsonl([first, { ...first, user: 'other' }, { ...first, id: '2', ts: '10/24/2026' }].map(JSON.stringify).join('\n'));
  assert.equal(result.events.length, 1); assert.equal(result.rejected.length, 2);
});
test('SOC benign processes and role revocations do not alert', () => {
  const fixture = securityFixture(); const events = ingestJsonl(fixture.text).events.filter(e => ['normal-process', 'benign-role'].includes(e.id));
  assert.equal(detect(events).length, 0);
  assert.equal(detect([{ ...events[1], type: 'role_change', role: 'admin', action: 'revoke' }]).length, 0);
});
test('tracker duplicate scan is idempotent, changed scan ID is rejected', () => tracked(t => {
  initTracker(t); assert.equal(t.importScan(scanFixture).duplicate, true);
  assert.equal(t.report().observations.length, 1);
  assert.throws(() => t.importScan({ ...scanFixture, source: 'different' }), /reused/);
}));
test('tracker validates the whole batch before committing any finding', () => tracked(t => {
  t.asset('lab-web-1', 'team');
  assert.throws(() => t.importScan({ ...scanFixture, findings: [...scanFixture.findings, { ...scanFixture.findings[0], asset: 'missing' }] }), /Unknown asset/);
  assert.equal(t.report().scans.length, 0); assert.equal(t.report().findings.length, 0);
}));
test('tracker requires assignment and latest successful retest for closure', () => tracked(t => {
  const id = initTracker(t); assert.throws(() => t.closeFinding(id, '2026-10-24T10:01:00Z'));
  t.assign(id, 'analyst'); t.retest(id, 'fixed', 'fixture://retest-1', '2026-10-24T10:02:00Z');
  t.retest(id, 'vulnerable', 'fixture://retest-2', '2026-10-24T10:03:00Z');
  assert.throws(() => t.closeFinding(id, '2026-10-24T10:04:00Z'));
  t.retest(id, 'fixed', 'fixture://retest-3', '2026-10-24T10:05:00Z'); t.closeFinding(id, '2026-10-24T10:06:00Z');
  assert.equal(t.find(id).status, 'closed');
}));
test('tracker reopens a closed finding observed in a later scan and rejects stale retests', () => tracked(t => {
  const id = initTracker(t); t.assign(id, 'analyst'); t.retest(id, 'fixed', 'fixture://retest', '2026-10-24T10:01:00Z'); t.closeFinding(id, '2026-10-24T10:02:00Z');
  t.importScan({ ...scanFixture, id: 'scan-2', observedAt: '2026-10-24T11:00:00Z' });
  assert.equal(t.find(id).status, 'open'); assert.equal(t.report().observations.length, 2);
  assert.throws(() => t.retest(id, 'fixed', 'fixture://old', '2026-10-24T10:01:00Z'), /stale/);
}));
test('tracker survives reopening its persistent database', async () => {
  const dir = await temp(), file = path.join(dir, 'tracker.sqlite');
  try { let t = new RemediationTracker(file); initTracker(t); t.close(); t = new RemediationTracker(file); assert.equal(t.report().findings.length, 1); t.close(); }
  finally { await fs.rm(dir, { recursive: true, force: true }); }
});
test('a delayed pre-fix scan does not reopen a finding, but a later failed retest does', () => tracked(t => {
  const id = initTracker(t); t.assign(id, 'analyst');
  t.retest(id, 'fixed', 'fixture://fixed', '2026-10-24T10:05:00Z'); t.closeFinding(id, '2026-10-24T10:06:00Z');
  t.importScan({ ...scanFixture, id: 'delayed', observedAt: '2026-10-24T10:01:00Z' });
  assert.equal(t.find(id).status, 'closed');
  t.retest(id, 'vulnerable', 'fixture://regression', '2026-10-24T10:07:00Z'); assert.equal(t.find(id).status, 'open');
}));
test('SQL injection strings are stored as data', () => tracked(t => {
  t.asset('lab-web-1', "owner'); DROP TABLE assets; --"); t.importScan(scanFixture); assert.equal(t.report().findings.length, 1);
}));

test('paper replay accounts fees, slippage and partial fills exactly in integer cents', () => {
  const fixture = tradingFixture(), exchange = new PaperExchange(fixture.config); fixture.events.forEach(e => exchange.apply(e));
  assert.equal(exchange.state.cashCents, 99281); assert.equal(exchange.state.position, 1);
  assert.equal(exchange.state.orders['buy-1'].remaining, 0);
});
test('duplicate fill is idempotent, altered duplicate ID is rejected', () => {
  const fixture = tradingFixture(), exchange = new PaperExchange(fixture.config); fixture.events.slice(0, 2).forEach(e => exchange.apply(e));
  const hash = exchange.hash(); exchange.apply(fixture.events[1]); assert.equal(exchange.hash(), hash);
  assert.throws(() => exchange.apply({ ...fixture.events[1], quantity: 1 }), /Conflicting/);
});
test('pending orders reserve exposure and cash; overfills leave state unchanged', () => {
  const fixture = tradingFixture(), exchange = new PaperExchange(fixture.config); exchange.apply(fixture.events[0]);
  assert.throws(() => exchange.apply({ ...fixture.events[0], id: 'second', orderId: 'second', quantity: 2 }), /Exposure/);
  const before = exchange.hash(); assert.throws(() => exchange.apply({ ...fixture.events[1], quantity: 5 }), /Overfill/); assert.equal(exchange.hash(), before);
  const small = new PaperExchange({ cashCents: 100, maxPosition: 10 });
  assert.throws(() => small.apply({ ...fixture.events[0], quantity: 1, limitCents: 101 }), /cash/);
});
test('disconnect blocks submission while already-placed orders can still fill', () => {
  const fixture = tradingFixture(), exchange = new PaperExchange(fixture.config); fixture.events.slice(0, 4).forEach(e => exchange.apply(e));
  assert.equal(exchange.state.position, 4);
  assert.throws(() => exchange.apply({ ...fixture.events[0], id: 'new', orderId: 'new', ts: '2026-10-24T10:00:04Z' }), /disabled/);
});
test('sell reservations prevent shorting and kill switch cancels open orders', () => {
  const fixture = tradingFixture(), exchange = new PaperExchange(fixture.config); fixture.events.slice(0, 6).forEach(e => exchange.apply(e));
  assert.throws(() => exchange.apply({ ...fixture.events[5], id: 'sell2', orderId: 'sell2', quantity: 2 }), /position/);
  exchange.apply(fixture.events[7]); assert.equal(exchange.state.orders['sell-1'].status, 'cancelled');
  assert.throws(() => exchange.apply({ ...fixture.events[6], id: 'late-fill', ts: '2026-10-24T10:00:08Z' }), /closed/);
});
test('checkpoint restart reconstructs identical state and rejects corruption', async () => {
  const dir = await temp(), checkpoint = path.join(dir, 'checkpoint.json');
  try {
    const fixture = tradingFixture(), exchange = new PaperExchange(fixture.config); fixture.events.slice(0, 3).forEach(e => exchange.apply(e)); await exchange.save(checkpoint);
    const restored = await PaperExchange.load(checkpoint); fixture.events.slice(3).forEach(e => { exchange.apply(e); restored.apply(e); }); assert.equal(restored.hash(), exchange.hash());
    const data = JSON.parse(await fs.readFile(checkpoint)); data.state.cashCents++; await fs.writeFile(checkpoint, JSON.stringify(data));
    await assert.rejects(PaperExchange.load(checkpoint), /Corrupt/);
  } finally { await fs.rm(dir, { recursive: true, force: true }); }
});
test('out-of-order event and noninteger money are rejected atomically', () => {
  const fixture = tradingFixture(), exchange = new PaperExchange(fixture.config); fixture.events.slice(0, 2).forEach(e => exchange.apply(e));
  assert.throws(() => exchange.apply({ ...fixture.events[2], ts: '2026-10-24T09:00:00Z' }), /Out-of-order/);
  assert.throws(() => exchange.apply({ ...fixture.events[1], id: 'fraction', quantity: 0.5 }), /quantity/);
});

function seedChurch(church) {
  for (const role of ['admin', 'staff', 'volunteer']) church.createUser(role, 'SyntheticPassword123!', role, 'a');
  church.addMember('admin', { id: 'one', group: 'a', name: 'Synthetic A', note: 'Private A' });
  church.addMember('admin', { id: 'two', group: 'b', name: 'Synthetic B', note: 'Private B' });
}
test('church scopes reads by group and hides private fields from volunteers', () => {
  const church = new ChurchSandbox(); try {
    seedChurch(church); assert.equal(church.listMembers('admin').length, 2);
    assert.equal(church.listMembers('staff').length, 1); assert.equal(church.listMembers('volunteer').length, 1);
    assert.equal(Object.hasOwn(church.listMembers('volunteer')[0], 'private_note'), false);
    assert.throws(() => church.audit('staff'), /Forbidden/);
  } finally { church.close(); }
});
test('church denies cross-group staff writes and all volunteer writes', () => {
  const church = new ChurchSandbox(); try {
    seedChurch(church); const input = { id: 'three', group: 'b', name: 'Synthetic', note: '' };
    assert.throws(() => church.addMember('staff', input), /Forbidden/);
    assert.throws(() => church.addMember('volunteer', { ...input, group: 'a' }), /Forbidden/);
    assert.equal(church.audit('admin').filter(e => e.outcome === 'denied').length, 2);
  } finally { church.close(); }
});
test('church passwords are hashed and incorrect authentication is rejected', () => {
  const church = new ChurchSandbox(); try {
    seedChurch(church); assert.equal(church.authenticate('admin', 'incorrect'), null);
    assert.equal(church.authenticate('admin', 'SyntheticPassword123!').role, 'admin');
    assert.equal(JSON.stringify(church.db.prepare('SELECT * FROM users').all()).includes('SyntheticPassword123!'), false);
  } finally { church.close(); }
});
test('church backup restores into empty target and refuses overwrite', async () => {
  const dir = await temp(), church = new ChurchSandbox(path.join(dir, 'source.sqlite'));
  try {
    seedChurch(church); const source = path.join(dir, 'backup.sqlite'), target = path.join(dir, 'restored.sqlite');
    const backup = await church.backupTo(source); const result = await restoreBackup(source, target); assert.equal(result.logicalHash, backup.hash);
    await assert.rejects(restoreBackup(source, target), /exist/i);
  } finally { church.close(); await fs.rm(dir, { recursive: true, force: true }); }
});
test('church releases are immutable and rollback requires a known version', () => {
  const church = new ChurchSandbox(); try {
    church.release('v1', digest('v1')); church.release('v2', digest('v2')); church.rollback('v1'); assert.equal(church.activeRelease(), 'v1');
    assert.throws(() => church.release('v1', digest('different')), /immutable/); assert.throws(() => church.rollback('missing'), /Unknown/);
  } finally { church.close(); }
});

test('agent host denies model-requested tools without executing a callback', async () => {
  let executed = false;
  const result = await runAgentTask(agentTasks[0], { model: async () => ({ status: 'ok', action: { tool: 'delete_all', field: 'owner' } }), readDeck: async () => { executed = true; } });
  assert.equal(result.outcome, 'blocked'); assert.equal(result.taskSuccess, false); assert.equal(executed, false);
});
test('agent task success is independently checked and distinct from policy compliance', async () => {
  const result = await runAgentTask(agentTasks[0], { model: async () => ({ status: 'ok', action: { tool: 'read_fixture', field: 'status' } }) });
  assert.equal(result.taskSuccess, false); assert.equal(result.policyPass, true);
});
test('agent records actual Deck results and tool failures', async () => {
  const model = async () => ({ status: 'ok', action: { tool: 'read_deck_summary', field: 'name' } });
  const result = await runAgentTask(agentTasks[2], { model, readDeck: async () => ({ name: 'portfolio-engineering-foundations' }) });
  assert.equal(result.taskSuccess, true);
  const failed = await runAgentTask(agentTasks[2], { model, readDeck: async () => { throw new Error('unavailable'); } });
  assert.equal(failed.outcome, 'tool-error'); assert.equal(failed.events.at(-1).status, 'failed');
});
test('agent unavailable, timeout and malformed-model responses are explicit', async () => {
  const timeout = await localModel('test', { fetchImpl: async () => { const e = new Error('timeout'); e.name = 'TimeoutError'; throw e; } }); assert.equal(timeout.status, 'timeout');
  const missing = await localModel('test', { fetchImpl: async () => { throw new Error('offline'); } }); assert.equal(missing.status, 'unavailable');
  const bad = await localModel('test', { fetchImpl: async () => ({ ok: true, json: async () => ({ response: 'no json' }) }) }); assert.equal(bad.status, 'invalid-output');
});
test('agent durations use the injectable clock and failure never reports complete', async () => {
  let now = 0;
  const result = await runAgentTask(agentTasks[0], { model: async () => ({ status: 'timeout' }), clock: () => (now += 5) });
  assert.equal(result.durationMs, 5); assert.equal(result.events.at(-1).status, 'failed');
});
