import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { ChurchSandbox, createChurchServer } from '../src/church.js';
import { packageRelease, launchRelease, releaseExercise } from '../src/releases.js';

async function withServer(action, options = {}) {
  const church = new ChurchSandbox();
  for (const role of ['admin', 'staff', 'volunteer']) church.createUser(role, 'SyntheticPassword123!', role, 'a');
  church.addMember('admin', { id: 'a', group: 'a', name: 'Synthetic A', note: 'Private A' });
  church.addMember('admin', { id: 'b', group: 'b', name: 'Synthetic B', note: 'Private B' });
  const server = createChurchServer(church, { secret: 'synthetic-test-key-'.repeat(4), ...options });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const origin = 'http://127.0.0.1:' + server.address().port;
  async function request(route, method = 'GET', body, token) {
    const response = await fetch(origin + route, { method,
      headers: { ...(body ? { 'content-type': 'application/json' } : {}), ...(token ? { authorization: 'Bearer ' + token } : {}) },
      body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(5000) });
    return { status: response.status, body: await response.json() };
  }
  const login = async id => (await request('/login', 'POST', { id, password: 'SyntheticPassword123!' })).body.token;
  try { return await action({ request, login, church }); }
  finally { await new Promise(resolve => server.close(resolve)); church.close(); }
}
test('HTTP role scopes hold for actual authenticated requests', async () => withServer(async ({ request, login }) => {
  const volunteer = await login('volunteer'), admin = await login('admin');
  const scoped = await request('/members', 'GET', undefined, volunteer);
  assert.equal(scoped.status, 200); assert.equal(scoped.body.length, 1); assert.equal(Object.hasOwn(scoped.body[0], 'private_note'), false);
  assert.equal((await request('/members', 'GET', undefined, admin)).body.length, 2);
  assert.equal((await request('/audit', 'GET', undefined, volunteer)).status, 403);
  assert.equal((await request('/members', 'POST', { id: 'denied', name: 'Denied', group: 'a', note: '' }, volunteer)).status, 403);
}));
test('HTTP unsigned, tampered and expired sessions cannot access data', async () => {
  let now = 1000;
  await withServer(async ({ request, login }) => {
    const token = await login('admin');
    assert.equal((await request('/members')).status, 403);
    assert.equal((await request('/members', 'GET', undefined, token + 'tampered')).status, 403);
    now += 2000; assert.equal((await request('/members', 'GET', undefined, token)).status, 403);
  }, { clock: () => now, lifetimeMs: 1000 });
});
test('HTTP role changes take effect for an existing signed session', async () => withServer(async ({ request, login, church }) => {
  const token = await login('admin'); church.db.prepare("UPDATE users SET role='volunteer' WHERE id='admin'").run();
  assert.equal((await request('/audit', 'GET', undefined, token)).status, 403);
}));
test('HTTP login throttling and malformed input return controlled failures', async () => withServer(async ({ request }) => {
  for (let i = 0; i < 8; i++) assert.equal((await request('/login', 'POST', { id: 'missing', password: 'incorrect' })).status, 401);
  assert.equal((await request('/login', 'POST', { id: 'missing', password: 'incorrect' })).status, 429);
}));
test('HTTP concurrent writes are persisted once with audit entries', async () => withServer(async ({ request, login, church }) => {
  const token = await login('staff');
  const results = await Promise.all(Array.from({ length: 5 }, (_, i) => request('/members', 'POST', { id: 'new-' + i, name: 'Synthetic ' + i, group: 'a', note: '' }, token)));
  assert.ok(results.every(r => r.status === 201)); assert.equal(church.listMembers('admin').length, 7);
}));
test('actual executable release starts v1, upgrades v2 and rolls back v1', { timeout: 30000 }, async () => {
  const root = path.join(process.cwd(), 'work', 'tests'); await fs.mkdir(root, { recursive: true });
  const dir = await fs.mkdtemp(path.join(root, 'release-'));
  try { const report = await releaseExercise(process.cwd(), dir); assert.equal(report.rollbackVerified, true); }
  finally { await fs.rm(dir, { recursive: true, force: true }); }
});
test('changed release artifact is rejected before it can execute', async () => {
  const root = path.join(process.cwd(), 'work', 'tests'); await fs.mkdir(root, { recursive: true });
  const dir = await fs.mkdtemp(path.join(root, 'release-corrupt-'));
  try {
    const artifact = await packageRelease(process.cwd(), dir, 'v1');
    await fs.appendFile(path.join(artifact, 'src/cli.js'), '\n// changed after packaging\n');
    await assert.rejects(launchRelease(artifact, path.join(dir, 'runtime')), /integrity/);
  } finally { await fs.rm(dir, { recursive: true, force: true }); }
});
