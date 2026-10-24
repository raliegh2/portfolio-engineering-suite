import fs from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { digest, writeJson } from './common.js';
const commands = [['test', ['--test', 'test/evaluator.test.js', 'test/projects.test.js', 'test/http.test.js','test/integrations.test.js']], ['check', ['src/check.js']], ['trace-demo', ['src/demo.js']], ['integration-demo', ['src/cli.js', 'demo']]];
const checks = [];
for (const [name, args] of commands) {
  const started = performance.now();
  const result = spawnSync(process.execPath, args, { encoding: 'utf8', windowsHide: true, timeout: 120000 });
  checks.push({ name, exitCode: result.status, durationMs: performance.now() - started, stdout: result.stdout, stderr: result.stderr });
  console.log(name + ': ' + (result.status === 0 ? 'passed' : 'failed'));
  if (result.status !== 0) { console.error(result.stdout, result.stderr); break; }
}
const sourceHashes = {};
for (const file of (await fs.readdir('src')).filter(n => n.endsWith('.js')).sort()) sourceHashes[file] = digest(await fs.readFile('src/' + file));
const report = { observedAt: new Date().toISOString(), node: process.version, passed: checks.length === commands.length && checks.every(c => c.exitCode === 0), checks, sourceHashes, runtimeDependencies: [] };
await writeJson('evidence/ci-report.json', report);
if (!report.passed) process.exitCode = 1;
