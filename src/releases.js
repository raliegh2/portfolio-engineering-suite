import fs from 'node:fs/promises';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { digest } from './common.js';
export async function packageRelease(sourceRoot, releasesRoot, version) {
  if (!/^[a-zA-Z0-9._-]{1,60}$/.test(version) || version === '.' || version === '..') throw new Error('Invalid version');
  await fs.mkdir(releasesRoot, { recursive: true });
  const target = path.join(releasesRoot, version); await fs.mkdir(target);
  await fs.cp(path.join(sourceRoot, 'src'), path.join(target, 'src'), { recursive: true });
  await fs.copyFile(path.join(sourceRoot, 'package.json'), path.join(target, 'package.json'));
  await fs.writeFile(path.join(target, 'src/build.js'), 'export const BUILD_VERSION = ' + JSON.stringify(version) + ';\n');
  const files = {};
  for (const name of (await fs.readdir(path.join(target, 'src'))).sort()) files['src/' + name] = digest(await fs.readFile(path.join(target, 'src', name)));
  files['package.json'] = digest(await fs.readFile(path.join(target, 'package.json')));
  await fs.writeFile(path.join(target, 'manifest.json'), JSON.stringify({ version, files }, null, 2));
  return target;
}
export async function launchRelease(directory, runtimeDirectory) {
  const manifest = JSON.parse(await fs.readFile(path.join(directory, 'manifest.json')));
  for (const [name, expected] of Object.entries(manifest.files)) {
    if (!/^(?:src\/[a-zA-Z0-9._-]+\.js|package\.json)$/.test(name)) throw new Error('Invalid manifest path');
    if (digest(await fs.readFile(path.join(directory, name))) !== expected) throw new Error('Artifact integrity mismatch');
  }
  const child = spawn(process.execPath, [path.join(directory, 'src/cli.js'), 'serve', runtimeDirectory, '0'], {
    windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
    env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, TEMP: process.env.TEMP, TMP: process.env.TMP, NODE_NO_WARNINGS: '1', CHURCH_BIND_HOST: '127.0.0.1' }
  });
  let output = '';
  const ready = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => { child.kill(); reject(new Error('Release startup timeout')); }, 15000);
    child.once('error', e => { clearTimeout(timer); reject(e); });
    child.once('exit', code => { if (code !== null && !output.includes('listening')) { clearTimeout(timer); reject(new Error('Release exited before ready')); } });
    child.stdout.on('data', chunk => {
      output += chunk; if (output.length > 8192) { clearTimeout(timer); child.kill(); reject(new Error('Unexpected release output')); }
      for (const line of output.split('\n')) { try { const message = JSON.parse(line); if (message.listening) { clearTimeout(timer); resolve(message); } } catch {} }
    });
    child.stderr.on('data', () => {});
  });
  const origin = 'http://127.0.0.1:' + ready.listening;
  const health = await (await fetch(origin + '/health', { signal: AbortSignal.timeout(5000) })).json();
  if (health.build !== manifest.version) { child.kill(); throw new Error('Wrong executable release'); }
  return { origin, health, stop: async () => { if (child.exitCode !== null) return; const done = new Promise(resolve => child.once('exit', resolve)); child.kill(); await done; } };
}
export async function releaseExercise(sourceRoot, directory) {
  const one = await packageRelease(sourceRoot, path.join(directory, 'releases'), 'v1');
  const two = await packageRelease(sourceRoot, path.join(directory, 'releases'), 'v2');
  const observed = [], runtime = path.join(directory, 'runtime');
  for (const release of [one, two, one]) {
    const server = await launchRelease(release, runtime);
    try { observed.push(server.health.build); } finally { await server.stop(); }
  }
  return { mode: 'actual-local-child-process-releases', observed, rollbackVerified: JSON.stringify(observed) === JSON.stringify(['v1', 'v2', 'v1']) };
}
