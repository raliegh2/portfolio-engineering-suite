import fs from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
const files = [...(await fs.readdir('src')).filter(f => f.endsWith('.js')).map(f => 'src/' + f), ...(await fs.readdir('test')).filter(f => f.endsWith('.js')).map(f => 'test/' + f)];
for (const file of files) {
  const result = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8', windowsHide: true });
  if (result.status !== 0) { console.error(result.stderr); process.exit(1); }
}
const manifest = JSON.parse(await fs.readFile('package.json'));
if (Object.keys(manifest.dependencies ?? {}).length) throw new Error('Dependency policy changed; audit required');
console.log(JSON.stringify({ syntaxFiles: files.length, thirdPartyRuntimeDependencies: 0, dependencyPolicy: 'standard-library-only' }));
