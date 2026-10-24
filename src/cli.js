import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { allDemos } from './demos.js';
import { liveAgentBenchmark } from './agent.js';
import { ingestJsonl, detect, incidentReport } from './soc.js';
import { RemediationTracker } from './remediation.js';
import { PaperExchange } from './replay.js';
import { ChurchSandbox, createChurchServer, restoreBackup } from './church.js';
import { BUILD_VERSION } from './build.js';
import { digest, writeJson } from './common.js';
import { releaseExercise } from './releases.js';
import { securityFixture, scanFixture, tradingFixture } from './fixtures.js';
import { collectWindows,syslogReceiver } from './collectors.js';
import { importTrivy,importSarif } from './scanners.js';
export async function command(args) {
  const [action, ...values] = args;
  if(action==='collect-windows')return collectWindows(values[0]??'work/collector',{channel:values[1]??'Application',limit:Number(values[2]??100)});
  if(action==='syslog'){
    const receiver=await syslogReceiver(values[0]??'work/syslog/events.jsonl',{port:Number(values[1]??5514)});
    process.once('SIGINT',async()=>{await receiver.close();process.exit(0);});
    process.once('SIGTERM',async()=>{await receiver.close();process.exit(0);});
    return {listening:receiver.port,transport:'loopback-UDP-RFC5424',output:values[0]??'work/syslog/events.jsonl'};
  }
  if(action==='scan-import'){
    const [format,input,dbFile,asset,owner='platform-team']=values;
    const parser={trivy:importTrivy,sarif:importSarif}[format];if(!parser)throw new Error('Expected trivy or sarif');
    const scan=parser(JSON.parse(await fs.readFile(input,'utf8')),{asset});
    await fs.mkdir(path.dirname(dbFile),{recursive:true});const tracker=new RemediationTracker(dbFile);
    try{tracker.asset(asset,owner,2,2);const imported=tracker.importScan(scan);return {...imported,summary:tracker.report().summary};}finally{tracker.close();}
  }
  if (action === 'fixtures') {
    await fs.mkdir('examples', { recursive: true });
    await fs.writeFile('examples/security.jsonl', securityFixture().text);
    await writeJson('examples/scan.json', scanFixture); await writeJson('examples/trading.json', tradingFixture());
    return { generated: ['examples/security.jsonl', 'examples/scan.json', 'examples/trading.json'] };
  }
  if (action === 'demo') {
    const report = await allDemos(values[0] ?? 'evidence');
    return { report: 'evidence/suite-report.json', soc: report.soc.metrics, remediation: report.remediation, deployment: report.deployment, trading: { cashCents: report.trading.cashCents, position: report.trading.position, repeatMatches: report.trading.repeatMatches } };
  }
  if (action === 'agent-live') {
    const report = await liveAgentBenchmark(); await writeJson(values[0] ?? 'evidence/agent-live.json', report);
    return { total: report.total, taskSuccessRate: report.taskSuccessRate, policyPassRate: report.policyPassRate, outcomes: report.results.map(r => ({ id: r.id, outcome: r.outcome })) };
  }
  if (action === 'release-demo') {
    const root = fileURLToPath(new URL('../', import.meta.url));
    const directory = path.resolve(values[0] ?? path.join('work', 'release-exercises', crypto.randomUUID()));
    const report = await releaseExercise(root, directory);
    await writeJson('evidence/release-report.json', report); return report;
  }
  if (action === 'soc') {
    const [input, out = 'evidence/soc'] = values, parsed = ingestJsonl(await fs.readFile(input, 'utf8'));
    const alerts = detect(parsed.events); await writeJson(path.join(out, 'alerts.json'), { ...parsed, alerts });
    await fs.writeFile(path.join(out, 'incident.md'), incidentReport(alerts));
    return { events: parsed.events.length, rejected: parsed.rejected.length, alerts: alerts.length };
  }
  if (action === 'vuln') {
    const [operation, dbFile, ...params] = values;
    await fs.mkdir(path.dirname(dbFile), { recursive: true }); const tracker = new RemediationTracker(dbFile);
    try {
      if (operation === 'asset') tracker.asset(params[0], params[1], Number(params[2] ?? 1), Number(params[3] ?? 1));
      else if (operation === 'import') return tracker.importScan(JSON.parse(await fs.readFile(params[0], 'utf8')));
      else if (operation === 'assign') tracker.assign(params[0], params[1]);
      else if (operation === 'retest') tracker.retest(params[0], params[1], params[2], params[3]);
      else if (operation === 'close') tracker.closeFinding(params[0], params[1]);
      else if (operation !== 'report') throw new Error('Unknown vulnerability operation');
      const report = tracker.report(); if (operation === 'report' && params[0]) await writeJson(params[0], report); return report;
    } finally { tracker.close(); }
  }
  if (action === 'replay') {
    const [input, out = 'evidence/replay.json', resume] = values;
    const data = JSON.parse(await fs.readFile(input, 'utf8'));
    const exchange = resume ? await PaperExchange.load(resume) : new PaperExchange(data.config);
    for (const event of data.events) exchange.apply(event);
    await writeJson(out, { mode: 'offline-paper-replay', hash: exchange.hash(), ...exchange.snapshot() });
    await exchange.save(out + '.checkpoint.json'); return { hash: exchange.hash(), cashCents: exchange.state.cashCents, position: exchange.state.position };
  }
  if (action === 'backup') {
    const sandbox = new ChurchSandbox(values[0]); try { return await sandbox.backupTo(values[1]); } finally { sandbox.close(); }
  }
  if (action === 'restore') return restoreBackup(values[0], values[1]);
  if (action === 'serve') {
    const directory = path.resolve(values[0] ?? 'work/church-runtime'), port = Number(values[1] ?? 8894);
    if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('Invalid port');
    await fs.mkdir(directory, { recursive: true });
    const secretFile = path.join(directory, 'session.key');
    let secret; try { secret = await fs.readFile(secretFile, 'utf8'); } catch (e) {
      if (e.code !== 'ENOENT') throw e; secret = crypto.randomBytes(48).toString('hex'); await fs.writeFile(secretFile, secret, { flag: 'wx', mode: 0o600 });
    }
    const sandbox = new ChurchSandbox(path.join(directory, 'church.sqlite'));
    if (!sandbox.db.prepare('SELECT id FROM users LIMIT 1').get()) {
      const credentials = {};
      for (const role of ['admin', 'staff', 'volunteer']) {
        credentials[role] = crypto.randomBytes(20).toString('base64url'); sandbox.createUser(role, credentials[role], role, 'synthetic-group');
      }
      sandbox.addMember('admin', { id: 'synthetic-member-1', group: 'synthetic-group', name: 'Synthetic Training Member', note: 'Synthetic private note' });
      await fs.writeFile(path.join(directory, 'bootstrap.json'), JSON.stringify(credentials), { flag: 'wx', mode: 0o600 });
    }
    sandbox.release(BUILD_VERSION, digest(await fs.readFile(new URL('./church.js', import.meta.url))));
    const server = createChurchServer(sandbox, { secret });
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, process.env.CHURCH_BIND_HOST ?? '127.0.0.1', resolve); });
    const stop = () => server.close(() => { sandbox.close(); process.exit(0); });
    process.once('SIGTERM', stop); process.once('SIGINT', stop);
    return { listening: server.address().port, mode: 'synthetic-local-sandbox', build: BUILD_VERSION, bootstrapFile: path.join(directory, 'bootstrap.json') };
  }
  throw new Error('Usage: cli.js demo|agent-live|soc|vuln|replay|serve|backup|restore (see README.md)');
}
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  command(process.argv.slice(2)).then(result => console.log(JSON.stringify(result))).catch(error => { console.error(error.message); process.exitCode = 1; });
}
