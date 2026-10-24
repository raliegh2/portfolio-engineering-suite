import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import dgram from 'node:dgram';
import {DatabaseSync}from'node:sqlite';
import {normalizeWindows,normalizeSyslog,syslogReceiver}from'../src/collectors.js';
import {importTrivy,importSarif}from'../src/scanners.js';
import {BrokerLifecycle}from'../src/broker-lifecycle.js';
import worker from '../cloud/worker.js';
import {replayMarketHistory}from'../src/market-history.js';
test('observed-price adapter validates OHLC data and produces repeatable paper execution',()=>{
 const bars=[{time:1,open:1.2,high:1.3,low:1.1,close:1.25},{time:2,open:1.25,high:1.4,low:1.2,close:1.3}];
 const report=replayMarketHistory({bars});assert.equal(report.deterministic,true);assert.equal(report.finalPosition,0);assert.equal(report.ordersSubmittedToBroker,0);
 assert.throws(()=>replayMarketHistory({bars:[bars[0],bars[0]]}),/Invalid/);
});
test('additional detection rules cover startup persistence, signed-binary download and script execution',async()=>{
 const {detect}=await import('../src/soc.js');const commands=['certutil.exe -urlcache -split -f https://example.test/file','reg.exe add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Demo','rundll32.exe javascript:demo'];
 const alerts=detect(commands.map((command,index)=>({id:String(index),ts:'2026-10-24T10:00:00Z',host:'fixture',user:'fixture',platform:'windows',type:'process',command})));
 assert.equal(alerts.length,3);
});
test('Windows adapter maps real event IDs, normalizes UTC and pseudonymizes identities',()=>{
 const event=normalizeWindows({recordId:'123',timeCreated:'2026-10-24T10:00:00.1234567Z',id:4625,machineName:'private-host',eventData:{TargetUserName:'private-user'}},'test-salt');
 assert.equal(event.type,'login_failure');assert.equal(event.ts,'2026-10-24T10:00:00.123Z');assert.equal(JSON.stringify(event).includes('private-'),false);
});
test('group membership alerts require a privileged SID, not just an addition event',()=>{
 const row={recordId:'1',timeCreated:'2026-10-24T10:00:00Z',id:4732,eventData:{TargetSid:'S-1-5-32-545'}};
 assert.equal(normalizeWindows(row,'salt').type,'host_event');row.eventData.TargetSid='S-1-5-32-544';assert.equal(normalizeWindows(row,'salt').type,'role_change');
});
test('RFC5424 collector parses failed SSH authentication and rejects malformed frames',()=>{
 const event=normalizeSyslog('<86>1 2026-10-24T10:00:00Z lab-linux sshd 100 - - Failed password for invalid user training from 127.0.0.1 port 1234 ssh2');
 assert.equal(event.type,'login_failure');assert.throws(()=>normalizeSyslog('bad frame'),/RFC5424/);
});
test('actual UDP collector writes valid frames and counts rejected frames',async()=>{
 const directory=path.join(process.cwd(),'work','integration-tests');await fs.mkdir(directory,{recursive:true});
 const file=path.join(directory,'syslog-'+crypto.randomUUID()+'.jsonl'),receiver=await syslogReceiver(file,{port:0}),sender=dgram.createSocket('udp4');
 try{
  for(const message of ['bad','<86>1 2026-10-24T10:00:00Z lab sshd 100 - - Failed password for training from 127.0.0.1'])await new Promise((resolve,reject)=>sender.send(message,receiver.port,'127.0.0.1',e=>e?reject(e):resolve()));
  const deadline=Date.now()+2000;while(receiver.stats.accepted+receiver.stats.rejected<2&&Date.now()<deadline)await new Promise(r=>setTimeout(r,10));
 }finally{sender.close();await receiver.close();}
 assert.deepEqual(receiver.stats,{accepted:1,rejected:1});assert.equal(JSON.parse((await fs.readFile(file,'utf8')).trim()).type,'login_failure');await fs.unlink(file);
});
test('Trivy and SARIF adapters preserve identities, severity and provenance',()=>{
 const trivy={SchemaVersion:2,Results:[{Target:'package-lock.json',Vulnerabilities:[{VulnerabilityID:'CVE-TEST',PkgName:'example',Severity:'HIGH',InstalledVersion:'1'}]}]};
 const scan=importTrivy(trivy,{asset:'lab'});assert.equal(scan.findings[0].severity,'high');assert.equal(scan.findings.length,1);assert.equal(importTrivy(trivy,{asset:'lab'}).id,scan.id);
 const sarif={version:'2.1.0',runs:[{tool:{driver:{name:'scanner'}},results:[{ruleId:'rule',level:'warning',message:{text:'Example'},locations:[{physicalLocation:{artifactLocation:{uri:'src/app.js'},region:{startLine:4}}}]}]}]};
 assert.equal(importSarif(sarif,{asset:'lab'}).findings[0].severity,'medium');assert.throws(()=>importSarif({}, {asset:'lab'}));
});
const event=(id,type,data={})=>({id,type,ts:'2026-10-24T10:00:00Z',...data});
test('cancel request preserves reservation until venue acknowledgment',()=>{
 const ledger=new BrokerLifecycle({maxPosition:5});ledger.apply(event('s','submit.requested',{orderId:'one',quantity:5}));ledger.apply(event('c','cancel.requested',{orderId:'one'}));
 assert.throws(()=>ledger.apply(event('s2','submit.requested',{orderId:'two',quantity:1})),/Exposure/);
 ledger.apply(event('ack','cancel.ack',{orderId:'one'}));ledger.apply(event('s3','submit.requested',{orderId:'two',quantity:1}));
});
test('late fill after cancellation is reconciled rather than silently dropped',()=>{
 const ledger=new BrokerLifecycle({maxPosition:5});ledger.apply(event('s','submit.requested',{orderId:'one',quantity:5}));ledger.apply(event('a','cancel.ack',{orderId:'one'}));ledger.apply(event('s2','submit.requested',{orderId:'two',quantity:5}));
 ledger.apply(event('f2','fill',{orderId:'two',quantity:5}));ledger.apply(event('late','fill',{orderId:'one',quantity:2}));assert.equal(ledger.state.position,7);assert.equal(ledger.state.killed,true);assert.equal(ledger.state.breaches.length,1);
 ledger.apply(event('late','fill',{orderId:'one',quantity:2}));assert.equal(ledger.state.position,7);
});
test('broker discrepancies block submission and kill retains actual outstanding exposure',()=>{
 const ledger=new BrokerLifecycle();ledger.apply(event('s','submit.requested',{orderId:'one',quantity:2}));ledger.apply(event('kill','kill'));assert.equal(ledger.state.orders.one.cancelPending,true);
 ledger.apply(event('f','fill',{orderId:'one',quantity:1}));assert.equal(ledger.state.position,1);assert.equal(ledger.reconcile({position:2}).matches,false);assert.equal(ledger.state.position,2);
});
async function cloudTest(action){
 const db=new DatabaseSync(':memory:');for(const migration of ['0001.sql','0002.sql'])db.exec(await fs.readFile(new URL('../cloud/migrations/'+migration,import.meta.url),'utf8'));
 const adapt=(sql,args=[])=>({bind:(...values)=>adapt(sql,values),first:async()=>db.prepare(sql).get(...args)??null,all:async()=>({results:db.prepare(sql).all(...args)}),run:async()=>{const r=db.prepare(sql).run(...args);return{meta:{changes:r.changes}};}});
 const env={DB:{prepare:adapt,batch:async statements=>{db.exec('BEGIN');try{const r=[];for(const s of statements)r.push(await s.run());db.exec('COMMIT');return r;}catch(e){db.exec('ROLLBACK');throw e;}}},ADMIN_TOKEN:'admin-'.repeat(12),STAFF_TOKEN:'staff-'.repeat(12),VOLUNTEER_TOKEN:'volunteer-'.repeat(8)};
 const request=async(route,method='GET',data,role='admin')=>{const response=await worker.fetch(new Request('https://sandbox.test'+route,{method,headers:{authorization:'Bearer '+env[role.toUpperCase()+'_TOKEN'],'content-type':'application/json'},body:data?JSON.stringify(data):undefined}),env);return{status:response.status,data:await response.json()};};
 try{await action({request,db,env});}finally{db.close();}
}
test('deployed-worker logic enforces roles and member row scopes',async()=>cloudTest(async({request})=>{
 assert.equal((await request('/api/members','POST',{id:'a',group:'training-a',name:'Synthetic A',note:'private'})).status,201);
 await request('/api/members','POST',{id:'b',group:'training-b',name:'Synthetic B',note:'private'});
 const rows=await request('/api/members','GET',undefined,'volunteer');assert.equal(rows.data.length,1);assert.equal(Object.hasOwn(rows.data[0],'private_note'),false);
 assert.equal((await request('/api/members','POST',{id:'c',group:'training-a',name:'Denied'},'volunteer')).status,403);
 assert.equal((await request('/api/audit','GET',undefined,'staff')).status,403);
}));
test('cloud scanner imports are idempotent and require retest evidence before closure',async()=>cloudTest(async({request})=>{
 await request('/api/assets','POST',{id:'lab',group:'training-a',owner:'team',importance:2,exposure:2});
 const scan={id:'scan1',scanner:'trivy',source:'fixture://scan',observedAt:'2026-10-24T10:00:00Z',findings:[{asset:'lab',rule:'CVE-EXAMPLE',title:'Synthetic',severity:'high',evidence:'fixture://evidence'}]};
 assert.equal((await request('/api/scans','POST',{group:'training-a',scan})).status,201);assert.equal((await request('/api/scans','POST',{group:'training-a',scan})).data.duplicate,true);
 const id=(await request('/api/findings')).data[0].id;
 assert.equal((await request('/api/findings/'+id+'/close','POST',{})).status,409);
 await request('/api/findings/'+id+'/assign','POST',{assignee:'analyst'});
 await request('/api/findings/'+id+'/retest','POST',{outcome:'fixed',artifact:'fixture://retest',observedAt:'2026-10-24T10:01:00Z'});
 assert.equal((await request('/api/findings/'+id+'/close','POST',{})).status,200);
}));
test('cloud snapshot restores only into an empty database and preserves content',async()=>cloudTest(async({request,db})=>{
 await request('/api/members','POST',{id:'a',group:'training-a',name:'Synthetic',note:'private'});
 const snapshot=(await request('/api/export')).data;
 assert.equal((await request('/api/restore','POST',{...snapshot,confirmation:'RESTORE_TO_EMPTY'})).status,409);
 for(const table of ['audit','incidents','telemetry','retests','observations','findings','scans','assets','members'])db.exec('DELETE FROM '+table);
 assert.equal((await request('/api/restore','POST',{...snapshot,confirmation:'RESTORE_TO_EMPTY'})).status,200);
 assert.equal((await request('/api/members')).data[0].id,'a');
}));
test('cloud incident disposition requires an analyst and evidence',async()=>cloudTest(async({request})=>{
 const input={id:'incident-test',group:'training-a',rule:'login-burst',evidence:['event-1'],observedAt:'2026-10-24T10:00:00Z'};
 assert.equal((await request('/api/incidents','POST',input,'staff')).status,201);
 assert.equal((await request('/api/incidents/incident-test/disposition','POST',{status:'benign',owner:'analyst',evidence:'fixture://triage'},'volunteer')).status,403);
 assert.equal((await request('/api/incidents/incident-test/disposition','POST',{status:'benign',owner:'analyst',evidence:'fixture://triage'},'staff')).status,200);
 assert.equal((await request('/api/incidents')).data[0].status,'benign');
}));
