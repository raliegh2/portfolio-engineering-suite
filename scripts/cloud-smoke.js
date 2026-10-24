import fs from 'node:fs/promises';
import {CloudClient}from'../src/cloud-client.js';
import {writeJson}from'../src/common.js';
const [origin,secretFile,output='evidence/cloud-verification.json',backupFile]=process.argv.slice(2);
if(!origin||!secretFile)throw new Error('Usage: cloud-smoke.js HTTPS_ORIGIN PRIVATE_SECRET_FILE [PUBLIC_REPORT] [PRIVATE_BACKUP]');
const admin=await CloudClient.fromSecrets(origin,secretFile),volunteer=await CloudClient.fromSecrets(origin,secretFile,'volunteer'),staff=await CloudClient.fromSecrets(origin,secretFile,'staff');
const nonce=crypto.randomUUID().slice(0,8),member='synthetic-'+nonce,asset='scanner-'+nonce;
const health=await admin.request('/health');
await admin.request('/api/members',{method:'POST',body:{id:member,group:'training-a',name:'Synthetic Training Member',note:'Synthetic private note'}});
await admin.request('/api/members',{method:'POST',body:{id:member+'-other',group:'training-b',name:'Synthetic Other Group',note:'Synthetic private note'}});
const visible=await volunteer.request('/api/members');
let deniedWrite=false,deniedAudit=false;
try{await volunteer.request('/api/members',{method:'POST',body:{id:'denied',group:'training-a',name:'Denied'}});}catch(e){deniedWrite=e.status===403;}
try{await staff.request('/api/audit');}catch(e){deniedAudit=e.status===403;}
await admin.request('/api/assets',{method:'POST',body:{id:asset,group:'training-a',owner:'synthetic-platform-team',importance:2,exposure:2}});
const now=new Date().toISOString(),scan={id:'verification-'+nonce,scanner:'cloud-contract-test',source:'fixture://cloud-contract/'+nonce,observedAt:now,findings:[{asset,rule:'synthetic-header',title:'Synthetic validation finding',severity:'medium',evidence:'fixture://observation'}]};
const imported=await admin.request('/api/scans',{method:'POST',body:{group:'training-a',scan}}),duplicate=await admin.request('/api/scans',{method:'POST',body:{group:'training-a',scan}});
const finding=(await admin.request('/api/findings')).find(f=>f.asset_id===asset);let closureBlocked=false;
try{await admin.request('/api/findings/'+finding.id+'/close',{method:'POST',body:{}});}catch(e){closureBlocked=e.status===409;}
await admin.request('/api/findings/'+finding.id+'/assign',{method:'POST',body:{assignee:'synthetic-analyst'}});
await admin.request('/api/findings/'+finding.id+'/retest',{method:'POST',body:{outcome:'fixed',artifact:'fixture://successful-cloud-retest',observedAt:new Date().toISOString()}});
await admin.request('/api/findings/'+finding.id+'/close',{method:'POST',body:{}});
const closed=(await admin.request('/api/findings')).find(f=>f.id===finding.id).status==='closed';
const snapshot=await admin.request('/api/export');if(backupFile)await fs.writeFile(backupFile,JSON.stringify(snapshot));
const report={observedAt:new Date().toISOString(),origin,mode:'actual-deployed-workers-d1',health:health.status,
 roleChecks:{volunteerOwnGroupOnly:visible.every(m=>m.group_id==='training-a'),privateFieldsHidden:visible.every(m=>!Object.hasOwn(m,'private_note')),deniedWrite,deniedAudit},
 remediation:{imported:imported.imported,idempotent:duplicate.duplicate,closureBlocked,closedAfterRetest:closed},backup:{exported:true,sha256:snapshot.sha256,schema:snapshot.schema}};
if(!Object.values(report.roleChecks).every(Boolean)||!duplicate.duplicate||!closureBlocked||!closed)throw new Error('Cloud integration verification failed');
await writeJson(output,report);console.log(JSON.stringify(report));
