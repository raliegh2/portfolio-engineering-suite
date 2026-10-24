const encoder=new TextEncoder();
const hash=async value=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',encoder.encode(typeof value==='string'?value:JSON.stringify(value))))).map(n=>n.toString(16).padStart(2,'0')).join('');
const text=(value,max=500)=>{if(typeof value!=='string'||!value.trim()||value.length>max)throw Object.assign(new Error('Invalid field'),{status:400});return value;};
const date=value=>{text(value);if(!/Z$/.test(value)||!Number.isFinite(Date.parse(value)))throw Object.assign(new Error('Invalid UTC timestamp'),{status:400});return value;};
const fail=(message='Forbidden',status=403)=>{throw Object.assign(new Error(message),{status});};
const publicHeaders={'content-type':'application/json','cache-control':'no-store','x-content-type-options':'nosniff','content-security-policy':"default-src 'none'; frame-ancestors 'none'"};
const response=(body,status=200)=>new Response(JSON.stringify(body),{status,headers:publicHeaders});
const tables={members:['id','group_id','display_name','private_note'],assets:['id','group_id','owner','importance','exposure'],scans:['id','group_id','fingerprint','observed_at','source'],findings:['id','asset_id','rule','title','severity','status','assignee','last_seen'],observations:['scan_id','finding_id','evidence'],retests:['id','finding_id','outcome','artifact','observed_at'],telemetry:['id','group_id','source','collected','rejected','observed_at'],incidents:['id','group_id','rule','evidence_json','status','owner','disposition_evidence','observed_at'],audit:['id','actor','action','observed_at']};
async function actor(request,env){
  const supplied=request.headers.get('authorization')??'';
  if(!supplied.startsWith('Bearer ')||supplied.length>512)fail('Unauthorized',401);
  const actual=await hash(supplied.slice(7));
  for(const [role,key]of Object.entries({admin:'ADMIN_TOKEN',staff:'STAFF_TOKEN',volunteer:'VOLUNTEER_TOKEN'})){
    if(!env[key]||env[key].length<32)continue;
    const expected=await hash(env[key]);let difference=0;for(let i=0;i<expected.length;i++)difference|=actual.charCodeAt(i)^expected.charCodeAt(i);
    if(difference===0)return {id:'sandbox-'+role,role,group:'training-a'};
  }
  fail('Unauthorized',401);
}
async function payload(request){const raw=await request.text();if(encoder.encode(raw).length>131072)fail('Payload too large',413);let data;try{data=JSON.parse(raw);}catch{fail('Invalid JSON',400);}if(!data||typeof data!=='object'||Array.isArray(data))fail('Invalid object',400);return data;}
const statement=(env,sql,...args)=>env.DB.prepare(sql).bind(...args);
const log=(env,user,action)=>statement(env,'INSERT INTO audit(actor,action,observed_at) VALUES(?,?,?)',user.id,action,new Date().toISOString());
const writer=user=>{if(user.role==='volunteer')fail();};
const group=(user,value)=>{text(value,100);if(user.role!=='admin'&&value!==user.group)fail();return value;};
export default {
async fetch(request,env){
 try{
  const url=new URL(request.url), route=url.pathname;
  if(request.method==='GET'&&route==='/health'){
    await env.DB.prepare('SELECT 1 AS ready').first();
    return response({status:'ok',mode:'synthetic-cloud-sandbox',version:env.BUILD_VERSION??'1',database:'connected'});
  }
  if(request.method==='GET'&&route==='/')return response({project:'Portfolio Engineering Suite',repository:'https://github.com/raliegh2/portfolio-engineering-suite',data:'Synthetic only; role-scoped APIs require bearer credentials',health:'/health'});
  const user=await actor(request,env);
  if(route==='/api/telemetry'&&request.method==='POST'){
    writer(user);const input=await payload(request),scope=group(user,input.group);
    if(![input.collected,input.rejected].every(n=>Number.isSafeInteger(n)&&n>=0))fail('Invalid counters',400);
    await env.DB.batch([statement(env,'INSERT INTO telemetry VALUES(?,?,?,?,?,?)',text(input.id,100),scope,text(input.source),input.collected,input.rejected,date(input.observedAt)),log(env,user,'ingest-telemetry')]);return response({saved:true},201);
  }
  if(route==='/api/telemetry'&&request.method==='GET')return response((await(user.role==='admin'?env.DB.prepare('SELECT * FROM telemetry ORDER BY observed_at'):statement(env,'SELECT * FROM telemetry WHERE group_id=? ORDER BY observed_at',user.group)).all()).results);
  if(route==='/api/incidents'&&request.method==='POST'){
    writer(user);const input=await payload(request),scope=group(user,input.group);
    if(!Array.isArray(input.evidence)||input.evidence.length>100||!input.evidence.every(v=>typeof v==='string'&&v.length<=200))fail('Invalid incident evidence',400);
    await env.DB.batch([statement(env,"INSERT INTO incidents VALUES(?,?,?,?,'needs_review',NULL,NULL,?) ON CONFLICT(id) DO NOTHING",text(input.id,100),scope,text(input.rule),JSON.stringify(input.evidence),date(input.observedAt)),log(env,user,'ingest-incident')]);return response({saved:true},201);
  }
  if(route==='/api/incidents'&&request.method==='GET')return response((await(user.role==='admin'?env.DB.prepare('SELECT * FROM incidents ORDER BY observed_at'):statement(env,'SELECT * FROM incidents WHERE group_id=? ORDER BY observed_at',user.group)).all()).results);
  const incidentAction=route.match(/^\/api\/incidents\/([a-zA-Z0-9-]{1,100})\/disposition$/);
  if(incidentAction&&request.method==='POST'){
    writer(user);const input=await payload(request),incident=await statement(env,'SELECT * FROM incidents WHERE id=?',incidentAction[1]).first();if(!incident)fail('Not found',404);group(user,incident.group_id);
    if(!['confirmed','benign','needs_review'].includes(input.status))fail('Invalid disposition',400);
    await env.DB.batch([statement(env,'UPDATE incidents SET status=?,owner=?,disposition_evidence=? WHERE id=?',input.status,text(input.owner),text(input.evidence,2000),incident.id),log(env,user,'incident-disposition')]);return response({saved:true});
  }
  if(route==='/api/members'&&request.method==='GET'){
    const result=await (user.role==='admin'?env.DB.prepare('SELECT * FROM members ORDER BY id'):statement(env,'SELECT * FROM members WHERE group_id=? ORDER BY id',user.group)).all();
    return response(result.results.map(row=>user.role==='volunteer'?{id:row.id,group_id:row.group_id,display_name:row.display_name}:row));
  }
  if(route==='/api/members'&&request.method==='POST'){
    writer(user);const input=await payload(request);const scope=group(user,input.group);
    await env.DB.batch([statement(env,'INSERT INTO members VALUES(?,?,?,?)',text(input.id,100),scope,text(input.name,100),typeof input.note==='string'?input.note.slice(0,2000):''),log(env,user,'create-member')]);return response({created:true},201);
  }
  if(route==='/api/assets'&&request.method==='POST'){
    writer(user);const input=await payload(request),scope=group(user,input.group);
    const prior=await statement(env,'SELECT group_id FROM assets WHERE id=?',text(input.id,100)).first();if(prior&&prior.group_id!==scope)fail('Asset scope conflict',409);
    if(![input.importance,input.exposure].every(v=>Number.isInteger(v)&&v>=1&&v<=3))fail('Invalid ranking',400);
    await env.DB.batch([statement(env,'INSERT INTO assets VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET owner=excluded.owner,importance=excluded.importance,exposure=excluded.exposure',input.id,scope,text(input.owner),input.importance,input.exposure),log(env,user,'upsert-asset')]);return response({saved:true});
  }
  if(route==='/api/scans'&&request.method==='POST'){
    writer(user);const input=await payload(request),scope=group(user,input.group),scan=input.scan;
    if(!scan||!Array.isArray(scan.findings)||scan.findings.length>500)fail('Invalid scan',400);
    for(const field of ['id','source','scanner'])text(scan[field]);date(scan.observedAt);
    const fingerprint=await hash(scan),prior=await statement(env,'SELECT * FROM scans WHERE id=?',scan.id).first();
    if(prior){if(prior.group_id!==scope||prior.fingerprint!==fingerprint)fail('Conflicting scan ID',409);return response({duplicate:true,imported:0});}
    const batch=[statement(env,'INSERT INTO scans VALUES(?,?,?,?,?)',scan.id,scope,fingerprint,scan.observedAt,scan.source)];const seen=new Set();
    for(const finding of scan.findings){
      for(const field of ['asset','rule','title','evidence'])text(finding[field],2000);
      if(!['low','medium','high','critical'].includes(finding.severity))fail('Invalid severity',400);
      const asset=await statement(env,'SELECT * FROM assets WHERE id=?',finding.asset).first();if(!asset||asset.group_id!==scope)fail('Asset outside scope');
      const id=await hash([finding.asset,scan.scanner,finding.rule]);if(seen.has(id))fail('Duplicate finding',400);seen.add(id);
      batch.push(statement(env,"INSERT INTO findings VALUES(?,?,?,?,?,'open',NULL,?) ON CONFLICT(id) DO UPDATE SET last_seen=CASE WHEN julianday(excluded.last_seen)>julianday(last_seen) THEN excluded.last_seen ELSE last_seen END",id,finding.asset,finding.rule,finding.title,finding.severity,scan.observedAt));
      batch.push(statement(env,'INSERT INTO observations VALUES(?,?,?)',scan.id,id,finding.evidence));
      batch.push(statement(env,"UPDATE findings SET status='open' WHERE id=? AND status='closed' AND julianday(?)>=COALESCE((SELECT MAX(julianday(observed_at)) FROM retests WHERE finding_id=?),0)",id,scan.observedAt,id));
    }
    batch.push(log(env,user,'import-scan'));await env.DB.batch(batch);return response({duplicate:false,imported:scan.findings.length},201);
  }
  if(route==='/api/findings'&&request.method==='GET'){
    const result=await (user.role==='admin'?env.DB.prepare('SELECT f.*,a.owner,a.group_id FROM findings f JOIN assets a ON a.id=f.asset_id ORDER BY f.id'):statement(env,'SELECT f.*,a.owner,a.group_id FROM findings f JOIN assets a ON a.id=f.asset_id WHERE a.group_id=? ORDER BY f.id',user.group)).all();return response(result.results);
  }
  const action=route.match(/^\/api\/findings\/([a-f0-9]{64})\/(assign|retest|close)$/);
  if(action&&request.method==='POST'){
    writer(user);const [,id,operation]=action,input=await payload(request);
    const finding=await statement(env,'SELECT f.*,a.group_id FROM findings f JOIN assets a ON a.id=f.asset_id WHERE f.id=?',id).first();if(!finding)fail('Not found',404);group(user,finding.group_id);
    if(operation==='assign')await env.DB.batch([statement(env,"UPDATE findings SET assignee=?,status='in_progress' WHERE id=?",text(input.assignee),id),log(env,user,'assign-finding')]);
    if(operation==='retest'){
      if(!['fixed','vulnerable'].includes(input.outcome)||Date.parse(date(input.observedAt))<Date.parse(finding.last_seen))fail('Invalid retest',400);
      const batch=[statement(env,'INSERT INTO retests VALUES(?,?,?,?,?)',crypto.randomUUID(),id,input.outcome,text(input.artifact,2000),input.observedAt),log(env,user,'retest-finding')];
      if(input.outcome==='vulnerable')batch.push(statement(env,"UPDATE findings SET status='open' WHERE id=? AND (SELECT outcome FROM retests WHERE finding_id=? ORDER BY julianday(observed_at) DESC,id DESC LIMIT 1)='vulnerable'",id,id));await env.DB.batch(batch);
    }
    if(operation==='close'){
      const retest=await statement(env,'SELECT * FROM retests WHERE finding_id=? ORDER BY julianday(observed_at) DESC,id DESC LIMIT 1',id).first();
      if(!finding.assignee||retest?.outcome!=='fixed'||Date.parse(retest.observed_at)<Date.parse(finding.last_seen))fail('Current successful retest required',409);
      const result=await env.DB.batch([statement(env,"UPDATE findings SET status='closed' WHERE id=? AND assignee IS NOT NULL AND EXISTS(SELECT 1 FROM retests WHERE finding_id=? AND outcome='fixed' AND julianday(observed_at)>=julianday(findings.last_seen) AND id=(SELECT id FROM retests WHERE finding_id=? ORDER BY julianday(observed_at) DESC,id DESC LIMIT 1))",id,id,id),log(env,user,'close-finding-attempt')]);
      if(!result[0].meta.changes)fail('Finding changed before closure',409);
    }return response({saved:true});
  }
  if(route==='/api/audit'&&request.method==='GET'){if(user.role!=='admin')fail();return response((await env.DB.prepare('SELECT * FROM audit ORDER BY id').all()).results);}
  if(route==='/api/export'&&request.method==='GET'){
    if(user.role!=='admin')fail();const data={};for(const table of Object.keys(tables))data[table]=(await env.DB.prepare('SELECT * FROM '+table+' ORDER BY 1').all()).results;
    return response({schema:1,observedAt:new Date().toISOString(),data,sha256:await hash(data)});
  }
  if(route==='/api/restore'&&request.method==='POST'){
    if(user.role!=='admin')fail();const input=await payload(request);
    if(input.schema!==1||input.confirmation!=='RESTORE_TO_EMPTY'||await hash(input.data)!==input.sha256)fail('Invalid restore',400);
    const batch=[];
    for(const [table,columns]of Object.entries(tables)){
      if((await env.DB.prepare('SELECT count(*) AS n FROM '+table).first()).n)fail('Restore target must be empty',409);
      if(!Array.isArray(input.data[table])||input.data[table].length>5000)fail('Invalid restore rows',400);
      for(const row of input.data[table])batch.push(statement(env,'INSERT INTO '+table+'('+columns.join(',')+') VALUES('+columns.map(()=>'?').join(',')+')',...columns.map(c=>row[c])));
    }if(batch.length)await env.DB.batch(batch);return response({restored:true});
  }
  return response({error:'Not found'},404);
 }catch(error){return response({error:error.status?error.message:'Request failed'},error.status??500);}
}
};
