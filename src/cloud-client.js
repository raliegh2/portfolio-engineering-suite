import fs from 'node:fs/promises';
export class CloudClient{
 constructor(origin,token){const parsed=new URL(origin);if(parsed.protocol!=='https:'||parsed.username||parsed.password)throw new Error('HTTPS origin required');if(typeof token!=='string'||token.length<32)throw new Error('Private role token required');this.origin=parsed.origin;this.token=token;}
 async request(route,{method='GET',body}={}){
  if(!/^\/(?:api\/|health$)/.test(route))throw new Error('Invalid cloud route');
  const response=await fetch(this.origin+route,{method,redirect:'error',signal:AbortSignal.timeout(15000),headers:{authorization:'Bearer '+this.token,'content-type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});
  const data=await response.json();if(!response.ok)throw Object.assign(new Error('Cloud request returned '+response.status),{status:response.status});return data;
 }
 static async fromSecrets(origin,file,role='admin'){const keys={admin:'ADMIN_TOKEN',staff:'STAFF_TOKEN',volunteer:'VOLUNTEER_TOKEN'};if(!Object.hasOwn(keys,role))throw new Error('Invalid role');const secrets=JSON.parse(await fs.readFile(file,'utf8'));return new CloudClient(origin,secrets[keys[role]]);}
}
