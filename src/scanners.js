import { digest, requireText, utc } from './common.js';
const severity = value => ({CRITICAL:'critical',HIGH:'high',MEDIUM:'medium',LOW:'low',UNKNOWN:'low',error:'high',warning:'medium',note:'low',none:'low'}[value] ?? 'low');
export function importTrivy(report,{asset,observedAt=new Date().toISOString()}={}) {
  requireText(asset,'asset');utc(observedAt);
  if(!report || !Number.isInteger(report.SchemaVersion) || (report.Results!==undefined&&!Array.isArray(report.Results))) throw new Error('Invalid Trivy JSON');
  const findings=[], seen=new Set();
  for(const target of report.Results??[]) for(const vulnerability of target.Vulnerabilities??[]) {
    requireText(vulnerability.VulnerabilityID,'vulnerability ID');requireText(vulnerability.PkgName,'package');
    const rule=[target.Type??target.Class??'package',vulnerability.PkgPath??'default',vulnerability.PkgName,vulnerability.VulnerabilityID].join(':');
    if(seen.has(rule))continue;seen.add(rule);
    findings.push({asset,rule,title:String(vulnerability.Title??vulnerability.VulnerabilityID).slice(0,500),severity:severity(vulnerability.Severity),
      evidence:JSON.stringify({target:target.Target,package:vulnerability.PkgName,installed:vulnerability.InstalledVersion,fixed:vulnerability.FixedVersion??null,primaryUrl:vulnerability.PrimaryURL??null}).slice(0,2000)});
  }
  return {id:'trivy-'+digest(report),scanner:'trivy',source:'scanner://trivy/'+digest(report),observedAt,findings};
}
export function importSarif(report,{asset,observedAt=new Date().toISOString()}={}) {
  requireText(asset,'asset');utc(observedAt);
  if(report?.version!=='2.1.0'||!Array.isArray(report.runs))throw new Error('Invalid SARIF 2.1.0');
  const findings=[],seen=new Set();
  for(const run of report.runs)for(const result of run.results??[]) {
    const location=result.locations?.[0]?.physicalLocation;
    const file=location?.artifactLocation?.uri??'unknown',line=location?.region?.startLine??0;
    const rule=[run.tool?.driver?.name??'sarif',result.ruleId??result.ruleIndex??'unknown',file,line].join(':');
    if(seen.has(rule))continue;seen.add(rule);
    findings.push({asset,rule,title:String(result.message?.text??result.ruleId??'SARIF finding').slice(0,500),severity:severity(result.level??'warning'),evidence:JSON.stringify({file,line,ruleId:result.ruleId,help:result.helpUri??null}).slice(0,2000)});
  }
  return {id:'sarif-'+digest(report),scanner:'sarif',source:'scanner://sarif/'+digest(report),observedAt,findings};
}
