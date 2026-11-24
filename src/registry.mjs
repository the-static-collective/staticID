// STATIC ID 003 · descriptive registry, not an authorization service.
import { createHash } from "node:crypto";
import { appPlan, ISSUER, CONSENT, probe } from "./onboarding.mjs";
export const CHECKS=Object.freeze(["anonymous-denied","owner-login","protected-read","logout","recovery"]);
const CAPABILITIES=new Set(["identity.consent","identity.owner-login","files.owner-read","files.owner-write","files.invited-share","files.recovery"]);
const slug=/^[a-z0-9][a-z0-9-]{0,62}$/;
const keys=(obj,allowed)=>obj && typeof obj==="object" && !Array.isArray(obj) && Object.keys(obj).every(k=>allowed.includes(k));
const exact=(obj,required)=>keys(obj,required)&&required.every(k=>Object.hasOwn(obj,k));
const validDate=d=>typeof d==="string"&&/^\d{4}-\d{2}-\d{2}$/.test(d)&&Number.isFinite(Date.parse(d))&&new Date(d).toISOString().slice(0,10)===d;
function uniqueStrings(list,allowed) {
  return Array.isArray(list)&&new Set(list).size===list.length&&list.every(x=>allowed.has(x));
}
export function validateRegistry(raw) {
  if(!exact(raw,["schema","identity","apps"])||raw.schema!=="static-id/registry/v1"||
     !exact(raw.identity,["issuer","consent"])||raw.identity.issuer!==ISSUER||raw.identity.consent!==CONSENT||
     !Array.isArray(raw.apps)||raw.apps.length>100) throw Error("Invalid registry schema or identity boundary");
  const ids=new Set(),origins=new Set(),projects=new Set();
  let hosts=0;
  for(const a of raw.apps) {
    if(!exact(a,["id","name","origin","kind","project","lifecycle","capabilities","evidence"])||
       typeof a.id!=="string"||!slug.test(a.id)||ids.has(a.id)||origins.has(a.origin)||
       !uniqueStrings(a.capabilities,CAPABILITIES)||!Array.isArray(a.evidence)||a.evidence.length>100)
      throw Error("Invalid or duplicate application declaration");
    if(a.kind==="identity-host") {
      hosts++;
      if(a.origin!==new URL(CONSENT).origin||a.project!==null||a.lifecycle!=="identity-host"||
         a.capabilities.some(c=>!c.startsWith("identity."))) throw Error("Invalid identity host");
      // Validate labels and origin through the same strict plan boundary.
      appPlan({name:a.name,origin:a.origin,project:a.id});
    } else if(a.kind==="pages-client") {
      if(!["candidate","onboarding","pilot","retired"].includes(a.lifecycle)||
         projects.has(a.project)||a.capabilities.includes("identity.consent"))
        throw Error("Invalid client lifecycle or duplicated project");
      appPlan({name:a.name,origin:a.origin,project:a.project});
      projects.add(a.project);
    } else throw Error("Unknown application kind");
    ids.add(a.id);origins.add(a.origin);
    for(const e of a.evidence) {
      validateEvidence(e);
      if(e.app!==a.id||e.method!=="owner-report") throw Error("Committed observations must be attributable owner reports for this app");
    }
    if(a.kind==="identity-host"&&a.evidence.length) throw Error("Client checks do not certify identity-host health");
  }
  if(hosts!==1) throw Error("Registry requires exactly one identity host");
  return structuredClone(raw);
}
export function validateEvidence(e) {
  if(!exact(e,["schema","app","check","method","result","observedOn"])||
     e.schema!=="static-id/check/v1"||typeof e.app!=="string"||!slug.test(e.app)||
     !CHECKS.includes(e.check)||!["owner-report","operator-attestation","public-probe"].includes(e.method)||
     !["pass","fail","hold"].includes(e.result)||!validDate(e.observedOn)||
     (e.method==="public-probe"&&e.check!=="anonymous-denied"))
    throw Error("Invalid evidence; no arbitrary logs, tokens or claimed automated owner verification");
  return structuredClone(e);
}
export function makeEvidence(app,check,method,result,observedOn=new Date().toISOString().slice(0,10)) {
  return validateEvidence({schema:"static-id/check/v1",app,check,method,result,observedOn});
}
export function evidenceId(e) {
  const v=validateEvidence(e);
  // Canonical field order independent of input JSON key order.
  return createHash("sha256").update(JSON.stringify([v.schema,v.app,v.check,v.method,v.result,v.observedOn])).digest("hex");
}
export function summarize(registry,receipts=[],today=new Date().toISOString().slice(0,10)) {
  const r=validateRegistry(registry);
  if(!validDate(today)||!Array.isArray(receipts)||receipts.length>1000)throw Error("Invalid report scope");
  const extra=receipts.map(validateEvidence);
  for(const e of extra)if(!r.apps.some(a=>a.id===e.app&&a.kind==="pages-client"))throw Error("Receipt app is not a registered client");
  return r.apps.map(a=>{
    const evidence=[...a.evidence,...extra.filter(e=>e.app===a.id)];
    if(evidence.some(e=>e.observedOn>today))throw Error("Future-dated evidence; inspect local clock");
    const checks=Object.fromEntries(CHECKS.map(check=>{
      const matches=evidence.filter(e=>e.check===check).sort((x,y)=>y.observedOn.localeCompare(x.observedOn));
      if(!matches.length)return [check,{status:"NOT_OBSERVED"}];
      const date=matches[0].observedOn;
      const latest=matches.filter(e=>e.observedOn===date);
      const ageDays=Math.round((Date.parse(today)-Date.parse(date))/86400000);
      // Same-day contradictory results HOLD instead of silently choosing a winner.
      const result=new Set(latest.map(e=>e.result)).size>1?"hold":latest[0].result;
      return [check,{status:result==="pass"?(ageDays>30?"STALE_PASS":"REPORTED_PASS"):result.toUpperCase(),
        observedOn:date,ageDays,methods:[...new Set(latest.map(e=>e.method))].sort(),
        evidenceIds:[...new Set(latest.map(evidenceId))].sort()}];
    }));
    const outstanding=a.kind==="pages-client"?CHECKS.filter(c=>checks[c].status!=="REPORTED_PASS"):[];
    const state=a.kind==="identity-host"?"IDENTITY_HOST_DECLARED":
      a.lifecycle==="retired"?"RETIRED":
      a.lifecycle==="candidate"?"CANDIDATE_NOT_CONNECTED":
      Object.values(checks).some(c=>["FAIL","HOLD"].includes(c.status))?"HOLD_REVIEW":
      outstanding.length===0?"PILOT_CHECKS_REPORTED_PASS":
      checks["owner-login"].status==="REPORTED_PASS"?"LOGIN_REPORTED_OTHER_CHECKS_OPEN":"CHECKS_OPEN";
    return {id:a.id,name:a.name,origin:a.origin,kind:a.kind,project:a.project,lifecycle:a.lifecycle,
      state,capabilitiesDeclared:a.capabilities,
      ...(a.kind==="pages-client"?{callback:appPlan({project:a.project,origin:a.origin,name:a.name}).callback,checks,outstanding}:{}),
      authority:"DESCRIPTIVE_ONLY_NOT_ACCESS_GRANT"};
  });
}
export async function observeAnonymous(app,fetcher=fetch,observedOn=new Date().toISOString().slice(0,10)) {
  if(app.kind!=="pages-client"||app.lifecycle==="retired"||app.lifecycle==="candidate")throw Error("No live probe for this entry");
  const p=appPlan({project:app.project,origin:app.origin,name:app.name});
  let outcome;
  try{outcome=await probe(p,fetcher);}catch{outcome={status:"HOLD_UNREACHABLE"};}
  const result=outcome.status==="ANONYMOUS_DENIED_LOGIN_NOT_TESTED"?"pass":
    outcome.status==="HOLD_UNEXPECTED_ANONYMOUS_RESPONSE"?"fail":"hold";
  return {observation:outcome.status,evidence:makeEvidence(app.id,"anonymous-denied","public-probe",result,observedOn)};
}
