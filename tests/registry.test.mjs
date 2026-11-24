import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { validateRegistry,summarize,makeEvidence,validateEvidence,evidenceId,observeAnonymous,CHECKS } from "../src/registry.mjs";
const r=JSON.parse(await readFile(new URL("../registry/apps.json",import.meta.url),"utf8"));
const today="2026-11-24";
const fileport=r.apps.find(a=>a.id==="fileport");
const state=(receipts=[],date=today)=>summarize(r,receipts,date).find(a=>a.id==="fileport");
const e=(check,result="pass",method="operator-attestation",date=today)=>makeEvidence("fileport",check,method,result,date);
test("shipped registry validates; Fileport owner report is not full verification",()=>{
  assert.equal(validateRegistry(r).apps.length,2);
  assert.equal(state().state,"LOGIN_REPORTED_OTHER_CHECKS_OPEN");
  assert.equal(state().outstanding.length,4);
  assert.equal(state().authority,"DESCRIPTIVE_ONLY_NOT_ACCESS_GRANT");
  assert.deepEqual(state().checks["owner-login"].methods,["owner-report"]);
});
test("reject duplicates, out-of-scope origins, arbitrary capability or secret field",()=>{
  for(const mutate of [
    a=>a.apps.push(structuredClone(a.apps[1])),
    a=>a.apps[1].origin="https://fileport.abundent.org.evil.test",
    a=>a.apps[1].capabilities.push("grant.owner"),
    a=>a.apps[1].clientSecret="dummy",
    a=>a.apps[1].evidence[0].method="public-probe",
    a=>a.identity.issuer="https://wrong.example/auth/v1"
  ]) {const bad=structuredClone(r);mutate(bad);assert.throws(()=>validateRegistry(bad));}
});
test("a report is bounded and provenance-preserving even with all checks reported",()=>{
  const pass=CHECKS.map(c=>e(c));
  assert.equal(state(pass).state,"PILOT_CHECKS_REPORTED_PASS");
  assert.equal(state(pass).authority,"DESCRIPTIVE_ONLY_NOT_ACCESS_GRANT");
  assert.equal(state([...pass,e("logout","fail")]).state,"HOLD_REVIEW");
  assert.equal(state(pass,"2027-01-01").checks["owner-login"].status,"STALE_PASS");
  assert.throws(()=>state([e("logout","pass","operator-attestation","2026-11-25")]),/Future/);
  assert.throws(()=>validateEvidence({...e("owner-login"),method:"public-probe"}));
  assert.throws(()=>validateEvidence({...e("logout"),observedOn:"2026-02-30"}));
  assert.equal(evidenceId(e("logout")),evidenceId(e("logout")));
});
test("anonymous probe is exact route, no credentials, no login claim",async()=>{
  const p=await observeAnonymous(fileport,async(url,options)=>{
    assert.equal(url,fileport.origin+"/api/static-id/status");
    assert.equal(options.redirect,"manual");
    assert.ok(!("Authorization" in options.headers));assert.ok(!("Cookie" in options.headers));
    return Response.json({authenticated:false});
  },today);
  assert.equal(p.evidence.check,"anonymous-denied");
  assert.equal(p.evidence.method,"public-probe");
  assert.equal(p.evidence.result,"pass");
  assert.equal(state([p.evidence]).outstanding.length,3);
  assert.equal((await observeAnonymous(fileport,async()=>Response.json({authenticated:true}),today)).evidence.result,"fail");
  assert.equal((await observeAnonymous(fileport,async()=>Response.json({}, {status:503}),today)).evidence.result,"hold");
  assert.equal((await observeAnonymous(fileport,async()=>{throw Error("network")},today)).evidence.result,"hold");
  await assert.rejects(()=>observeAnonymous({...fileport,lifecycle:"candidate"}));
});
