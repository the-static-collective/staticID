import test from "node:test";
import assert from "node:assert/strict";
import { readFile,mkdtemp,readdir,rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildGate,renderGate,publicDirectory } from "../tools/build-gate.mjs";
const registry=JSON.parse(await readFile(new URL("../registry/apps.json",import.meta.url),"utf8"));
test("public Gate projects only eligible registry entries and safe navigation",()=>{
  const data=publicDirectory(registry);
  assert.equal(data.length,2);
  assert.equal(data.find(a=>a.id==="humkin").signIn,null);
  assert.equal(data.find(a=>a.id==="fileport").signIn,"https://fileport.abundent.org/api/static-id/login");
  const page=renderGate(registry);
  for(const forbidden of ["kbhqacsdvjsstzyplqij","/oauth/consent/","/api/static-id/callback","files.recovery","owner-report","2026-11-24","<script","<form","localStorage"])
    assert.ok(!page.includes(forbidden),forbidden);
  assert.match(page,/does not sign you in, grant access/);
  const future=structuredClone(registry);future.apps[1].lifecycle="candidate";
  assert.equal(publicDirectory(future).length,1);
});
test("malicious registry values cannot become public links or markup",()=>{
  const bad=structuredClone(registry);bad.apps[1].origin="https://bad.example";
  assert.throws(()=>renderGate(bad));
  bad.apps[1].origin="https://fileport.abundent.org";bad.apps[1].name="<script>";
  assert.throws(()=>renderGate(bad));
});
test("output contains only the dedicated static Gate files",async()=>{
  const dir=await mkdtemp(join(tmpdir(),"village-gate-"));
  try{await buildGate(dir);assert.deepEqual((await readdir(dir)).sort(),[".nojekyll","gate.css","index.html"]);
    assert.match(await readFile(join(dir,"index.html"),"utf8"),/Village Gate/);
  }finally{await rm(dir,{recursive:true,force:true});}
});
