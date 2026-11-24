#!/usr/bin/env node
import { readFile,mkdir,readdir,writeFile,lstat } from "node:fs/promises";
import { resolve,join } from "node:path";
import { createInterface } from "node:readline/promises";
import { stdin,stdout } from "node:process";
import { validateRegistry,validateEvidence,evidenceId,summarize,makeEvidence,observeAnonymous,CHECKS } from "../src/registry.mjs";

const root=resolve(".static-id/registry-receipts");
async function readSmall(path,max) {
  const info=await lstat(path);
  if(!info.isFile()||info.size>max)throw Error("Invalid local registry file");
  return JSON.parse(await readFile(path,"utf8"));
}
async function receipts(){
  let names;
  try{names=await readdir(root);}catch(e){if(e.code==="ENOENT")return [];throw e;}
  const files=names.filter(n=>/^[a-f0-9]{64}\.json$/.test(n));
  if(files.length>1000)throw Error("Archive local receipts before adding more");
  return Promise.all(files.map(async n=>{
    const e=validateEvidence(await readSmall(join(root,n),4096));
    if(n!==evidenceId(e)+".json")throw Error("Receipt content does not match its filename");
    return e;
  }));
}
async function save(e) {
  await mkdir(root,{recursive:true,mode:0o700});
  const file=join(root,evidenceId(e)+".json");
  try{await writeFile(file,JSON.stringify(e,null,2)+"\n",{flag:"wx",mode:0o600});}
  catch(err){if(err.code!=="EEXIST")throw err;
    if(evidenceId(await readSmall(file,4096))!==evidenceId(e))throw Error("Receipt conflict");
  }
  return file;
}
const out=x=>console.log(JSON.stringify(x,null,2));
async function main(){
  const [cmd="list",id,check,result,...rest]=process.argv.slice(2);
  if(rest.length)throw Error("Unexpected arguments");
  const registry=validateRegistry(await readSmall(new URL("../registry/apps.json",import.meta.url),131072));
  const history=await receipts();
  if(cmd==="list"&&!id){out(summarize(registry,history));return;}
  const app=registry.apps.find(a=>a.id===id);
  if(!app)throw Error("Use list, show APP, probe APP, or attest APP CHECK pass|fail|hold");
  if(cmd==="show"&&!check){out(summarize(registry,history).find(a=>a.id===id));return;}
  if(cmd==="probe"&&!check){
    const observation=await observeAnonymous(app);
    out({...observation,receipt:await save(observation.evidence)});return;
  }
  if(cmd==="attest"&&app.kind==="pages-client"&&app.lifecycle!=="retired"&&app.lifecycle!=="candidate"&&CHECKS.includes(check)&&["pass","fail","hold"].includes(result)){
    if(!stdin.isTTY)throw Error("Operator attestation requires interactive confirmation");
    const rl=createInterface({input:stdin,output:stdout});
    try{
      const answer=await rl.question("Record only your own observed "+check+" result for "+id+" ("+result+")? Type ATTEST: ");
      if(answer!=="ATTEST")throw Error("No attestation recorded");
      const e=makeEvidence(id,check,"operator-attestation",result);
      out({evidence:e,receipt:await save(e)});
    }finally{rl.close();}
    return;
  }
  throw Error("Unsupported registry command");
}
main().catch(e=>{console.error("REGISTRY HOLD: "+e.message);process.exitCode=1;});
