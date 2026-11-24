#!/usr/bin/env node
import { createInterface } from "node:readline/promises";
import { Writable } from "node:stream";
import { stdin, stdout } from "node:process";
import { appPlan,preflight,applyOnboarding,probe } from "../src/onboarding.mjs";

async function main(){
  const [cmd,project,origin,...words]=process.argv.slice(2);
  if(!["plan","probe","apply"].includes(cmd)||!project||!origin||!words.length){
    console.log("Usage: npm run onboard -- plan|probe|apply PROJECT https://APP.abundent.org App Name");
    process.exitCode=1;return;
  }
  const plan=appPlan({project,origin,name:words.join(" ")});
  if(cmd==="plan"){console.log(JSON.stringify(plan,null,2));return;}
  if(cmd==="probe"){console.log(JSON.stringify(await probe(plan),null,2));return;}
  if(!stdin.isTTY||!stdout.isTTY)throw Error("Interactive local terminal required");
  // No secrets in arguments, environment files, Git, console output, or receipt.
  let muted=false;
  const output=new Writable({write(chunk,encoding,cb){if(!muted)stdout.write(chunk,encoding);cb();}});
  output.isTTY=true;output.columns=stdout.columns;
  const rl=createInterface({input:stdin,output,terminal:true});
  const ask=async(prompt)=> (await rl.question(prompt)).trim();
  const hidden=async(prompt)=>{
    stdout.write(prompt);muted=true;
    try{return (await rl.question("")).trim();}finally{muted=false;stdout.write("\n");}
  };
  try{
    console.log(JSON.stringify(plan,null,2));
    console.log("Register this one exact confidential OAuth client in Supabase Auth > OAuth Apps. Do not change shared Auth settings.");
    console.log("Use a Cloudflare API token scoped to Pages Edit for the intended account. No Supabase admin key is needed.");
    const account=await ask("Cloudflare account ID: ");
    const token=await hidden("Cloudflare API token (hidden): ");
    if(!/^[A-Za-z0-9_-]{20,300}$/.test(token))throw Error("Invalid Cloudflare token format");
    await preflight(plan,account,token);
    console.log("Target project and domain verified. No existing STATIC ID secrets found.");
    const clientId=await hidden("New Supabase OAuth client ID (hidden): ");
    const clientSecret=await hidden("New Supabase OAuth client secret (hidden): ");
    const ownerSub=await hidden("Existing verified Supabase owner UID (hidden): ");
    const confirmation=await ask("Type ADD STATIC ID "+project+" to write production bindings: ");
    const receipt=await applyOnboarding(plan,account,token,{clientId,clientSecret,ownerSub},{confirmation});
    console.log(JSON.stringify(receipt,null,2));
    console.log("Redeploy the reviewed application adapter and test login, protected reads, logout and recovery.");
  }finally{rl.close();}
}
main().catch(e=>{console.error("ONBOARDING HOLD: "+e.message);process.exitCode=1;});
