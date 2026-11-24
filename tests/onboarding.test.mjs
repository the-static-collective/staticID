import test from "node:test";
import assert from "node:assert/strict";
import { appPlan,buildPatch,applyOnboarding,probe,SECRET_NAMES,ISSUER } from "../src/onboarding.mjs";
const plan=appPlan({project:"demo",origin:"https://demo.abundent.org",name:"Demo"});
const credentials={clientId:"00000000-0000-4000-8000-000000000001",ownerSub:"00000000-0000-4000-8000-000000000002",clientSecret:"synthetic-test-secret-123456"};
const project=()=>({name:"demo",domains:["demo.abundent.org"],deployment_configs:{production:{wrangler_config_hash:"fixture-hash",env_vars:{RECOVERY_TOKEN:{type:"secret_text"},OTHER:{type:"plain_text",value:"keep"}}},preview:{env_vars:{UNCHANGED:{type:"plain_text",value:"preview"}}}}});
const account="a".repeat(32);
test("single app plan fixes identity provider and exact callback",()=>{
  assert.equal(plan.issuer,ISSUER);assert.equal(plan.callback,"https://demo.abundent.org/api/static-id/callback");
  for(const origin of ["http://demo.abundent.org","https://demo.abundent.org/","https://demo.abundent.org.evil.net","https://*.abundent.org","https://other.net"])
    assert.throws(()=>appPlan({project:"demo",name:"Demo",origin}));
  assert.throws(()=>appPlan({project:"../demo",origin:plan.origin,name:"Demo"}));
});
test("only new identity bindings, unique cookie key, no recovery or preview changes",()=>{
  const p=project(),a=buildPatch(plan,p,credentials),b=buildPatch(plan,p,credentials);
  const vars=a.deployment_configs.production.env_vars;
  assert.equal(Object.keys(vars).length,6);
  assert.deepEqual(Object.keys(a.deployment_configs),["production"]);
  assert.ok(!("RECOVERY_TOKEN" in vars));assert.ok(!("OTHER" in vars));
  assert.equal(vars.STATIC_ID_CLIENT_SECRET.type,"secret_text");
  assert.equal(vars.STATIC_ID_COOKIE_KEY.value.length,43);
  assert.notEqual(vars.STATIC_ID_COOKIE_KEY.value,b.deployment_configs.production.env_vars.STATIC_ID_COOKIE_KEY.value);
  p.deployment_configs.production.env_vars.STATIC_ID_CLIENT_ID={type:"secret_text"};
  assert.throws(()=>buildPatch(plan,p,credentials),/no overwrite/);
  assert.throws(()=>buildPatch(plan,{...project(),domains:["elsewhere.abundent.org"]},credentials),/no write/);
  const wrong=project();wrong.deployment_configs.production.env_vars.STATIC_ID_ISSUER={type:"plain_text",value:"https://wrong.example"};
  assert.throws(()=>buildPatch(plan,wrong,credentials),/differs/);
});
test("apply requires explicit confirmation, checks domain, patches once, verifies metadata and redacts receipt",async()=>{
  let calls=[],p=project();
  const fetcher=async(url,opts)=>{
    assert.equal(url,"https://api.cloudflare.com/client/v4/accounts/"+account+"/pages/projects/demo");
    assert.equal(opts.redirect,"manual");calls.push(opts.method);
    if(opts.method==="PATCH"){
      const patch=JSON.parse(opts.body).deployment_configs.production.env_vars;
      Object.assign(p.deployment_configs.production.env_vars,patch);
    }
    return Response.json({success:true,result:p});
  };
  await assert.rejects(()=>applyOnboarding(plan,account,"fixture-token",credentials,{confirmation:"yes",fetcher}),/confirmation/);
  assert.deepEqual(calls,[]);
  const receipt=await applyOnboarding(plan,account,"fixture-token",credentials,{confirmation:"ADD STATIC ID demo",fetcher});
  assert.deepEqual(calls,["GET","PATCH","GET"]);
  assert.equal(receipt.status,"BINDINGS_PRESENT_NOT_DEPLOYED_OR_LOGIN_VERIFIED");
  assert.ok(!JSON.stringify(receipt).includes(credentials.clientSecret));
  assert.ok(!JSON.stringify(receipt).includes(credentials.ownerSub));
  assert.ok(SECRET_NAMES.every(x=>receipt.bindingNames.includes(x)));
  await assert.rejects(()=>applyOnboarding(plan,account,"fixture-token",credentials,{confirmation:"ADD STATIC ID demo",fetcher}),/no overwrite/);
  assert.deepEqual(calls,["GET","PATCH","GET","GET"]);
});
test("anonymous probe never claims successful owner login",async()=>{
  const r=await probe(plan,async()=>Response.json({authenticated:false}));
  assert.equal(r.status,"ANONYMOUS_DENIED_LOGIN_NOT_TESTED");
  assert.equal((await probe(plan,async()=>Response.json({authenticated:true}))).status,"HOLD_UNEXPECTED_ANONYMOUS_RESPONSE");
  assert.equal((await probe(plan,async()=>Response.json({}, {status:503}))).status,"NOT_CONFIGURED");
});
