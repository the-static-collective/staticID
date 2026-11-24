import test from "node:test";
import assert from "node:assert/strict";
import {
  randomSecret,b64url,unb64url,identityConfig,beginAuthorization,encryptJson,decryptJson,
  verifyJwt,ensureOwner,IdentityError
} from "../src/oidc.mjs";
import {
  SESSION_COOKIE,FLOW_COOKIE,requireStaticIdOwner,handleStaticIdRequest
} from "../src/cloudflare.mjs";

const owner = "17f57734-5420-4faf-ab5c-d2c7f95beac2";
const other = "0bdcd8ce-13f3-4417-8a5b-324ad69148c3";
const issuer="https://example.supabase.co/auth/v1";
const origin="https://fileport.abundent.org";
const env = () => ({
  STATIC_ID_ISSUER:issuer,STATIC_ID_APP_ORIGIN:origin,
  STATIC_ID_CLIENT_ID:"fileport-oauth-client",
  STATIC_ID_CLIENT_SECRET:"example-confidential-client-secret",
  STATIC_ID_OWNER_SUB:owner,STATIC_ID_COOKIE_KEY:randomSecret()
});
const req=(path,options={})=>new Request(origin+path,options);
function getCookie(response,name) {
  return response.headers.getSetCookie().map(s=>s.split(";")[0]).find(s=>s.startsWith(name+"="));
}
function asBytes(value) {return new TextEncoder().encode(JSON.stringify(value));}
async function fixtureSigner() {
  const pair=await crypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]);
  const publicJwk=await crypto.subtle.exportKey("jwk",pair.publicKey);
  publicJwk.kid="test-key";publicJwk.alg="ES256";publicJwk.use="sig";
  const signed=async claims=>{
    const head=b64url(asBytes({typ:"JWT",alg:"ES256",kid:"test-key"}));
    const body=b64url(asBytes(claims));
    const signature=new Uint8Array(await crypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},pair.privateKey,new TextEncoder().encode(head+"."+body)));
    return head+"."+body+"."+b64url(signature);
  };
  return {publicJwk,signed};
}
test("PKCE request is bound to one app, opaque state, nonce and verifier",async()=>{
  const config=identityConfig(env());
  const a=await beginAuthorization(config),b=await beginAuthorization(config);
  const url=new URL(a.url);
  assert.equal(url.origin,"https://example.supabase.co");
  assert.equal(url.pathname,"/auth/v1/oauth/authorize");
  assert.equal(url.searchParams.get("client_id"),"fileport-oauth-client");
  assert.equal(url.searchParams.get("redirect_uri"),origin+"/api/static-id/callback");
  assert.equal(url.searchParams.get("code_challenge_method"),"S256");
  assert.ok(url.searchParams.get("code_challenge").length>=43);
  assert.equal(url.searchParams.get("scope"),"openid email");
  assert.equal(a.state.length,43);assert.equal(a.nonce.length,43);assert.equal(a.verifier.length,43);
  assert.notEqual(a.state,b.state);
});
test("config refuses empty owner, wrong host, weak keys or plaintext http",()=>{
  const x=env();delete x.STATIC_ID_OWNER_SUB;
  assert.throws(()=>identityConfig(x),IdentityError);
  assert.throws(()=>identityConfig({...env(),STATIC_ID_APP_ORIGIN:"http://fileport.abundent.org"}),IdentityError);
  assert.throws(()=>identityConfig({...env(),STATIC_ID_COOKIE_KEY:"weak"}),IdentityError);
  assert.throws(()=>identityConfig({...env(),STATIC_ID_ISSUER:"https://example.supabase.co/not-auth"}),IdentityError);
});
test("AES-GCM cookies are purpose and app origin bound",async()=>{
  const c=identityConfig(env());
  const secret=await encryptJson({ok:true},c,"flow");
  assert.deepEqual(await decryptJson(secret,c,"flow"),{ok:true});
  await assert.rejects(()=>decryptJson(secret,c,"session"),IdentityError);
  await assert.rejects(()=>decryptJson(secret.slice(0,-2)+"aa",c,"flow"),IdentityError);
  await assert.rejects(()=>decryptJson(secret,{...c,origin:"https://different.abundent.org"},"flow"),IdentityError);
  assert.ok(unb64url(randomSecret()).length===32);
});
test("JWT signatures, audience, nonce, expiry and owner require independent proof",async()=>{
  const {publicJwk,signed}=await fixtureSigner();
  const now=Math.floor(Date.now()/1000);
  const claims={iss:issuer,aud:"fileport-oauth-client",nonce:"n-1",sub:owner,
    exp:now+300,iat:now-1,email_verified:true};
  const token=await signed(claims);
  const opts={issuer,audience:"fileport-oauth-client",nonce:"n-1",jwks:{keys:[publicJwk]}};
  assert.equal((await verifyJwt(token,opts)).sub,owner);
  assert.equal(ensureOwner(claims,identityConfig(env())).sub,owner);
  await assert.rejects(()=>verifyJwt(token,{...opts,nonce:"bad"}),IdentityError);
  await assert.rejects(()=>verifyJwt(token,{...opts,audience:"another-app"}),IdentityError);
  await assert.rejects(()=>verifyJwt(await signed({...claims,exp:now-3}),opts),IdentityError);
  await assert.rejects(()=>verifyJwt(await signed({...claims,sub:other}),{...opts,nonce:"wrong"}),IdentityError);
  assert.throws(()=>ensureOwner({...claims,sub:other},identityConfig(env())),IdentityError);
  assert.throws(()=>ensureOwner({...claims,email_verified:false},identityConfig(env())),IdentityError);
  const altered=token.split(".");altered[1]=b64url(asBytes({...claims,sub:other}));
  await assert.rejects(()=>verifyJwt(altered.join("."),opts),IdentityError);
  const none=b64url(asBytes({alg:"none",kid:"test-key"}))+"."+token.split(".").slice(1).join(".");
  await assert.rejects(()=>verifyJwt(none,opts),IdentityError);
});
test("full Cloudflare OAuth cycle is tied to the pinned owner and actual JWT",async()=>{
  const cfg=env(),config=identityConfig(cfg),{publicJwk,signed}=await fixtureSigner();
  const start=await handleStaticIdRequest(req("/api/static-id/login"),cfg);
  assert.equal(start.status,302);
  const flowCookie=getCookie(start,FLOW_COOKIE);assert.ok(flowCookie);
  const flow=await decryptJson(flowCookie.split("=")[1],config,"flow");
  const url=new URL(start.headers.get("Location"));
  assert.equal(url.searchParams.get("state"),flow.state);
  const now=Math.floor(Date.now()/1000);
  const idToken=await signed({iss:issuer,aud:config.clientId,sub:owner,email_verified:true,
    nonce:flow.nonce,exp:now+600,iat:now-2});
  const accessToken=await signed({iss:issuer,aud:"authenticated",sub:owner,
    client_id:config.clientId,exp:now+600,iat:now-2});
  const calls=[];
  const fetcher=async(url,options={})=>{
    calls.push({url,options});
    if(url.endsWith("/.well-known/jwks.json"))return new Response(JSON.stringify({keys:[publicJwk]}),{status:200});
    if(url.endsWith("/oauth/token")){
      assert.equal(options.method,"POST");
      assert.ok(options.headers.Authorization.startsWith("Basic "));
      assert.equal(options.body.get("code_verifier"),flow.verifier);
      return new Response(JSON.stringify({id_token:idToken,access_token:accessToken}),{status:200});
    }
    throw new Error("Unexpected request");
  };
  const wrong=await handleStaticIdRequest(req("/api/static-id/callback?code=code123456&state=wrong",{
    headers:{Cookie:flowCookie}
  }),cfg,fetcher);
  assert.equal(wrong.status,401);
  assert.equal(calls.length,0);
  const callback=await handleStaticIdRequest(req("/api/static-id/callback?code=code123456&state="+flow.state,{
    headers:{Cookie:flowCookie}
  }),cfg,fetcher);
  assert.equal(callback.status,303);
  assert.equal(callback.headers.get("Location"),origin+"/");
  assert.match(getCookie(callback,FLOW_COOKIE),/Max-Age=0/);
  const sessionCookie=getCookie(callback,SESSION_COOKIE);
  assert.ok(sessionCookie);
  assert.match(callback.headers.getSetCookie().join(" " ),/HttpOnly/);
  assert.match(callback.headers.getSetCookie().join(" " ),/SameSite=Lax/);
  assert.equal(await requireStaticIdOwner(req("/api/admin/files",{headers:{Cookie:sessionCookie}}),cfg,fetcher),true);
  assert.equal(await requireStaticIdOwner(req("/api/admin/files",{method:"POST",headers:{Cookie:sessionCookie,Origin:origin}}),cfg,fetcher),true);
  assert.equal(await requireStaticIdOwner(req("/api/admin/files",{method:"POST",headers:{Cookie:sessionCookie,Origin:"https://attacker.test"}}),cfg,fetcher),false);
  assert.equal(await requireStaticIdOwner(req("/api/admin/files",{headers:{Cookie:sessionCookie}}),
    {...cfg,STATIC_ID_OWNER_SUB:other},fetcher),false);
  const status=await handleStaticIdRequest(req("/api/static-id/status",{headers:{Cookie:sessionCookie}}),cfg,fetcher);
  assert.deepEqual(await status.json(),{authenticated:true});
  const logoutBad=await handleStaticIdRequest(req("/api/static-id/logout",{method:"POST",headers:{Cookie:sessionCookie,Origin:"https://attacker.test"}}),cfg,fetcher);
  assert.equal(logoutBad.status,403);
  const logout=await handleStaticIdRequest(req("/api/static-id/logout",{method:"POST",headers:{Cookie:sessionCookie,Origin:origin}}),cfg,fetcher);
  assert.equal(logout.status,200);
  assert.match(getCookie(logout,SESSION_COOKIE),/Max-Age=0/);
  assert.equal(await requireStaticIdOwner(req("/api/admin/files"),cfg,fetcher),false);
  assert.ok(calls.some(x=>x.url.endsWith("/oauth/token")));
});
test("unconfigured static ID never authorizes, but cannot affect other routes",async()=>{
  assert.equal(await requireStaticIdOwner(req("/api/admin/status"),{}),false);
  assert.equal(await handleStaticIdRequest(req("/api/admin/status"),{}),null);
  const result=await handleStaticIdRequest(req("/api/static-id/login"),{});
  assert.equal(result.status,503);
});
