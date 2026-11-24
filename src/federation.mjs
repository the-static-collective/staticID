// STATIC ID 005 — additive federation; no changes to legacy owner routes.
import {verifyJwt,randomSecret,b64url,sha256Bytes,sameString,unb64url} from "./oidc.mjs";
const googleIssuer="https://accounts.google.com", googleKeys="https://www.googleapis.com/oauth2/v3/certs";
const uuid=x=>typeof x==="string"&&/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(x);
const opaque=x=>typeof x==="string"&&/^[\x21-\x7e]{1,255}$/.test(x);
const fail=x=>{throw Error(x)};
export async function verifyGoogle(token,{clientId,nonce,fetcher=fetch,now=Date.now()}){
 if(!opaque(clientId)||!opaque(nonce)||typeof token!=="string"||token.length>16384)fail("INVALID_GOOGLE_TOKEN");
 const parts=token.split(".");if(parts.length!==3)fail("INVALID_GOOGLE_TOKEN");
 const decode=x=>JSON.parse(new TextDecoder().decode(unb64url(x)));
 const h=decode(parts[0]),c=decode(parts[1]),t=Math.floor(now/1000);
 if(h.alg!=="RS256"||!opaque(h.kid)||h.crit!==undefined||![googleIssuer,"accounts.google.com"].includes(c.iss)||c.aud!==clientId||c.azp!==undefined&&c.azp!==clientId||!opaque(c.sub)||!sameString(c.nonce,nonce)||!Number.isSafeInteger(c.exp)||c.exp<=t||!Number.isSafeInteger(c.iat)||c.iat>t+60||c.iat>c.exp||c.nbf!==undefined&&(!Number.isSafeInteger(c.nbf)||c.nbf>t+60))fail("GOOGLE_CLAIMS_DENIED");
 const res=await fetcher(googleKeys,{redirect:"error",signal:AbortSignal.timeout(10000)});if(!res.ok)fail("GOOGLE_KEYS_UNAVAILABLE");
 const raw=await res.text();if(raw.length>128000)fail("GOOGLE_KEYS_TOO_LARGE");
 const keys=JSON.parse(raw).keys?.filter(k=>k.kid===h.kid&&k.kty==="RSA"&&(!k.alg||k.alg==="RS256")&&(!k.use||k.use==="sig"));
 if(keys?.length!==1)fail("GOOGLE_KEY_DENIED");
 const key=await crypto.subtle.importKey("jwk",keys[0],{name:"RSASSA-PKCS1-v1_5",hash:"SHA-256"},false,["verify"]);
 if(!await crypto.subtle.verify("RSASSA-PKCS1-v1_5",key,unb64url(parts[2]),new TextEncoder().encode(parts[0]+"."+parts[1])))fail("GOOGLE_SIGNATURE_DENIED");
 return {issuer:googleIssuer,subject:c.sub,expiresAt:c.exp*1000};
}
export async function verifyStatic(token,{issuer,clientId,nonce,fetcher=fetch,now=Date.now()}){
 if(!opaque(nonce)||!opaque(clientId))fail("INVALID_STATIC_CONFIG");
 const c=await verifyJwt(token,{issuer,audience:clientId,nonce,fetcher,now});
 if(!uuid(c.sub)||c.email_verified!==true||c.azp!==undefined&&c.azp!==clientId)fail("STATIC_CLAIMS_DENIED");
 return {issuer,subject:c.sub,expiresAt:c.exp*1000};
}
export const tokenDigest=async token=>b64url(await sha256Bytes(token));
// Private trusted server configuration; never construct memberships from request claims.
// Memberships are exact application + issuer + subject + scope; same email does not link.
export function memoryAuthority({app,members,clock=Date.now}){
 if(!opaque(app)||!Array.isArray(members))fail("INVALID_MEMBERSHIP_CONFIG");
 const roster=new Map(),sessions=new Map();
 const index=(issuer,subject)=>JSON.stringify([issuer,subject]);
 for(const m of members){
  if(!opaque(m.issuer)||!opaque(m.subject)||!uuid(m.principal)||!Array.isArray(m.scopes)||m.scopes.some(x=>!opaque(x))||roster.has(index(m.issuer,m.subject)))fail("INVALID_MEMBER");
  roster.set(index(m.issuer,m.subject),{...structuredClone(m),active:true,revision:1});
 }
 return Object.freeze({
 async issue(identity){
  const k=index(identity.issuer,identity.subject),m=roster.get(k),now=clock();
  if(!m?.active||!Number.isFinite(identity.expiresAt)||identity.expiresAt<=now)fail("MEMBERSHIP_REQUIRED");
  const token=randomSecret(),hash=await tokenDigest(token);
  if(!m.active)fail("MEMBERSHIP_REQUIRED");
  const expiresAt=Math.min(identity.expiresAt,now+3600000);
  sessions.set(hash,{k,revision:m.revision,expiresAt});return {token,expiresAt};
 },
 async authenticate(token,scope){
  if(typeof token!=="string"||!/^[A-Za-z0-9_-]{43}$/.test(token))return null;
  const s=sessions.get(await tokenDigest(token)),m=s&&roster.get(s.k);
  if(!s||s.expiresAt<=clock()||!m?.active||m.revision!==s.revision||!m.scopes.includes(scope))return null;
  return {app,principal:m.principal,scope,expiresAt:s.expiresAt};
 },
 async logout(token){if(typeof token==="string"&&token.length===43)sessions.delete(await tokenDigest(token))},
 revoke(issuer,subject){const m=roster.get(index(issuer,subject));if(m){m.active=false;m.revision++}}
 });
}
// Login flow uses server-side one-use state; this memory implementation is a rehearsal,
// not suitable for multi-instance or restart-tolerant hosting.
export function createFederation({origin,providers,authority,flowStore=null,clock=Date.now,fetcher=fetch}){
 const u=new URL(origin);if(u.protocol!=="https:"||u.origin!==origin)fail("INVALID_ORIGIN");
 const configs=structuredClone(providers),flows=new Map();
 const cookie="__Host-staticid-federated",flowCookie="__Host-staticid-federated-flow";
 const cookieValue=(req,name)=>(req.headers.get("cookie")||"").split(";").map(x=>x.trim()).find(x=>x.startsWith(name+"="))?.slice(name.length+1)||"";
 const setCookie=(name,value,age)=>name+"="+value+"; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age="+Math.max(0,Math.floor(age));
 const response=(obj,status=200,headers={})=>new Response(JSON.stringify(obj),{status,headers:{"content-type":"application/json","cache-control":"private, no-store","referrer-policy":"no-referrer",...headers}});
 const callback=origin+"/api/federation/callback";
 const check=p=>{if(!p||!opaque(p.clientId)||!opaque(p.clientSecret))fail("PROVIDER_NOT_CONFIGURED");return p};
 const endpoints=(name,p)=>{
  if(name==="google")return {auth:"https://accounts.google.com/o/oauth2/v2/auth",token:"https://oauth2.googleapis.com/token"};
  if(name!=="static")fail("UNKNOWN_PROVIDER");
  const i=new URL(p.issuer);if(i.protocol!=="https:"||i.pathname!=="/auth/v1"||i.username||i.password||i.search||i.hash)fail("INVALID_ISSUER");
  return {auth:i.href+"/oauth/authorize",token:i.href+"/oauth/token"};
 };
 return Object.freeze({
 async require(request,scope){if(new URL(request.url).origin!==origin||!["GET","HEAD"].includes(request.method)&&request.headers.get("origin")!==origin)return null;return authority.authenticate(cookieValue(request,cookie),scope)},
 async handle(request){
  const url=new URL(request.url);if(!url.pathname.startsWith("/api/federation/"))return null;
  if(url.origin!==origin)return response({error:"ORIGIN_DENIED"},403);
  try{
   if(url.pathname==="/api/federation/login"&&request.method==="GET"){
    const name=url.searchParams.get("provider");if(!["static","google"].includes(name))fail("UNKNOWN_PROVIDER");
    const p=check(configs[name]),ep=endpoints(name,p),state=randomSecret(),nonce=randomSecret(),verifier=randomSecret(),browser=randomSecret();
    const flow={name,nonce,verifier,browser,expires:clock()+600000};
    if(flowStore)await flowStore.put(state,flow);else{for(const [k,v] of flows)if(v.expires<=clock())flows.delete(k);if(flows.size>=200)fail("FLOW_LIMIT");flows.set(state,flow)}
    const target=new URL(ep.auth);target.search=new URLSearchParams({client_id:p.clientId,redirect_uri:callback,response_type:"code",scope:"openid email",state,nonce,code_challenge:b64url(await sha256Bytes(verifier)),code_challenge_method:"S256"}).toString();
    return new Response(null,{status:302,headers:{location:target.href,"cache-control":"no-store","referrer-policy":"no-referrer","set-cookie":setCookie(flowCookie,browser,600)}});
   }
   if(url.pathname==="/api/federation/callback"&&request.method==="GET"){
    const state=url.searchParams.get("state"),code=url.searchParams.get("code"),browser=cookieValue(request,flowCookie);
    if(!opaque(code))fail("FLOW_DENIED");
    const f=flowStore?await flowStore.take(state,browser):flows.get(state);
    if(!f||f.expires<=clock()||!sameString(f.browser,cookieValue(request,flowCookie))||!opaque(code))fail("FLOW_DENIED");
    if(!flowStore)flows.delete(state);const p=check(configs[f.name]),ep=endpoints(f.name,p);
    const fields={grant_type:"authorization_code",code,redirect_uri:callback,code_verifier:f.verifier};
    const headers={"content-type":"application/x-www-form-urlencoded"};
    if(f.name==="static")headers.authorization="Basic "+btoa(p.clientId+":"+p.clientSecret);else Object.assign(fields,{client_id:p.clientId,client_secret:p.clientSecret});
    const res=await fetcher(ep.token,{method:"POST",headers,body:new URLSearchParams(fields).toString(),redirect:"error",signal:AbortSignal.timeout(15000)});
    if(!res.ok)fail("TOKEN_EXCHANGE_FAILED");const raw=await res.text();if(raw.length>32768)fail("TOKEN_RESPONSE_LIMIT");const token=JSON.parse(raw).id_token;
    const opts={...p,nonce:f.nonce,fetcher,now:clock()},identity=f.name==="google"?await verifyGoogle(token,opts):await verifyStatic(token,opts);
    const s=await authority.issue(identity);
    const out=new Response(null,{status:303,headers:{location:origin+"/","cache-control":"no-store","referrer-policy":"no-referrer"}});
    out.headers.append("set-cookie",setCookie(cookie,s.token,(s.expiresAt-clock())/1000));out.headers.append("set-cookie",setCookie(flowCookie,"",0));return out;
   }
   if(url.pathname==="/api/federation/logout"&&request.method==="POST"){
    if(request.headers.get("origin")!==origin)return response({error:"ORIGIN_DENIED"},403);
    await authority.logout(cookieValue(request,cookie));return response({ok:true},200,{"set-cookie":setCookie(cookie,"",0)});
   }
   return response({error:"NOT_FOUND"},404);
  }catch{return response({error:"AUTHENTICATION_HELD"},401)}
 }});
}
