// STATIC ID 002. Local owner-only onboarding for Cloudflare Pages.
// No deployment, OAuth registration, provider-wide configuration, or credential logging.
import { identityConfig, randomSecret } from "./oidc.mjs";

export const ISSUER="https://kbhqacsdvjsstzyplqij.supabase.co/auth/v1";
export const CONSENT="https://humkin.abundent.org/oauth/consent/";
export const SECRET_NAMES=Object.freeze([
  "STATIC_ID_CLIENT_ID","STATIC_ID_CLIENT_SECRET","STATIC_ID_OWNER_SUB","STATIC_ID_COOKIE_KEY"
]);
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export function appPlan(input) {
  if(!input||typeof input!=="object"||
     Object.keys(input).some(k=>!["project","origin","name"].includes(k))) throw Error("Invalid app plan");
  const {project,origin,name}=input;
  if(typeof project!=="string"||!/^[a-z0-9][a-z0-9-]{0,62}$/.test(project)||
     typeof origin!=="string"||!/^https:\/\/[a-z0-9][a-z0-9-]{0,62}\.abundent\.org$/.test(origin)||
     typeof name!=="string"||!/^[a-zA-Z0-9][a-zA-Z0-9 ._-]{0,79}$/.test(name))
    throw Error("Use a Pages project slug, exact HTTPS abundent.org subdomain, and plain app name");
  return {schema:"static-id/onboarding/v1",project,origin,name,issuer:ISSUER,consent:CONSENT,
    callback:origin+"/api/static-id/callback",environment:"production",
    oauth:{client_type:"confidential",token_endpoint_auth_method:"client_secret_basic",grant_type:"authorization_code",pkce:"S256"},
    requiredSecrets:[...SECRET_NAMES],
    publicVariables:{STATIC_ID_ISSUER:ISSUER,STATIC_ID_APP_ORIGIN:origin},
    routes:["login","callback","status","logout"].map(x=>"/api/static-id/"+x)};
}
export function secretBindings(plan,{clientId,clientSecret,ownerSub},makeKey=randomSecret) {
  if(!uuid.test(clientId)||!uuid.test(ownerSub)||typeof clientSecret!=="string"||
      !/^[\x21-\x7e]{16,1024}$/.test(clientSecret)) throw Error("Invalid OAuth client or owner credential format");
  const values={STATIC_ID_CLIENT_ID:clientId,STATIC_ID_CLIENT_SECRET:clientSecret,
    STATIC_ID_OWNER_SUB:ownerSub,STATIC_ID_COOKIE_KEY:makeKey(32)};
  identityConfig({...plan.publicVariables,...values});
  return Object.fromEntries(Object.entries(values).map(([key,value])=>[key,{type:"secret_text",value}]));
}
function checkedProject(plan,p) {
  if(p?.name!==plan.project||!Array.isArray(p.domains)||!p.domains.includes(new URL(plan.origin).hostname))
    throw Error("Target project or custom domain does not match; no write");
  const config=p.deployment_configs?.production;
  if(!config||typeof config!=="object") throw Error("Production configuration not found");
  const vars=config.env_vars||{};
  if(SECRET_NAMES.some(k=>Object.hasOwn(vars,k))) throw Error("Existing STATIC ID binding found; no overwrite. Use a separately reviewed recovery procedure.");
  for(const [key,value] of Object.entries(plan.publicVariables)) {
    if(Object.hasOwn(vars,key)&&(vars[key]?.type!=="plain_text"||vars[key]?.value!==value))
      throw Error("Existing identity routing variable differs; no write");
  }
  return config;
}
export function buildPatch(plan,project,credentials,makeKey=randomSecret) {
  const c=checkedProject(plan,project);
  const bindings=secretBindings(plan,credentials,makeKey);
  // Preserve unrelated settings; no null/delete, preview mutations, or existing binding values.
  const vars={...bindings};
  for(const [key,value] of Object.entries(plan.publicVariables))
    if(!Object.hasOwn(c.env_vars||{},key)) vars[key]={type:"plain_text",value};
  const patch={env_vars:vars};
  if(typeof c.wrangler_config_hash==="string") patch.wrangler_config_hash=c.wrangler_config_hash;
  return {deployment_configs:{production:patch}};
}
export function cloudflareProjectUrl(account,project) {
  if(typeof account!=="string"||!/^[a-f0-9]{32}$/i.test(account)||typeof project!=="string"||!/^[a-z0-9][a-z0-9-]{0,62}$/.test(project))
    throw Error("Invalid Cloudflare account or project");
  return "https://api.cloudflare.com/client/v4/accounts/"+account+"/pages/projects/"+project;
}
export async function cfRequest(url,token,method="GET",body,fetcher=fetch) {
  let res;
  try{res=await fetcher(url,{method,redirect:"manual",signal:AbortSignal.timeout(20000),
      headers:{Authorization:"Bearer "+token,"Content-Type":"application/json",Accept:"application/json"},
      ...(body?{body:JSON.stringify(body)}:{})});}
  catch{throw Error("Cloudflare request unavailable; inspect dashboard before retrying");}
  if(!res.ok)throw Error("Cloudflare request refused (HTTP "+res.status+"); inspect dashboard before retrying");
  let response;
  try{response=await res.json();}catch{throw Error("Cloudflare response invalid; inspect dashboard");}
  if(response?.success!==true||!response.result)throw Error("Cloudflare did not confirm operation; inspect dashboard");
  return response.result;
}
export async function preflight(plan,account,token,fetcher=fetch) {
  const url=cloudflareProjectUrl(account,plan.project);
  const p=await cfRequest(url,token,"GET",undefined,fetcher);
  checkedProject(plan,p);
  return p;
}
export async function applyOnboarding(plan,account,token,credentials,{confirmation,fetcher=fetch,makeKey=randomSecret}={}) {
  if(confirmation!=="ADD STATIC ID "+plan.project)throw Error("Explicit confirmation required");
  const p=await preflight(plan,account,token,fetcher);
  const patch=buildPatch(plan,p,credentials,makeKey);
  const result=await cfRequest(cloudflareProjectUrl(account,plan.project),token,"PATCH",patch,fetcher);
  if(result?.name!==plan.project)throw Error("Write not independently confirmed; inspect dashboard");
  // Never serialize or return a provider response, which may contain sensitive bindings.
  const verify=await cfRequest(cloudflareProjectUrl(account,plan.project),token,"GET",undefined,fetcher);
  const vars=verify.deployment_configs?.production?.env_vars||{};
  if(verify.name!==plan.project||!verify.domains?.includes(new URL(plan.origin).hostname)||
      !SECRET_NAMES.every(k=>vars[k]?.type==="secret_text")||
      !Object.entries(plan.publicVariables).every(([k,v])=>vars[k]?.type==="plain_text"&&vars[k]?.value===v))
    throw Error("Write attempted; binding metadata not verified. Inspect dashboard; do not blindly retry.");
  return {schema:"static-id/onboarding-receipt/v1",project:plan.project,origin:plan.origin,
    environment:"production",status:"BINDINGS_PRESENT_NOT_DEPLOYED_OR_LOGIN_VERIFIED",
    bindingNames:SECRET_NAMES,publicVariables:Object.keys(plan.publicVariables),
    observedAt:new Date().toISOString()};
}
export async function probe(plan,fetcher=fetch) {
  // A public anonymous request is NOT a user login or owner authorization proof.
  const response=await fetcher(plan.origin+"/api/static-id/status",{redirect:"manual",signal:AbortSignal.timeout(15000),
    headers:{Accept:"application/json","Cache-Control":"no-cache"}});
  if(response.status===503)return {status:"NOT_CONFIGURED",authenticated:false};
  if(response.status!==200)return {status:"HOLD_UNEXPECTED_HTTP",http:response.status};
  let data;try{data=await response.json();}catch{return {status:"HOLD_INVALID_RESPONSE"};}
  if(data?.authenticated!==false)return {status:"HOLD_UNEXPECTED_ANONYMOUS_RESPONSE"};
  return {status:"ANONYMOUS_DENIED_LOGIN_NOT_TESTED",authenticated:false};
}
