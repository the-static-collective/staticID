// Server-only Passport adapter. query must be a trusted parameterized PostgreSQL driver.
import {randomSecret,b64url,unb64url} from "./oidc.mjs";
import {tokenDigest} from "./federation.mjs";
const valid=x=>typeof x==="string"&&/^[A-Za-z0-9_-]{43}$/.test(x);
const uuid=x=>typeof x==="string"&&/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(x);
const opaque=x=>typeof x==="string"&&x.length>0&&x.length<=255;
const scopesAllowed=["draft.read","draft.write"];
export function postgresAuthority({app,query,clock=Date.now}){
 if(!opaque(app)||typeof query!=="function")throw Error("INVALID_AUTHORITY");
 return Object.freeze({
 async issue(identity){
  if(!opaque(identity.issuer)||!opaque(identity.subject)||!Number.isFinite(identity.expiresAt)||identity.expiresAt<=clock())throw Error("IDENTITY_EXPIRED");
  const token=randomSecret(),hash=await tokenDigest(token),expiry=new Date(Math.min(identity.expiresAt,clock()+3600000)).toISOString();
  const q=await query("INSERT INTO passport.sessions(app,token_hash,issuer,subject,membership_revision,expires_at) SELECT app,$2,issuer,subject,revision,$5::timestamptz FROM passport.members WHERE app=$1 AND issuer=$3 AND subject=$4 AND active RETURNING expires_at",[app,hash,identity.issuer,identity.subject,expiry]);
  if(!q.rows.length)throw Error("MEMBERSHIP_REQUIRED");return {token,expiresAt:Date.parse(q.rows[0].expires_at)};
 },
 async authenticate(token,scope){
  if(!valid(token)||!opaque(scope))return null;
  const q=await query("SELECT m.principal,s.expires_at FROM passport.sessions s JOIN passport.members m USING(app,issuer,subject) WHERE s.app=$1 AND s.token_hash=$2 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND m.active AND m.revision=s.membership_revision AND $3=ANY(m.scopes)",[app,await tokenDigest(token),scope]);
  const r=q.rows[0];return r?{app,principal:r.principal,scope,expiresAt:Date.parse(r.expires_at)}:null;
 },
 async logout(token){if(valid(token))await query("UPDATE passport.sessions SET revoked_at=clock_timestamp() WHERE app=$1 AND token_hash=$2 AND revoked_at IS NULL",[app,await tokenDigest(token)])},
 // Administrative methods are trusted server operations; never exposed as anonymous routes.
 async invite(ownerToken,{issuer,subject,scopes}){
  if(!valid(ownerToken)||!opaque(issuer)||!opaque(subject)||!Array.isArray(scopes)||!scopes.length||new Set(scopes).size!==scopes.length||scopes.some(s=>!scopesAllowed.includes(s)))throw Error("INVITATION_INVALID");
  const code=randomSecret(),principal=crypto.randomUUID(),hash=await tokenDigest(code);
  const r=await query("INSERT INTO passport.invitations(app,code_hash,issuer,subject,principal,scopes,invited_by,expires_at) SELECT s.app,$3,$4,$5,$6::uuid,$7::text[],m.principal,clock_timestamp()+interval '24 hours' FROM passport.sessions s JOIN passport.members m USING(app,issuer,subject) WHERE s.app=$1 AND s.token_hash=$2 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND m.active AND m.revision=s.membership_revision AND 'membership.invite'=ANY(m.scopes) AND $7::text[] <@ m.scopes RETURNING principal",[app,await tokenDigest(ownerToken),hash,issuer,subject,principal,scopes]);
  if(!r.rows.length)throw Error("DELEGATION_DENIED");return {code,principal};
 },
 async accept(identity,code){
  if(!valid(code)||!opaque(identity.issuer)||!opaque(identity.subject)||!Number.isFinite(identity.expiresAt)||identity.expiresAt<=clock())throw Error("INVITATION_DENIED");
  const r=await query("SELECT passport.accept_invitation($1,$2,$3,$4) AS accepted",[app,await tokenDigest(code),identity.issuer,identity.subject]);
  if(r.rows[0]?.accepted!==true)throw Error("INVITATION_DENIED");
 },
 async revoke(ownerToken,issuer,subject){
  if(!valid(ownerToken)||!opaque(issuer)||!opaque(subject))throw Error("REVOCATION_DENIED");
  const r=await query("UPDATE passport.members target SET active=false,revision=target.revision+1 FROM passport.sessions s JOIN passport.members m USING(app,issuer,subject) WHERE s.app=$1 AND s.token_hash=$2 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND m.active AND m.revision=s.membership_revision AND 'membership.revoke'=ANY(m.scopes) AND target.app=s.app AND target.issuer=$3 AND target.subject=$4 AND target.active AND target.principal<>m.principal AND NOT ('membership.revoke'=ANY(target.scopes)) RETURNING target.principal",[app,await tokenDigest(ownerToken),issuer,subject]);
  return r.rows.length===1;
 }
 });
}
export async function postgresFlows({app,query,key}){
 if(!opaque(app)||typeof query!=="function"||!valid(key)||unb64url(key).length!==32)throw Error("FLOW_STORE_CONFIG");
 const aes=await crypto.subtle.importKey("raw",unb64url(key),"AES-GCM",false,["encrypt","decrypt"]),enc=new TextEncoder(),dec=new TextDecoder();
 return Object.freeze({
 async put(state,flow){
  const iv=crypto.getRandomValues(new Uint8Array(12)),hash=await tokenDigest(state);
  const cipher=new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv,additionalData:enc.encode(app+"|"+hash)},aes,enc.encode(JSON.stringify(flow))));
  const combined=new Uint8Array(iv.length+cipher.length);combined.set(iv);combined.set(cipher,iv.length);
  await query("INSERT INTO passport.flows(app,state_hash,browser_hash,sealed,expires_at) VALUES($1,$2,$3,$4,$5::timestamptz)",[app,hash,await tokenDigest(flow.browser),b64url(combined),new Date(flow.expires).toISOString()]);
 },
 async take(state,browser){
  if(!valid(state)||!valid(browser))return null;
  const hash=await tokenDigest(state),r=await query("UPDATE passport.flows SET consumed_at=clock_timestamp() WHERE app=$1 AND state_hash=$2 AND browser_hash=$3 AND consumed_at IS NULL AND expires_at>clock_timestamp() RETURNING sealed",[app,hash,await tokenDigest(browser)]);
  if(!r.rows.length)return null;
  const bytes=unb64url(r.rows[0].sealed);
  return JSON.parse(dec.decode(await crypto.subtle.decrypt({name:"AES-GCM",iv:bytes.slice(0,12),additionalData:enc.encode(app+"|"+hash)},aes,bytes.slice(12))));
 }
 });
}
