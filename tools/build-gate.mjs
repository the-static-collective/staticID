import { readFile,mkdir,writeFile,copyFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { validateRegistry } from "../src/registry.mjs";

const escapeHTML=s=>String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const labels={
  "identity.consent":"Identity & consent",
  "identity.owner-login":"Owner sign-in",
  "files.owner-read":"Browse files",
  "files.owner-write":"Manage files",
  "files.invited-share":"Invited sharing"
};
// Deliberately do not publish internal recovery capabilities, evidence receipts,
// issuer, callback configuration, client IDs, or any session information.
export function publicDirectory(raw){
  const registry=validateRegistry(raw);
  return registry.apps.filter(a=>a.kind==="identity-host"||a.lifecycle==="pilot").map(a=>({
    id:a.id,name:a.name,origin:a.origin,
    label:a.kind==="identity-host"?"Identity host":"Sign-in pilot",
    description:a.kind==="identity-host"?"Listen to HUMKIN and explore community radio.":"An independent workspace for your files.",
    capabilities:a.capabilities.filter(c=>Object.hasOwn(labels,c)).map(c=>labels[c]),
    launch:a.origin+"/",
    signIn:a.kind==="pages-client"?a.origin+"/api/static-id/login":null
  }));
}
export function renderGate(raw){
  const apps=publicDirectory(raw);
  const cards=apps.map(a=>'<article class="door"><div class="door-top"><span class="mark" aria-hidden="true">'+(a.id==="humkin"?"~":"◇")+'</span><span class="status">'+escapeHTML(a.label)+'</span></div><h2>'+escapeHTML(a.name)+'</h2><p>'+escapeHTML(a.description)+'</p><div class="tags">'+a.capabilities.map(c=>'<span>'+escapeHTML(c)+'</span>').join("")+'</div><div class="door-actions"><a class="action" href="'+escapeHTML(a.launch)+'">Open '+escapeHTML(a.name)+' <span aria-hidden="true">↗</span></a>'+(a.signIn?'<a class="secondary" href="'+escapeHTML(a.signIn)+'">Owner sign-in</a>':"")+'</div></article>').join("\n");
  return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'self\'; img-src \'self\'; base-uri \'none\'; form-action \'none\'"><meta name="description" content="A common entrance to independent Static Collective applications."><title>Village Gate · STATIC ID</title><link rel="stylesheet" href="./gate.css"></head><body><a href="#doors" class="skip">Skip to applications</a><header class="top"><a class="brand" href="./"><span class="logo" aria-hidden="true">✳</span> STATIC <b>ID</b></a><span class="eyebrow">STATIC COLLECTIVE / 004</span></header><main><section class="hero"><div class="intro"><p class="eyebrow">A COMMON ENTRANCE</p><h1>The Village<br><em>Gate.</em></h1><p class="lede">One identity. Many independent worlds. Find your workspaces, return to what you were building, and let each door keep its own keys.</p><a href="#doors" class="jump">Explore the village <span aria-hidden="true">↓</span></a></div><div class="seal" aria-hidden="true"><span class="orbit o1"></span><span class="orbit o2"></span><span class="orbit o3"></span><span class="arch"></span><span class="sun">✳</span><span class="ground"></span></div></section><section id="doors" aria-labelledby="doors-title"><div class="section-title"><h2 id="doors-title">The doors</h2><span>'+apps.length+' listed applications</span></div><div class="doors">'+cards+'</div></section><aside class="note"><h2>Independent by design.</h2><p>This public directory does not sign you in, grant access, or inspect your session. Each application verifies its own permissions. Status labels are registry declarations, not live uptime checks.</p></aside></main><footer><span>STATIC ID / VILLAGE GATE</span><a href="https://github.com/the-static-collective/staticID">Source &amp; documentation ↗</a></footer></body></html>';
}
export async function buildGate(dir=resolve("gate-dist")){
  const raw=JSON.parse(await readFile(new URL("../registry/apps.json",import.meta.url),"utf8"));
  await mkdir(dir,{recursive:true});
  await writeFile(resolve(dir,"index.html"),renderGate(raw));
  await copyFile(new URL("../gate/gate.css",import.meta.url),resolve(dir,"gate.css"));
  await writeFile(resolve(dir,".nojekyll"),"");
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  await buildGate();
  console.log("Built public Village Gate in gate-dist/");
}
