#!/usr/bin/env python3
"""Build the password-protected index.html from the plain page.

The plain page is encrypted with AES-256-GCM using a key derived from the
password (PBKDF2-SHA256, 600,000 rounds). The published index.html only holds
the ciphertext plus a small unlock screen; the browser decrypts it locally once
the right password is entered. The password is never stored in this repo.

Usage:
    SITE_PASSWORD='...' python3 tools/encrypt.py path/to/plain.html index.html
    (or leave SITE_PASSWORD unset to be prompted)

Keep the plain page out of this public repository.
"""
import base64, getpass, json, os, sys, hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ITERATIONS = 600_000
TITLE = "1Cell.Ai Competitive Price Landscape"
DESC = "Interactive comparison of 1Cell.Ai oncology tests against competitor tests."
BASE = "https://onecellaimarketing.github.io/competitive-landscape/"

TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<title>__TITLE__</title>
<meta name="description" content="__DESC__">
<meta name="robots" content="noindex, nofollow">
<link rel="canonical" href="__BASE__">
<link rel="icon" type="image/png" href="favicon.png">
<link rel="apple-touch-icon" href="apple-touch-icon.png">
<meta property="og:type" content="website">
<meta property="og:site_name" content="1Cell.Ai">
<meta property="og:title" content="__TITLE__">
<meta property="og:description" content="__DESC__">
<meta property="og:url" content="__BASE__">
<meta property="og:image" content="__BASE__og-image.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:image:alt" content="1Cell.Ai — Ai-Powered Precision Oncology">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="__TITLE__">
<meta name="twitter:description" content="__DESC__">
<meta name="twitter:image" content="__BASE__og-image.png">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=Lexend:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{color-scheme:light;--bg:#F7F9FC;--surface:#FFFFFF;--ink:#16294A;--ink-2:#55657F;--ink-3:#8A97AC;--line:#E7ECF3;--navy:#1B365D;--gold:#D4A015;--err:#B42318;--err-bg:#FDECEA}
*,*::before,*::after{box-sizing:border-box}
html,body{height:100%}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 'Inter',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;-webkit-font-smoothing:antialiased;
  display:grid;place-items:center;padding:24px max(16px,env(safe-area-inset-right,0px)) 24px max(16px,env(safe-area-inset-left,0px))}
.card{width:100%;max-width:400px;background:var(--surface);border:1px solid var(--line);border-radius:16px;padding:32px 28px 28px;box-shadow:0 12px 40px rgba(22,41,74,.08);display:flex;flex-direction:column;gap:20px}
.card img{height:46px;width:auto;align-self:flex-start}
h1{font-family:'Lexend','Inter',system-ui,sans-serif;font-weight:500;font-size:1.35rem;margin:0;letter-spacing:-.01em}
p{margin:4px 0 0;color:var(--ink-2)}
form{display:flex;flex-direction:column;gap:12px}
label{font-size:.8rem;color:var(--ink-2);font-weight:500}
.field{display:flex;align-items:center;border:1px solid var(--line);border-radius:10px;background:var(--surface);transition:border-color .15s,box-shadow .15s}
.field:focus-within{border-color:var(--navy);box-shadow:0 0 0 3px rgba(27,54,93,.12)}
.field.bad{border-color:var(--err)}
input{flex:1;min-width:0;border:0;outline:0;background:transparent;padding:11px 12px;font:inherit;font-size:1rem;color:var(--ink)}
.eye{border:0;background:none;color:var(--ink-3);padding:0 12px;cursor:pointer;font:inherit;font-size:.78rem}
.eye:hover{color:var(--ink)}
button[type=submit]{border:0;border-radius:10px;background:var(--navy);color:#fff;padding:11px 14px;font:inherit;font-weight:600;cursor:pointer}
button[type=submit]:hover{background:#142a4a}
button[type=submit]:disabled{opacity:.6;cursor:progress}
button:focus-visible{outline:2px solid var(--navy);outline-offset:2px}
.msg{font-size:.82rem;color:var(--err);background:var(--err-bg);border-radius:8px;padding:8px 10px}
.foot{font-size:.74rem;color:var(--ink-3);border-top:1px solid var(--line);padding-top:14px}
[hidden]{display:none!important}
@keyframes shake{20%,60%{transform:translateX(-6px)}40%,80%{transform:translateX(6px)}}
.shake{animation:shake .35s}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
</style>
</head>
<body>
<main class="card" id="card" role="dialog" aria-labelledby="ttl" aria-describedby="sub">
  <img src="logo.png" alt="1Cell.Ai — Ai-Powered Precision Oncology">
  <div>
    <h1 id="ttl">Competitive Price Landscape</h1>
    <p id="sub">This page is for 1Cell.Ai internal use. Enter the password to continue.</p>
  </div>
  <form id="f" autocomplete="off">
    <label for="pw">Password</label>
    <div class="field" id="field">
      <input id="pw" type="password" autocomplete="current-password" required autofocus>
      <button type="button" class="eye" id="eye" aria-label="Show password">Show</button>
    </div>
    <div class="msg" id="msg" role="alert" hidden>Incorrect password. Try again.</div>
    <button type="submit" id="go">Unlock</button>
  </form>
  <div class="foot">Don't have the password? Contact the 1Cell.Ai marketing team.</div>
</main>
<script>
const P=__PAYLOAD__;
const b64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
async function keyFrom(pw){
  const base=await crypto.subtle.importKey('raw',new TextEncoder().encode(pw),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',salt:b64(P.salt),iterations:P.iter,hash:'SHA-256'},base,{name:'AES-GCM',length:256},true,['decrypt']);
}
async function open_(key){
  const buf=await crypto.subtle.decrypt({name:'AES-GCM',iv:b64(P.iv)},key,b64(P.data));
  return new TextDecoder().decode(buf);
}
function show(html){
  const go=()=>{document.open();document.write(html);document.close();};
  document.readyState==='complete'?go():window.addEventListener('load',go,{once:true});
}
const KEY='cpl-key';
(async()=>{
  try{const raw=sessionStorage.getItem(KEY);
    if(raw){const k=await crypto.subtle.importKey('raw',b64(raw),'AES-GCM',false,['decrypt']);show(await open_(k));return;}
  }catch(e){try{sessionStorage.removeItem(KEY)}catch(_){}}
})();
const f=document.getElementById('f'),pw=document.getElementById('pw'),msg=document.getElementById('msg'),go=document.getElementById('go'),field=document.getElementById('field'),card=document.getElementById('card');
document.getElementById('eye').addEventListener('click',e=>{const s=pw.type==='password';pw.type=s?'text':'password';e.target.textContent=s?'Hide':'Show';e.target.setAttribute('aria-label',s?'Hide password':'Show password');pw.focus();});
pw.addEventListener('input',()=>{msg.hidden=true;field.classList.remove('bad');});
f.addEventListener('submit',async e=>{
  e.preventDefault(); if(!pw.value) return;
  go.disabled=true; go.textContent='Unlocking…';
  try{
    const k=await keyFrom(pw.value); const html=await open_(k);
    try{const raw=new Uint8Array(await crypto.subtle.exportKey('raw',k));sessionStorage.setItem(KEY,btoa(String.fromCharCode(...raw)));}catch(_){}
    show(html);
  }catch(err){
    msg.hidden=false; field.classList.add('bad'); card.classList.remove('shake'); void card.offsetWidth; card.classList.add('shake');
    pw.select(); go.disabled=false; go.textContent='Unlock';
  }
});
</script>
</body>
</html>
"""

def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    src, out = sys.argv[1], sys.argv[2]
    pw = os.environ.get("SITE_PASSWORD") or getpass.getpass("Password: ")
    plain = open(src, "rb").read()
    salt, iv = os.urandom(16), os.urandom(12)
    key = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, ITERATIONS, 32)
    data = AESGCM(key).encrypt(iv, plain, None)
    e = lambda b: base64.b64encode(b).decode()
    payload = json.dumps({"iter": ITERATIONS, "salt": e(salt), "iv": e(iv), "data": e(data)})
    html = (TEMPLATE.replace("__TITLE__", TITLE).replace("__DESC__", DESC)
            .replace("__BASE__", BASE).replace("__PAYLOAD__", payload))
    open(out, "w").write(html)
    print(f"Wrote {out} ({len(html):,} bytes)")

if __name__ == "__main__":
    main()
