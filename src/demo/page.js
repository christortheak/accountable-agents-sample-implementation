// The browser demo page: real passkeys (WebAuthn) against the demo ModelHub.
export function demoPage() {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Passkeys and Accountable Agents</title>
<style>
:root { --bg:#f7f7f5; --fg:#1d1d1b; --muted:#63635e; --card:#fff; --line:#e3e3de; --accent:#2457d6; --ok:#1f7a4d; --bad:#b3261e; --warn:#9a6700; --chip:#eef2fc; }
@media (prefers-color-scheme: dark) { :root { --bg:#151514; --fg:#ececea; --muted:#a3a39d; --card:#1f1f1d; --line:#33332f; --accent:#8aa9ff; --ok:#5cc28f; --bad:#ff8a80; --warn:#e3b341; --chip:#232a3d; } }
* { box-sizing:border-box; }
body { margin:0; font:15px/1.5 -apple-system, system-ui, sans-serif; background:var(--bg); color:var(--fg); }
main { max-width:860px; margin:0 auto; padding:28px 16px 64px; }
h1 { font-size:22px; margin:0 0 6px; } h2 { font-size:16px; margin:0 0 6px; }
.lede { color:var(--muted); margin:0 0 20px; }
.card { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:16px; margin:14px 0; }
.step { display:flex; gap:12px; align-items:flex-start; }
.num { flex:0 0 28px; height:28px; border-radius:50%; background:var(--chip); color:var(--accent); display:grid; place-items:center; font-weight:700; }
.body { flex:1; min-width:0; }
p { margin:4px 0 10px; }
button { font:inherit; padding:8px 14px; border-radius:8px; border:1px solid var(--line); background:var(--card); color:var(--fg); cursor:pointer; margin:4px 6px 4px 0; }
button.primary { background:var(--accent); border-color:var(--accent); color:#fff; }
button:disabled { opacity:.45; cursor:not-allowed; }
.out { margin-top:8px; font-size:14px; }
.row { padding:8px 10px; border:1px solid var(--line); border-radius:8px; margin:6px 0; }
.ok { color:var(--ok); } .bad { color:var(--bad); } .warn { color:var(--warn); }
.tag { display:inline-block; font-size:12px; padding:1px 8px; border-radius:999px; background:var(--chip); margin-left:6px; }
code { font:12.5px ui-monospace, SFMono-Regular, Menlo, monospace; word-break:break-all; }
table { width:100%; border-collapse:collapse; font-size:14px; } th, td { text-align:left; padding:6px 8px; border-bottom:1px solid var(--line); vertical-align:top; } th { color:var(--muted); font-weight:600; font-size:12.5px; }
.wrap { overflow-x:auto; }
.note { color:var(--muted); font-size:13.5px; }
.err { color:var(--bad); font-size:14px; }
</style></head>
<body><main>
<h1>Passkeys and accountable agents</h1>
<p class="lede">You are the administrator of the <b>victim-org</b> account at ModelHub, a model-hosting platform. In July 2026, rogue agents used stolen API tokens to take private data from such a platform. Here the platform no longer honors bare tokens: people act with a passkey, and agents act only if the account holder has approved that specific accountable agent with a passkey.</p>
<div id="support" class="card err" hidden></div>

<div class="card step"><div class="num">1</div><div class="body">
<h2>Register a passkey for victim-org</h2>
<p>Your device creates a key pair and keeps the private key. ModelHub stores only the public key. You will be asked for Touch ID, Face ID or your device PIN.</p>
<button class="primary" id="register">Create passkey</button> <button id="reset">Start over</button>
<div class="out" id="registerOut"></div></div></div>

<div class="card step"><div class="num">2</div><div class="body">
<h2>Your organization's agent asks to use the account</h2>
<p>Victim Org's evaluation agent is registered under Victim Org with a federation registry. ModelHub shows you who stands behind it, without naming anyone, and you decide.</p>
<button id="ask">Agent requests access</button>
<div class="out" id="askOut"></div></div></div>

<div class="card step"><div class="num">3</div><div class="body">
<h2>Replay the attack</h2>
<p>Victim-org's old API token has been stolen. Three of another lab's agents, which are accountable but rogue, present it. So does an unidentified client. Your own agent reads data as before.</p>
<button class="primary" id="attack">Replay the attack</button>
<div class="out" id="attackOut"></div></div></div>

<div class="card step"><div class="num">4</div><div class="body">
<h2>Step-up: the agent wants to delete a dataset</h2>
<p>Deleting needs your passkey approval every time, for that exact dataset.</p>
<button id="del">Agent asks to delete victim-org/old-evals</button>
<div class="out" id="delOut"></div></div></div>

<p class="note">Your passkey never leaves your device; ModelHub sees only a signature over a challenge that commits to what you approved, made after your device verified you. The agents, registries and record keepers are the simulated federation from this repository.</p>

<script>
const b64u = {
  enc: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, ''),
  dec: (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), (c) => c.charCodeAt(0)),
};
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);
async function post(path, body = {}) {
  const res = await fetch(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const json = await res.json().catch(() => ({}));
  if (!res.ok && !json.decision) throw new Error(json.message || json.error || res.statusText);
  return json;
}
const decisionClass = (d) => (d === 'allow' ? 'ok' : d === 'deny' ? 'bad' : 'warn');
const verdict = (r) => '<b class="' + decisionClass(r.decision) + '">' + esc(String(r.decision).toUpperCase()) + '</b><span class="tag">' + esc(r.classification) + '</span>';

if (!window.PublicKeyCredential) {
  $('support').hidden = false;
  $('support').textContent = 'This browser does not support passkeys (WebAuthn). Open this page at http://localhost:4300 in a current Chrome, Safari, Edge or Firefox.';
} else if (location.hostname !== 'localhost') {
  $('support').hidden = false;
  $('support').innerHTML = 'Passkeys are bound to a domain. Open this page at <a href="http://localhost:4300">http://localhost:4300</a> (not 127.0.0.1).';
}

async function approveWithPasskey(requestId) {
  const opts = await post('/approval-requests/' + requestId + '/options');
  const pk = opts.publicKey;
  pk.challenge = b64u.dec(pk.challenge);
  pk.allowCredentials = pk.allowCredentials.map((c) => ({ ...c, id: b64u.dec(c.id) }));
  const a = await navigator.credentials.get({ publicKey: pk });
  const credential = {
    id: a.id, rawId: b64u.enc(a.rawId), type: a.type,
    response: { clientDataJSON: b64u.enc(a.response.clientDataJSON), authenticatorData: b64u.enc(a.response.authenticatorData), signature: b64u.enc(a.response.signature), userHandle: a.response.userHandle ? b64u.enc(a.response.userHandle) : null },
  };
  return post('/approval-requests/' + requestId + '/approve', { credential });
}

$('register').onclick = async () => {
  const out = $('registerOut');
  try {
    const { publicKey } = await post('/accounts/victim-org/passkeys/options');
    publicKey.challenge = b64u.dec(publicKey.challenge);
    publicKey.user.id = b64u.dec(publicKey.user.id);
    const cred = await navigator.credentials.create({ publicKey });
    const credential = {
      id: cred.id, rawId: b64u.enc(cred.rawId), type: cred.type, authenticatorAttachment: cred.authenticatorAttachment,
      response: { clientDataJSON: b64u.enc(cred.response.clientDataJSON), attestationObject: b64u.enc(cred.response.attestationObject) },
    };
    const res = await post('/accounts/victim-org/passkeys', { credential });
    out.innerHTML = '<span class="ok">✓ Passkey registered.</span> Credential <code>' + esc(res.credential_id.slice(0, 22)) + '…</code>';
  } catch (e) {
    out.innerHTML = '<span class="err">' + esc(e.message) + '</span>';
  }
};

$('reset').onclick = async () => {
  await post('/demo/reset');
  for (const id of ['registerOut', 'askOut', 'attackOut', 'delOut']) $(id).innerHTML = '';
  $('registerOut').innerHTML = '<span class="note">Account reset: no passkey, no authorized agents, a fresh (soon to be stolen) token.</span>';
};

$('ask').onclick = async () => {
  const out = $('askOut');
  try {
    const r = await post('/demo/agent/access');
    if (r.decision === 'allow') {
      out.innerHTML = '<div class="row">' + verdict(r) + ' The agent is already authorized: ' + esc(r.reasons.join('; ')) + '</div>';
      return;
    }
    const req = r.approval_request;
    if (!req) {
      out.innerHTML = '<div class="row">' + verdict(r) + ' ' + esc(r.reasons.join('; ')) + '</div>';
      return;
    }
    const d = req.details;
    const who = d.accountability;
    out.innerHTML = '<div class="row"><b>Access request</b><br>Agent <code>' + esc(d.ppid) + '</code><br>' +
      'Stands behind it: a <b>' + esc(String(who.type).replace('_', ' ')) + '</b>, verified at <b>' + esc(who.assurance) + '</b> by ' + esc(who.verifier) +
      ' (identity ' + (who.identity ? esc(Object.values(who.identity).join(', ')) : 'protected') + ')<br>Asks for: <code>' + esc(d.scope.map((s) => s.type + '.' + (s.actions ? s.actions.join('|') : '*')).join(', ')) + '</code></div>' +
      '<button class="primary" id="approveAccess">Approve with passkey</button><button id="declineAccess">Decline</button><div id="approveOut"></div>';
    $('approveAccess').onclick = async () => {
      try {
        await approveWithPasskey(req.request_id);
        const again = await post('/demo/agent/access');
        $('approveOut').innerHTML = '<div class="row"><span class="ok">✓ Approved with your passkey.</span> Agent retries: ' + verdict(again) + ' ' + esc(again.reasons.join('; ')) + '</div>';
      } catch (e) {
        $('approveOut').innerHTML = '<span class="err">' + esc(e.message) + '</span>';
      }
    };
    $('declineAccess').onclick = async () => {
      await post('/approval-requests/' + req.request_id + '/decline');
      $('approveOut').innerHTML = '<span class="note">Declined. The agent cannot use the account.</span>';
    };
  } catch (e) {
    out.innerHTML = '<span class="err">' + esc(e.message) + '</span>';
  }
};

$('attack').onclick = async () => {
  const out = $('attackOut');
  out.innerHTML = '<span class="note">Running…</span>';
  try {
    const r = await post('/demo/attack');
    out.innerHTML = '<div class="wrap"><table><thead><tr><th>Who</th><th>Presented</th><th>Outcome</th><th>Why</th></tr></thead><tbody>' +
      r.results.map((x) => '<tr><td>' + esc(x.actor) + '</td><td>' + esc(x.presented) + '</td><td>' + verdict(x) + '</td><td>' + esc(x.reasons.join('; ')) + '</td></tr>').join('') +
      '</tbody></table></div><div class="row">Rows of private data read by attackers: <b>' + r.rows_read_by_attackers + '</b>. ' +
      (r.frontier_notified ? 'The rogue agents\\' principal (Frontier Lab) was notified through its registry on the first attempt, about ' + esc(r.frontier_notified) + '.' : '') + '</div>' +
      '<p class="note">Without passkeys (the July 2026 situation), the stolen token alone would have opened the data to anyone holding it.</p>';
  } catch (e) {
    out.innerHTML = '<span class="err">' + esc(e.message) + '</span>';
  }
};

$('del').onclick = async () => {
  const out = $('delOut');
  try {
    const r = await post('/demo/agent/delete', { repo: 'victim-org/old-evals' });
    if (!r.approval_request) {
      out.innerHTML = '<div class="row">' + verdict(r) + ' ' + esc(r.reasons.join('; ')) + '</div>';
      return;
    }
    const req = r.approval_request;
    out.innerHTML = '<div class="row">' + verdict(r) + ' ' + esc(r.reasons.join('; ')) + '<br>Approve exactly: <code>' + esc(req.details.summary) + '</code></div>' +
      '<button class="primary" id="approveDel">Approve with passkey</button><div id="delApproveOut"></div>';
    $('approveDel').onclick = async () => {
      try {
        await approveWithPasskey(req.request_id);
        const done = await post('/demo/agent/delete', { repo: 'victim-org/old-evals', approval_ref: req.request_id });
        const reuse = await post('/demo/agent/delete', { repo: 'victim-org/held-out-evals', approval_ref: req.request_id });
        $('delApproveOut').innerHTML = '<div class="row">Agent retries with your approval: ' + verdict(done) + ' ' + esc(done.reasons.join('; ')) + '</div>' +
          '<div class="row">Agent tries to reuse it for <code>victim-org/held-out-evals</code>: ' + verdict(reuse) + ' ' + esc(reuse.reasons.join('; ')) + '</div>';
      } catch (e) {
        $('delApproveOut').innerHTML = '<span class="err">' + esc(e.message) + '</span>';
      }
    };
  } catch (e) {
    out.innerHTML = '<span class="err">' + esc(e.message) + '</span>';
  }
};
</script>
</main></body></html>`;
}
