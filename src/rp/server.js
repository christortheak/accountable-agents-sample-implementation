// A generic relying party: a merchant, API, agency portal or platform that
// verifies agent presentations, applies its policy, performs the action, keeps
// evidence, and writes its own account to the agent's activity log.
import { createApp, closeServer, HttpError } from '../lib/http.js';
import { generateSigningKey, signJws, randomId, digestOf, sha256b64u, publicOf } from '../lib/crypto.js';
import { postJson, postSigned } from '../lib/http.js';
import { HEADERS, RP_METADATA_PATH } from '../lib/protocol.js';
import { createVerifier } from './verifier.js';
import { pickTier, decide } from './policy.js';
import { createAccounts } from './accounts.js';
import { toRar, parseAction } from '../lib/scope.js';
import { CLASSIFICATION as C } from '../lib/protocol.js';
import { TYP as RK_TYP } from '../recordkeeper/recordkeeper.js';

/**
 * @param {object} opts
 * @param {string} opts.id         relying party identifier (the audience agents address)
 * @param {object} opts.rules      policy tiers per action (see policy.js)
 * @param {object} opts.handlers   action -> async (params, verification, rp) => result
 * @param {object} opts.requests   what the RP asks agents to disclose: { identity, attributes, provenance }
 * @param {Function} opts.onDecision  hook called after every decision (anomaly detection, SAR flags...)
 * @param {object} opts.accounts   { rpId, origin } to enable passkey accounts (accounts.js)
 * @param {Function} opts.onAccountMisuse  hook when an agent presents an account's token without the holder's authorization
 * @param {Function} opts.routes   (app, rp) => void, to add routes (used by the browser demo)
 * @param {string} opts.publicUrl  the URL agents use to reach this relying party, if it runs behind a proxy
 */
export async function startRelyingParty({ id, name, port = 0, host = '127.0.0.1', trust, rules, handlers = {}, requests = {}, onDecision, accounts: accountsConfig, onAccountMisuse, routes, publicUrl, key: givenKey }) {
  const key = givenKey ?? generateSigningKey();
  const verifier = createVerifier({ rpId: id, trust });
  const app = createApp(id);
  const accounts = accountsConfig ? createAccounts({ ...accountsConfig, name }) : null;
  const rp = { id, name, key, evidence: [], received: [], trust, accounts };

  app.get(RP_METADATA_PATH, () => ({
    id,
    name,
    jwks: { keys: [{ ...publicOf(key.publicJwk), use: 'sig' }] },
    accepted_registries: trust.registries.map((r) => r.id),
    requests,
    actions: Object.fromEntries(Object.entries(rules).map(([a, tiers]) => [a, tiers.map((t) => ({ label: t.label, require: { ...t.require } }))])),
    ...(accounts ? { webauthn: { rpId: accounts.rpId, origin: accounts.origin } } : {}),
  }));

  app.post('/actions/:action', async ({ params: route, body, rawBody, headers }) => {
    const action = route.action;
    const params = body ?? {};
    const tier = pickTier(rules, action, params);
    const v = await verifier.verify({
      headers, url: `${rp.url}/actions/${action}`, method: 'POST', rawBody, action, params, liveStatus: tier?.require.liveStatus !== false,
    });
    let d = decide(tier, v);
    let classification = v.classification;
    let gate = null;
    if (accounts && tier?.require.account && (d.decision === 'allow' || d.humanPath)) {
      gate = accountGate({ accounts, tier, action, params, v, headers });
      d = { ...d, decision: gate.decision, reasons: gate.reasons };
      if (gate.classification) classification = gate.classification;
    }
    const txn = randomId('txn', 10);
    let result = null;
    if (d.decision === 'allow' && handlers[action]) result = await handlers[action](params, v, rp);
    if (gate?.misuse && onAccountMisuse) await onAccountMisuse({ rp, action, params, verification: v, account: gate.account });

    // What the relying party keeps: the presented identifier, the chain it
    // resolved, the profile it relied on, signed status tokens and the outcome.
    const evidence = {
      txn, at: new Date().toISOString(), action, params, decision: d.decision, reasons: d.reasons, tier: d.tier,
      classification, ppid: v.ppid, ppid_mode: v.mode, registry: v.registry?.id ?? null, sealed_ref: v.sealedRef,
      root: v.root ? { type: v.root.type, trust_framework: v.root.verification?.trust_framework, assurance: v.root.verification?.assurance_level, verifier: v.root.verification?.verifier, identity: v.identity } : null,
      chain_length: v.chainLength, attributes: v.attributes.map((a) => ({ name: a.name, value: a.value })),
      authority_relied_on: v.authorization?.valid ? v.authorization.permissions : null,
      approval: v.approval, status_tokens: [...v.tokens, v.authorization?.statusToken].filter(Boolean),
      presentation_digest: headers[HEADERS.presentation] ? sha256b64u(headers[HEADERS.presentation]) : null,
      checks: v.checks, activity_receipt: null,
      account_gate: gate ? { account: gate.account, decision: gate.decision, passkey_approval: gate.evidence ? { passkey: gate.evidence.passkey, user_verified: gate.evidence.user_verified, approved_at: gate.evidence.approved_at } : null } : null,
    };
    evidence.activity_receipt = await writeActivity(rp, verifier, v, {
      txn, event: 'decision',
      details: { action, params_digest: digestOf(params), decision: d.decision, reasons: d.reasons, classification, presentation_digest: evidence.presentation_digest },
    });
    rp.evidence.push(evidence);
    rp.received.push({ txn, presentation: headers[HEADERS.presentation] ?? null, signatureInput: headers['signature-input'] ?? null, signature: headers.signature ?? null });
    if (onDecision) await onDecision({ rp, txn, action, params, verification: v, decision: d, result, evidence });
    return {
      __raw: true,
      status: d.decision === 'allow' ? 200 : 403,
      body: { txn, decision: d.decision, reasons: d.reasons, tier: d.tier, classification, result, ...(gate?.approvalRequest ? { approval_request: gate.approvalRequest } : {}) },
    };
  });

  if (accounts) {
    // Account holders' passkey ceremonies. (A production service would require
    // the holder's signed-in session for these; registration here is allowed
    // only while an account has no passkey yet.)
    app.post('/accounts/:account/passkeys/options', ({ params }) => {
      if (accounts.get(params.account)?.passkeys.size) throw new HttpError(403, 'already_registered', 'add further passkeys from a signed-in session');
      return accounts.passkeyRegistrationOptions(params.account);
    });
    app.post('/accounts/:account/passkeys', ({ params, body }) => accounts.registerPasskey(params.account, body?.credential));
    app.get('/accounts/:account/requests', ({ params }) => ({ requests: accounts.pendingFor(params.account).map(({ challenge, id, evidence, ...r }) => ({ request_id: id, ...r })) }));
    app.post('/accounts/:account/human-requests', ({ params, body }) =>
      accounts.openRequest(params.account, 'approve-action', { actor: 'human', action: body.action, params_digest: digestOf(body.params ?? {}), summary: summarize(body.action, body.params) }),
    );
    app.post('/approval-requests/:rid/options', ({ params }) => accounts.approvalOptions(params.rid));
    app.post('/approval-requests/:rid/approve', ({ params, body }) => accounts.approve(params.rid, body?.credential));
    app.post('/approval-requests/:rid/decline', ({ params }) => accounts.decline(params.rid));
  }

  if (routes) routes(app, rp);
  const server = await app.listen(port, host);
  // Agents sign the URL they call, so verification uses the public URL when there is one.
  rp.url = publicUrl ? publicUrl.replace(/\/$/, '') : `http://${host === '0.0.0.0' ? '127.0.0.1' : host}:${server.address().port}`;
  rp.server = server;
  rp.close = () => closeServer(server);

  /** Report an incident to the registry that issued a PPID; it relays to the principal. */
  rp.fileIncident = async ({ ppid, sealedRef, registry, summary, evidence = [] }) =>
    postSigned(`${registry.url}/v1/incidents`, { ppid, sealed_ref: sealedRef ?? undefined, reporter: id, summary, evidence }, key, { embedJwk: true });

  /** Read back the activity log for one of our counterparties (we wrote to it, so we may read it). */
  rp.readActivity = async (rk, subject) =>
    postSigned(`${rk.url}/v1/activity/query`, { subject }, key, { embedJwk: true });

  return rp;
}

async function writeActivity(rp, verifier, v, { txn, event, details }) {
  const pointer = v.records.find((r) => r.role === 'activity');
  if (!pointer || !v.ppid) return null;
  const rk = rp.trust.recordKeeper(pointer.rk);
  if (!rk) return null;
  const acc = await verifier.accreditation(v.registry.id, rk.id, 'activity');
  if (!acc.ok) return null;
  const entry = signJws(
    { subject: v.ppid, txn, writer_role: 'relying_party', writer: rp.id, event, details, at: new Date().toISOString() },
    rp.key,
    { typ: RK_TYP.activity, embedJwk: true },
  );
  try {
    return (await postJson(`${rk.url}/v1/activity`, { entry })).receipt;
  } catch {
    return null;
  }
}

const summarize = (action, params = {}) => {
  const { account_token: _t, ...rest } = params;
  return `${action} ${JSON.stringify(rest)}`;
};

/**
 * Passkey account gate (accounts.js). Decides whether this request may act on
 * the account it names, and opens an approval request for the holder when a
 * passkey approval is what is missing.
 */
function accountGate({ accounts, tier, action, params, v, headers }) {
  const account = params.account_token ? accounts.byToken(params.account_token) : accounts.get(params.account);
  if (!account) return { decision: 'deny', reasons: ['unknown account'] };
  if (params.account && params.account !== account.id) return { decision: 'deny', reasons: ['the token belongs to a different account'], account: account.id };

  if (v.classification === C.UNLABELED) {
    // Human path: no agent credentials, so the holder must approve this exact request with a passkey.
    const ev = headers[HEADERS.humanApproval] && accounts.consumeActionApproval(headers[HEADERS.humanApproval], { account: account.id, actor: 'human', action, params });
    if (ev) return { decision: 'allow', classification: C.HUMAN, reasons: ['approved by the account holder with a passkey (user verified), for this request'], account: account.id, evidence: ev };
    return {
      decision: 'deny', account: account.id,
      reasons: ['a bearer token alone is not accepted: the account holder must approve with their passkey, or act through an accountable agent they have authorized'],
    };
  }

  const delegation = accounts.delegationFor(account.id, v.ppid, action);
  if (!delegation) {
    if (params.account_token) {
      return { decision: 'deny', account: account.id, misuse: true, reasons: ["the account's token was presented by an agent the account holder never authorized"] };
    }
    const root = v.root ?? {};
    const approvalRequest = accounts.openRequest(account.id, 'delegate-agent', {
      ppid: v.ppid,
      // The holder authorizes the agent for this kind of resource; actions marked
      // humanApproval still need the holder's passkey every time.
      scope: [toRar({ action: `${parseAction(action).type}.*` })],
      accountability: { type: root.type, assurance: root.verification?.assurance_level, verifier: root.verification?.verifier, chain_length: v.chainLength, identity: v.identity },
      valid_for_seconds: 86400,
    });
    return { decision: 'step_up', account: account.id, approvalRequest, reasons: ['the account holder must first authorize this agent with their passkey (request sent)'] };
  }
  if (tier.require.humanApproval) {
    const ev = headers[HEADERS.approvalRef] && accounts.consumeActionApproval(headers[HEADERS.approvalRef], { account: account.id, actor: v.ppid, action, params });
    if (!ev) {
      const approvalRequest = accounts.openRequest(account.id, 'approve-action', { actor: v.ppid, action, params_digest: digestOf(params), summary: summarize(action, params) });
      return { decision: 'step_up', account: account.id, approvalRequest, reasons: [`${action} needs the account holder's passkey approval each time (request sent)`] };
    }
    return { decision: 'allow', account: account.id, evidence: ev, reasons: ['agent authorized by the account holder, and this action approved with their passkey'] };
  }
  return { decision: 'allow', account: account.id, evidence: delegation.evidence, reasons: ['agent authorized by the account holder with their passkey'] };
}
