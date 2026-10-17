// Service-side accounts with passkeys (WebAuthn). Three uses:
//
//  1. Human path: a request with no agent credentials is honored only with a
//     fresh passkey approval by the account holder, bound to that exact request.
//  2. Agent-bound access: the account holder approves, with a passkey, which
//     accountable agent (its PPID at this service) may use the account and for
//     what. Bearer tokens are no longer enough on their own, so a stolen token
//     is worthless to anyone else's agent.
//  3. Step-up: for sensitive actions even an authorized agent needs the account
//     holder's passkey approval of that specific action.
//
// Every approval is a WebAuthn ceremony whose challenge commits to what is
// being approved, made with user verification (biometric or device PIN).
import { randomId, digestOf } from '../lib/crypto.js';
import { creationOptions, requestOptions, verifyRegistration, verifyAssertion, bindingChallenge } from '../lib/webauthn.js';
import { detailMatches, describePermission } from '../lib/scope.js';
import { HttpError } from '../lib/http.js';

export function createAccounts({ rpId, origin, name }) {
  const accounts = new Map();
  const requests = new Map(); // approval request id -> { account, purpose, details, actor, challenge, status, expires }

  const mustAccount = (id) => {
    const a = accounts.get(id);
    if (!a) throw new HttpError(404, 'unknown_account', `no account ${id}`);
    return a;
  };

  const api = {
    rpId,
    origin,

    create(id, ownerName) {
      const account = { id, owner: ownerName, tokens: new Set(), passkeys: new Map(), delegations: [], pendingRegistration: null };
      accounts.set(id, account);
      return account;
    },

    get: (id) => accounts.get(id) ?? null,

    /** A legacy bearer API token for the account (what the attackers stole). */
    issueToken(id) {
      const token = `mh_${id.replace(/[^a-z0-9]/gi, '')}_${randomId('t', 8).slice(2)}`;
      mustAccount(id).tokens.add(token);
      return token;
    },

    byToken: (token) => [...accounts.values()].find((a) => a.tokens.has(token)) ?? null,

    passkeyRegistrationOptions(id) {
      const account = mustAccount(id);
      const { challenge } = bindingChallenge('register', { account: id });
      account.pendingRegistration = challenge;
      return { publicKey: creationOptions({ rpId, rpName: name, user: { id: `${id}:${randomId('u', 6)}`, name: `${account.owner} (${id})` }, challenge }) };
    },

    registerPasskey(id, credential) {
      const account = mustAccount(id);
      const challenge = account.pendingRegistration;
      account.pendingRegistration = null;
      let reg;
      try {
        reg = verifyRegistration({ response: credential, expectedChallenge: challenge, expectedOrigin: origin, rpId });
      } catch (err) {
        throw new HttpError(400, err.code ?? 'invalid_registration', err.message);
      }
      account.passkeys.set(reg.credentialId, { publicJwk: reg.publicJwk, alg: reg.alg, signCount: reg.signCount });
      return { credential_id: reg.credentialId };
    },

    /**
     * Open an approval request for the account holder.
     *   purpose 'delegate-agent': details { ppid, scope: [authorization_details], accountability }
     *   purpose 'approve-action': details { action, params_digest, actor }  (actor = 'human' or a PPID)
     */
    openRequest(accountId, purpose, details, ttlSeconds = 600) {
      mustAccount(accountId);
      const id = randomId('apr', 10);
      requests.set(id, { id, account: accountId, purpose, details, status: 'pending', expires: Date.now() + ttlSeconds * 1000 });
      return { request_id: id, account: accountId, purpose, details };
    },

    pendingFor: (accountId) => [...requests.values()].filter((r) => r.account === accountId && r.status === 'pending' && r.expires > Date.now()),

    /** WebAuthn request options whose challenge commits to the approval request. */
    approvalOptions(requestId) {
      const r = requests.get(requestId);
      if (!r || r.status !== 'pending' || r.expires < Date.now()) throw new HttpError(404, 'unknown_request', 'no pending approval request');
      const { challenge } = bindingChallenge(r.purpose, { request_id: r.id, account: r.account, ...r.details });
      r.challenge = challenge;
      return { request_id: r.id, purpose: r.purpose, details: r.details, publicKey: requestOptions({ rpId, challenge, credentials: [...mustAccount(r.account).passkeys.keys()] }) };
    },

    /** The account holder's passkey assertion; on success the approval takes effect. */
    approve(requestId, credential) {
      const r = requests.get(requestId);
      if (!r || r.status !== 'pending' || !r.challenge) throw new HttpError(404, 'unknown_request', 'no pending approval request with an issued challenge');
      const account = mustAccount(r.account);
      const stored = account.passkeys.get(credential?.id);
      if (!stored) throw new HttpError(403, 'unknown_passkey', "not one of this account's passkeys");
      let result;
      try {
        result = verifyAssertion({ response: credential, expectedChallenge: r.challenge, expectedOrigin: origin, rpId, credential: stored });
      } catch (err) {
        throw new HttpError(403, err.code ?? 'invalid_assertion', err.message);
      }
      stored.signCount = result.signCount;
      r.status = 'approved';
      r.challenge = null;
      r.evidence = { passkey: credential.id, user_verified: result.userVerified, approved_at: new Date().toISOString(), assertion: credential };
      if (r.purpose === 'delegate-agent') {
        account.delegations.push({ ppid: r.details.ppid, scope: r.details.scope, until: Date.now() + (r.details.valid_for_seconds ?? 86400) * 1000, evidence: r.evidence });
      }
      return { request_id: r.id, status: 'approved', user_verified: result.userVerified };
    },

    decline(requestId) {
      const r = requests.get(requestId);
      if (r && r.status === 'pending') r.status = 'declined';
      return { request_id: requestId, status: r?.status ?? 'unknown' };
    },

    /** Is this agent (PPID) authorized by the account holder for this action? */
    delegationFor(accountId, ppid, action) {
      const account = accounts.get(accountId);
      return account?.delegations.find((d) => d.ppid === ppid && d.until > Date.now() && d.scope.some((s) => detailMatches(s, action))) ?? null;
    },

    /** Use a one-time action approval: it must match the account, actor, action and exact parameters. */
    consumeActionApproval(requestId, { account, actor, action, params }) {
      const r = requests.get(requestId);
      if (!r || r.purpose !== 'approve-action' || r.status !== 'approved') return null;
      const ok = r.account === account && r.details.actor === actor && r.details.action === action && r.details.params_digest === digestOf(params);
      if (!ok) return null;
      r.status = 'used';
      return r.evidence;
    },
  };
  return api;
}

/** What the account holder is shown when an agent asks for access. */
export function describeAccessRequest(details) {
  const who = details.accountability;
  return `${who.type.replace('_', ' ')} verified ${who.assurance} by ${who.verifier}; chain length ${who.chain_length}; requests ${details.scope.map(describePermission).join('; ')}`;
}

