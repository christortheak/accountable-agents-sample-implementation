// Relying-party verification. Turns whatever an agent presented into:
//   - an accountability classification (disclosed / protected / unsupported /
//     unlabeled / revoked / lookup failed),
//   - verified, disclosed authority evaluated against the requested action,
//   - the evidence (status list tokens etc.) the relying party should keep.
import { verifyJws, decodeJws, thumbprint, nowSeconds, b64u } from '../lib/crypto.js';
import { verifySdJwt } from '../lib/sd-jwt.js';
import { verifyRequest, consumeNonce, SignatureError } from '../lib/httpsig.js';
import { evaluate } from '../lib/scope.js';
import { HEADERS, CLASSIFICATION as C } from '../lib/protocol.js';
import { SD_JWT_VC_TYP, vct, AGENT_SIGNATURE_TAG, AGENT_SIGNED_COMPONENTS } from '../lib/credentials.js';
import { verifyStatusListToken, statusAt, STATUS, STATUS_NAME } from '../lib/status-list.js';
import { trustMarkType, TRUST_MARK_TYP } from '../lib/openid-federation.js';
import { normalizeAttribute } from '../lib/ida.js';

const peek = (jwt) => decodeJws(String(jwt).split('~')[0]);
const KB_MAX_AGE_SECONDS = 60;

export function createVerifier({ rpId, trust }) {
  const replay = new Map();
  const accreditationCache = new Map();
  const statusListCache = new Map();
  const vctOf = (kind) => vct(trust.trustAnchor.entity_id, kind);

  /**
   * Is record keeper rkId accredited by registryId for a role? Asks the
   * registry's OpenID Federation Trust Mark endpoint, verifies the Trust Mark,
   * and checks the Trust Anchor lets that registry issue it. Cached for a minute.
   */
  async function accreditation(registryId, rkId, role) {
    const key = `${registryId}|${rkId}|${role}`;
    const hit = accreditationCache.get(key);
    if (hit && hit.until > Date.now()) return hit.value;
    const registry = trust.registry(registryId);
    const type = trustMarkType(trust.trustAnchor.entity_id, role);
    let value;
    try {
      const res = await fetch(`${registry.url}/federation/trust-mark?trust_mark_type=${encodeURIComponent(type)}&sub=${encodeURIComponent(rkId)}`, { signal: AbortSignal.timeout(5000) });
      if (!res.ok) throw new Error(`no trust mark (${res.status})`);
      const mark = await res.text();
      const { payload } = verifyJws(mark, trust.signingKey(registry, decodeJws(mark).header.kid), { typ: TRUST_MARK_TYP });
      const ok = payload.iss === registryId && payload.sub === rkId && payload.trust_mark_type === type && payload.exp > nowSeconds() && trust.trustMarkIssuers(type).includes(registryId);
      value = { ok, role, by: registryId, trustMark: mark };
    } catch (err) {
      value = { ok: false, role, by: registryId, lookupFailed: err.name === 'TypeError' || err.name === 'TimeoutError' };
    }
    accreditationCache.set(key, { value, until: Date.now() + 60000 });
    return value;
  }

  /**
   * Look up a credential's entry in its issuer's Token Status List. fresh=true
   * always refetches (a "live" check); otherwise a list is reused for its ttl.
   */
  async function statusOf(statusClaim, issuer, { fresh }) {
    const { idx, uri } = statusClaim.status_list;
    const cached = statusListCache.get(uri);
    let token;
    let payload;
    if (!fresh && cached && cached.until > Date.now()) ({ token, payload } = cached);
    else {
      const res = await fetch(trust.locate(uri), { signal: AbortSignal.timeout(5000) });
      if (!res.ok) throw new Error(`status list unavailable (${res.status})`);
      token = await res.text();
      payload = verifyStatusListToken(token, trust.signingKey(issuer, decodeJws(token).header.kid), { uri });
      statusListCache.set(uri, { token, payload, until: Date.now() + (payload.ttl ?? 10) * 1000 });
    }
    const code = statusAt(payload.status_list, idx);
    return { code, name: STATUS_NAME[code] ?? `0x${code.toString(16)}`, token, idx, uri };
  }

  async function verify({ headers, url, method, rawBody, action, params, liveStatus = true }) {
    const checks = [];
    const check = (name, ok, detail = '') => {
      checks.push({ name, ok, detail });
      return ok;
    };
    const out = {
      classification: null, checks, ppid: null, registry: null, mode: null, sealedRef: null,
      root: null, chainLength: null, identity: null, attributes: [], records: [],
      status: null, authorization: null, approval: null, authority: null, tokens: [], failure: null,
    };
    const fail = (classification, reason) => {
      out.classification = classification;
      out.failure = reason;
      return out;
    };

    // 0. Anything presented at all?
    const presentationHeader = headers[HEADERS.presentation];
    if (!presentationHeader) {
      if (headers[HEADERS.selfAsserted]) {
        check('registry credential present', false, `only a self-asserted claim: "${headers[HEADERS.selfAsserted]}"`);
        return fail(C.UNSUPPORTED, 'self-asserted claim with no registry credential');
      }
      return fail(C.UNLABELED, 'no accountability information presented');
    }
    let presentation;
    try {
      presentation = b64u.decodeJson(presentationHeader);
    } catch {
      return fail(C.UNSUPPORTED, 'malformed presentation');
    }

    // 1. Accountability credential (SD-JWT VC) from a federation registry.
    let att;
    let registryKey;
    try {
      const { header, payload } = peek(presentation.accountability);
      const registry = trust.registry(payload.iss);
      if (!check('issued by a federation registry', Boolean(registry), payload.iss)) {
        return fail(C.UNSUPPORTED, `credential issuer ${payload.iss} is not a member of the federation`);
      }
      out.registry = registry;
      registryKey = trust.signingKey(registry, header.kid);
      att = verifySdJwt(presentation.accountability, registryKey, { typ: SD_JWT_VC_TYP }).payload;
      if (att.vct !== vctOf('accountability')) throw new Error(`unexpected credential type ${att.vct}`);
      check('registry signature valid (SD-JWT VC)', true, att.vct);
    } catch (err) {
      check('registry signature valid (SD-JWT VC)', false, err.message);
      return fail(C.UNSUPPORTED, `credential could not be verified: ${err.message}`);
    }
    if (!check('issued for this relying party', att.aud === rpId, att.aud)) return fail(C.UNSUPPORTED, 'credential issued for someone else');
    if (!check('credential unexpired', att.exp > nowSeconds())) return fail(C.UNSUPPORTED, 'credential expired');

    // 2. The request is signed (RFC 9421) by the credential's cnf key, and the
    //    Key Binding JWT ties the presentation to this audience and nonce. The
    //    keyid only selects a key: the key that actually verified the signature
    //    must be the cnf key. The nonce is consumed only once everything holds.
    let sig;
    try {
      const cnfKeyid = `cnf:${thumbprint(att.cnf.jwk)}`;
      sig = await verifyRequest({
        method, url, headers, body: rawBody, tag: AGENT_SIGNATURE_TAG, required: AGENT_SIGNED_COMPONENTS, maxAgeSeconds: KB_MAX_AGE_SECONDS,
        resolveKey: (keyid) => (keyid === cnfKeyid ? att.cnf.jwk : null),
      });
      if (sig.keyid !== cnfKeyid || sig.thumbprint !== thumbprint(att.cnf.jwk)) throw new SignatureError('wrong_key', "request not signed by the credential's cnf key");
      verifySdJwt(presentation.accountability, registryKey, { typ: SD_JWT_VC_TYP, keyBinding: { aud: rpId, nonce: sig.params.nonce, maxAgeSeconds: KB_MAX_AGE_SECONDS } });
      consumeNonce(replay, sig, KB_MAX_AGE_SECONDS);
      check('request signed by the credential holder (RFC 9421 + key binding)', true, 'covers method, URL, body and presentation');
    } catch (err) {
      check('request signed by the credential holder (RFC 9421 + key binding)', false, err.message);
      return fail(C.UNSUPPORTED, `presenter does not hold the credential's key (${err.code ?? err.message})`);
    }

    out.ppid = att.sub;
    out.mode = att.ppid_mode;
    out.sealedRef = att.sealed_ref ?? null;
    out.root = att.accountability.root_principal;
    out.chainLength = att.accountability.chain_length;
    out.attributes = (att.accountability.attributes ?? []).map(normalizeAttribute);
    out.records = att.records ?? [];
    const disclosedIdentity = out.root.disclosed_identity ?? {};
    out.identity = Object.keys(disclosedIdentity).length ? disclosedIdentity : null;
    const rv = out.root.verification ?? {};
    check('chain ends in a verified legal person', out.root.verified === true, `${out.root.type}, ${rv.trust_framework} ${rv.assurance_level}, verified by ${rv.verifier}`);

    // 3. Status in the registry's Token Status List ("still valid?").
    let classification = out.identity?.legal_name ? C.DISCLOSED : C.PROTECTED;
    try {
      const st = await statusOf(att.status, out.registry, { fresh: liveStatus });
      const reason = { [STATUS.INVALID]: 'revoked or expired', [STATUS.SUSPENDED]: 'suspended', [STATUS.TRANSFERRED]: 'custody_transferred: this principal–agent relationship has ended' }[st.code] ?? null;
      out.status = { status: st.name, idx: st.idx, uri: st.uri, reason };
      out.tokens.push(st.token);
      if (!check(`status list entry ${liveStatus ? '(fetched now)' : '(cached list)'}`, st.code === STATUS.VALID, reason ?? 'VALID')) classification = C.REVOKED;
    } catch (err) {
      check('status list entry', false, `registry unreachable: ${err.message}`);
      classification = C.LOOKUP_FAILED;
    }
    out.classification = classification;

    // 4. Authorization credential from an accredited record keeper.
    if (presentation.authorization) out.authorization = await verifyAuthorization(presentation.authorization, att, sig.params.nonce, liveStatus, check);

    // 5. Approval by a designated human, if carried.
    if (presentation.approval) out.approval = await verifyApproval(presentation.approval, att, action, params, check);

    // 6. Does the disclosed authority cover this request?
    if (out.authorization?.valid) {
      out.authority = evaluate({ permissions: out.authorization.permissions, prohibitions: out.authorization.prohibitions }, { action, params }, { approval: out.approval ?? undefined });
      check('authority covers the requested action', out.authority.permitted, out.authority.permitted ? action : out.authority.reasons.join('; '));
    }
    return out;
  }

  async function verifyAuthorization(sdjwt, att, nonce, liveStatus, check) {
    const result = { valid: false, reason: null, issuer: null, permissions: [], prohibitions: [], status: null };
    const { header, payload: unverified } = peek(sdjwt);
    const rk = trust.recordKeeper(unverified.iss);
    if (!check('authorization from a federation record keeper', Boolean(rk), unverified.iss)) return { ...result, reason: 'unknown record keeper' };
    result.issuer = rk.id;
    const acc = await accreditation(att.iss, rk.id, 'authorization');
    if (!check(`record keeper holds ${att.iss}'s trust mark for authorization records`, acc.ok, acc.ok ? 'trust mark verified' : 'no valid trust mark')) {
      return { ...result, reason: 'record keeper not accredited for authorization records' };
    }
    let az;
    try {
      az = verifySdJwt(sdjwt, trust.signingKey(rk, header.kid), { typ: SD_JWT_VC_TYP, keyBinding: { aud: rpId, nonce, maxAgeSeconds: KB_MAX_AGE_SECONDS } }).payload;
      if (az.vct !== vctOf('authorization')) throw new Error(`unexpected credential type ${az.vct}`);
    } catch (err) {
      check('authorization valid (SD-JWT VC + key binding)', false, err.message);
      return { ...result, reason: `invalid authorization: ${err.message}` };
    }
    // RFC 8693 act: the acting party must be this agent; same holder key.
    const bound = az.act?.sub === att.sub && az.aud === rpId && thumbprint(az.cnf.jwk) === thumbprint(att.cnf.jwk);
    if (!check('authorization bound to this agent (act.sub = PPID, same cnf key)', bound)) return { ...result, reason: 'authorization not bound to this presentation' };
    if (!check('authorization unexpired', az.exp > nowSeconds())) return { ...result, reason: 'authorization expired' };
    result.permissions = az.authorization_details ?? [];
    result.prohibitions = az.prohibitions ?? [];
    let depth = 0;
    for (let a = az.act?.act; a; a = a.act) depth += 1;
    result.delegated = depth > 0;
    result.delegationDepth = depth;
    result.validUntil = az.valid_until;
    result.purpose = az.purpose;
    try {
      const st = await statusOf(az.status, rk, { fresh: liveStatus });
      result.status = st.name;
      result.statusToken = st.token;
      if (!check('grant still in force (status list)', st.code === STATUS.VALID, st.name)) return { ...result, reason: `grant is ${st.name}` };
    } catch (err) {
      check('grant still in force (status list)', false, err.message);
      return { ...result, reason: 'authorization status could not be checked' };
    }
    result.valid = true;
    return result;
  }

  async function verifyApproval(sdjwt, att, action, params, check) {
    const { header, payload: unverified } = peek(sdjwt);
    const rk = trust.recordKeeper(unverified.iss);
    if (!rk) return { valid: false, reason: 'approval from unknown record keeper' };
    const acc = await accreditation(att.iss, rk.id, 'authorization');
    if (!acc.ok) return { valid: false, reason: 'approval issuer not accredited' };
    let ap;
    try {
      ap = verifySdJwt(sdjwt, trust.signingKey(rk, header.kid), { typ: SD_JWT_VC_TYP }).payload;
      if (ap.vct !== vctOf('approval')) throw new Error('not an approval credential');
    } catch {
      return { valid: false, reason: 'invalid approval signature' };
    }
    const problems = [];
    if (ap.sub !== att.sub) problems.push('approval is for a different agent');
    if (ap.action !== action) problems.push(`approval covers ${ap.action}, not ${action}`);
    if (ap.subject_digest !== params.subject_digest) problems.push('approval covers a different document');
    if (ap.exp < nowSeconds()) problems.push('approval expired');
    if (ap.approval_method?.type !== 'webauthn' || ap.approval_method.user_verified !== true) problems.push('approval was not made with a user-verified passkey');
    try {
      const st = await statusOf(ap.status, rk, { fresh: true });
      if (st.code !== STATUS.VALID) problems.push(`approver's designation is revoked (status ${st.name})`);
    } catch {
      problems.push('approval status could not be checked');
    }
    const valid = problems.length === 0;
    check(`approval by ${ap.role}`, valid, valid ? `passkey, user verified; covers ${ap.action} of document ${ap.subject_digest.slice(0, 12)}…` : problems.join('; '));
    return { valid, role: ap.role, reason: problems.join('; '), jti: ap.jti };
  }

  return { verify, accreditation };
}
