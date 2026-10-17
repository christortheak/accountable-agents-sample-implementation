// WebAuthn (W3C Web Authentication Level 3): passkeys.
//
// Relying-party side: creation and request options, and verification of
// registration and authentication responses (clientDataJSON, authenticator
// data, COSE keys, signatures, user-presence and user-verification flags,
// signature counters).
//
// Plus a SoftwareAuthenticator that produces exactly the wire format a browser
// returns, so the simulator and tests can exercise the same verification code
// a real passkey goes through. It STANDS IN for a platform authenticator: it
// sets the "user verified" flag without any biometric, which is precisely why
// a production service relying on biometrics must require attestation (§16).
import crypto from 'node:crypto';
import { b64u, sha256, canonicalize, randomBytes } from './crypto.js';
import { encodeCbor, decodeCbor } from './cbor.js';

const FLAG = { UP: 0x01, UV: 0x04, BE: 0x08, BS: 0x10, AT: 0x40, ED: 0x80 };
export const COSE_ALG = { ES256: -7, EdDSA: -8, RS256: -257 };

/** A challenge that commits to what is being approved: SHA-256 over JCS of { purpose, details, nonce }. */
export function bindingChallenge(purpose, details) {
  const nonce = b64u.encode(randomBytes(16));
  return { challenge: b64u.encode(sha256(canonicalize({ purpose, details, nonce }))), nonce };
}

// ---------------------------------------------------------------------------
// COSE keys and authenticator data
// ---------------------------------------------------------------------------

export function coseToJwk(cose) {
  const kty = cose.get(1);
  const alg = cose.get(3);
  if (kty === 2 && cose.get(-1) === 1) return { alg, jwk: { kty: 'EC', crv: 'P-256', x: b64u.encode(cose.get(-2)), y: b64u.encode(cose.get(-3)) } };
  if (kty === 1 && cose.get(-1) === 6) return { alg, jwk: { kty: 'OKP', crv: 'Ed25519', x: b64u.encode(cose.get(-2)) } };
  if (kty === 3) return { alg, jwk: { kty: 'RSA', n: b64u.encode(cose.get(-1)), e: b64u.encode(cose.get(-2)) } };
  throw new Error('unsupported COSE key');
}

function jwkToCose(jwk) {
  return new Map([[1, 2], [3, COSE_ALG.ES256], [-1, 1], [-2, b64u.decode(jwk.x)], [-3, b64u.decode(jwk.y)]]);
}

export function parseAuthenticatorData(buf) {
  const flags = buf[32];
  const out = {
    rpIdHash: buf.subarray(0, 32),
    flags: { up: !!(flags & FLAG.UP), uv: !!(flags & FLAG.UV), be: !!(flags & FLAG.BE), bs: !!(flags & FLAG.BS), at: !!(flags & FLAG.AT), ed: !!(flags & FLAG.ED) },
    signCount: buf.readUInt32BE(33),
  };
  if (out.flags.at) {
    const aaguid = buf.subarray(37, 53);
    const len = buf.readUInt16BE(53);
    const credentialId = buf.subarray(55, 55 + len);
    const { value: cose } = decodeCbor(buf, 55 + len);
    out.attested = { aaguid: aaguid.toString('hex'), credentialId: b64u.encode(credentialId), cose };
  }
  return out;
}

function verifySignature(alg, jwk, data, signature) {
  const key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  if (alg === COSE_ALG.ES256) return crypto.verify('sha256', data, { key, dsaEncoding: 'der' }, signature);
  if (alg === COSE_ALG.EdDSA) return crypto.verify(null, data, key, signature);
  if (alg === COSE_ALG.RS256) return crypto.verify('sha256', data, key, signature);
  throw new Error(`unsupported algorithm ${alg}`);
}

export class WebAuthnError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

function checkClientData(clientDataB64, { type, challenge, origin }) {
  const raw = b64u.decode(clientDataB64);
  const cd = JSON.parse(raw.toString('utf8'));
  if (cd.type !== type) throw new WebAuthnError('wrong_type', `expected ${type}`);
  if (cd.challenge !== challenge) throw new WebAuthnError('wrong_challenge', 'response is not for this challenge');
  if (cd.origin !== origin) throw new WebAuthnError('wrong_origin', `origin ${cd.origin} is not ${origin}`);
  return raw;
}

// ---------------------------------------------------------------------------
// Relying party
// ---------------------------------------------------------------------------

export function creationOptions({ rpId, rpName, user, challenge }) {
  return {
    rp: { id: rpId, name: rpName },
    user: { id: b64u.encode(Buffer.from(user.id)), name: user.name, displayName: user.displayName ?? user.name },
    challenge,
    pubKeyCredParams: [{ type: 'public-key', alg: COSE_ALG.ES256 }, { type: 'public-key', alg: COSE_ALG.EdDSA }, { type: 'public-key', alg: COSE_ALG.RS256 }],
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
    attestation: 'none',
    timeout: 120000,
  };
}

export function requestOptions({ rpId, challenge, credentials }) {
  return { rpId, challenge, allowCredentials: credentials.map((id) => ({ type: 'public-key', id })), userVerification: 'required', timeout: 120000 };
}

/** Verify a registration (navigator.credentials.create) response. */
export function verifyRegistration({ response, expectedChallenge, expectedOrigin, rpId, requireUserVerification = true }) {
  checkClientData(response.response.clientDataJSON, { type: 'webauthn.create', challenge: expectedChallenge, origin: expectedOrigin });
  const { value: att } = decodeCbor(b64u.decode(response.response.attestationObject));
  const authData = parseAuthenticatorData(att.get('authData'));
  if (!authData.rpIdHash.equals(sha256(rpId))) throw new WebAuthnError('wrong_rp', 'credential is for a different relying party');
  if (!authData.flags.up) throw new WebAuthnError('no_user_presence', 'user presence flag not set');
  if (requireUserVerification && !authData.flags.uv) throw new WebAuthnError('no_user_verification', 'user verification (biometric or PIN) not performed');
  if (!authData.attested) throw new WebAuthnError('no_credential', 'no attested credential data');
  const { alg, jwk } = coseToJwk(authData.attested.cose);
  return {
    credentialId: authData.attested.credentialId,
    publicJwk: jwk,
    alg,
    signCount: authData.signCount,
    aaguid: authData.attested.aaguid,
    attestationFormat: att.get('fmt'),
    backupEligible: authData.flags.be,
  };
}

/** Verify an authentication (navigator.credentials.get) response against a stored credential. */
export function verifyAssertion({ response, expectedChallenge, expectedOrigin, rpId, credential, requireUserVerification = true }) {
  const clientData = checkClientData(response.response.clientDataJSON, { type: 'webauthn.get', challenge: expectedChallenge, origin: expectedOrigin });
  const authDataRaw = b64u.decode(response.response.authenticatorData);
  const authData = parseAuthenticatorData(authDataRaw);
  if (!authData.rpIdHash.equals(sha256(rpId))) throw new WebAuthnError('wrong_rp', 'assertion is for a different relying party');
  if (!authData.flags.up) throw new WebAuthnError('no_user_presence', 'user presence flag not set');
  if (requireUserVerification && !authData.flags.uv) throw new WebAuthnError('no_user_verification', 'user verification (biometric or PIN) not performed');
  const signed = Buffer.concat([authDataRaw, sha256(clientData)]);
  if (!verifySignature(credential.alg, credential.publicJwk, signed, b64u.decode(response.response.signature))) {
    throw new WebAuthnError('bad_signature', 'passkey signature does not verify');
  }
  if (credential.signCount && authData.signCount && authData.signCount <= credential.signCount) {
    throw new WebAuthnError('counter_regressed', 'signature counter did not increase (possible cloned authenticator)');
  }
  return { userVerified: authData.flags.uv, signCount: authData.signCount, backupState: authData.flags.bs };
}

// ---------------------------------------------------------------------------
// Software authenticator (simulation only)
// ---------------------------------------------------------------------------

export class SoftwareAuthenticator {
  constructor({ label = 'software authenticator (simulated)' } = {}) {
    this.label = label;
    this.credentials = new Map(); // credentialId -> { rpId, privateKey, publicJwk, userHandle, signCount }
  }

  /** Equivalent of navigator.credentials.create({ publicKey: options }) on the given origin. */
  create(options, origin, { userVerified = true } = {}) {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const publicJwk = publicKey.export({ format: 'jwk' });
    const credentialId = randomBytes(32);
    const id = b64u.encode(credentialId);
    this.credentials.set(id, { rpId: options.rp.id, privateKey, publicJwk, userHandle: options.user.id, signCount: 0 });
    const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge: options.challenge, origin, crossOrigin: false }));
    const idLen = Buffer.alloc(2);
    idLen.writeUInt16BE(credentialId.length);
    const authData = Buffer.concat([
      sha256(options.rp.id),
      Buffer.from([FLAG.UP | (userVerified ? FLAG.UV : 0) | FLAG.AT]),
      Buffer.alloc(4),
      Buffer.alloc(16), // AAGUID: all zeros for "none" attestation
      idLen,
      credentialId,
      encodeCbor(jwkToCose(publicJwk)),
    ]);
    return {
      id, rawId: id, type: 'public-key', authenticatorAttachment: 'platform',
      response: { clientDataJSON: b64u.encode(clientDataJSON), attestationObject: b64u.encode(encodeCbor({ fmt: 'none', attStmt: {}, authData })), transports: ['internal'] },
    };
  }

  /** Equivalent of navigator.credentials.get({ publicKey: options }) on the given origin. */
  get(options, origin, { userVerified = true } = {}) {
    const allowed = (options.allowCredentials ?? []).map((c) => c.id);
    const id = [...this.credentials.keys()].find((k) => this.credentials.get(k).rpId === options.rpId && (!allowed.length || allowed.includes(k)));
    if (!id) throw new WebAuthnError('no_credential', 'this authenticator holds no passkey for that relying party');
    const cred = this.credentials.get(id);
    cred.signCount += 1;
    const count = Buffer.alloc(4);
    count.writeUInt32BE(cred.signCount);
    const authData = Buffer.concat([sha256(options.rpId), Buffer.from([FLAG.UP | (userVerified ? FLAG.UV : 0)]), count]);
    const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: options.challenge, origin, crossOrigin: false }));
    const signature = crypto.sign('sha256', Buffer.concat([authData, sha256(clientDataJSON)]), { key: cred.privateKey, dsaEncoding: 'der' });
    return {
      id, rawId: id, type: 'public-key', authenticatorAttachment: 'platform',
      response: { clientDataJSON: b64u.encode(clientDataJSON), authenticatorData: b64u.encode(authData), signature: b64u.encode(signature), userHandle: cred.userHandle },
    };
  }
}
