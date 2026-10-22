// IETF SD-JWT (Selective Disclosure for JWTs), with Key Binding.
//
// The issuer replaces each selectively disclosable value with a salted digest.
// The holder later reveals only the disclosures it chooses and appends a Key
// Binding JWT (typ kb+jwt) signed with the key in the credential's `cnf`,
// binding the presentation to an audience, a nonce and the exact disclosures.
//
// Combined format: <issuer-signed JWT>~<disclosure>~...~<KB-JWT>
import { b64u, sha256b64u, randomBytes, signJws, verifyJws, decodeJws, nowSeconds, JoseError } from './crypto.js';

const SD_MARK = Symbol('selectively-disclosable');

/** Mark a value (object property value or array element) as selectively disclosable. */
export const sd = (value) => ({ [SD_MARK]: true, value });

const isMarked = (v) => v !== null && typeof v === 'object' && v[SD_MARK] === true;
const newSalt = () => b64u.encode(randomBytes(16));
const disclosureDigest = (encoded) => sha256b64u(Buffer.from(encoded, 'ascii'));

/**
 * Issue an SD-JWT. `payload` may contain values wrapped with sd().
 * Returns the combined serialization with ALL disclosures; the holder trims it with present().
 */
export function issueSdJwt(payload, key, { typ } = {}) {
  const disclosures = [];

  const encode = (node) => {
    if (Array.isArray(node)) {
      return node.map((el) => {
        if (isMarked(el)) {
          const encoded = b64u.encodeJson([newSalt(), encode(el.value)]);
          disclosures.push(encoded);
          return { '...': disclosureDigest(encoded) };
        }
        return encode(el);
      });
    }
    if (node !== null && typeof node === 'object') {
      const out = {};
      const digests = [];
      for (const [name, value] of Object.entries(node)) {
        if (isMarked(value)) {
          const encoded = b64u.encodeJson([newSalt(), name, encode(value.value)]);
          disclosures.push(encoded);
          digests.push(disclosureDigest(encoded));
        } else if (value !== undefined) {
          out[name] = encode(value);
        }
      }
      if (digests.length) out._sd = digests.sort();
      return out;
    }
    return node;
  };

  const body = { ...encode(payload), _sd_alg: 'sha-256' };
  const jwt = signJws(body, key, { typ });
  return [jwt, ...disclosures].join('~') + '~';
}

export const KB_JWT_TYP = 'kb+jwt';

export function splitSdJwt(combined) {
  const parts = String(combined).split('~');
  const jwt = parts[0];
  const last = parts.length > 1 ? parts[parts.length - 1] : '';
  const kbJwt = last.includes('.') ? last : null;
  const disclosures = parts.slice(1, kbJwt ? -1 : undefined).filter((p) => p.length > 0);
  return { jwt, disclosures, kbJwt, withoutKb: kbJwt ? String(combined).slice(0, -kbJwt.length) : String(combined) };
}

/** Holder: append a Key Binding JWT over the presentation (which must end in "~"). */
export function addKeyBinding(presented, holderKey, { aud, nonce, iat = nowSeconds() }) {
  const kb = signJws({ iat, aud, nonce, sd_hash: sdHash(presented) }, holderKey, { typ: KB_JWT_TYP });
  return presented + kb;
}

/** Decode a disclosure into { encoded, digest, salt, name?, value }. */
export function decodeDisclosure(encoded) {
  const arr = b64u.decodeJson(encoded);
  const digest = disclosureDigest(encoded);
  if (arr.length === 3) return { encoded, digest, salt: arr[0], name: arr[1], value: arr[2] };
  if (arr.length === 2) return { encoded, digest, salt: arr[0], value: arr[1] };
  throw new JoseError('malformed', 'disclosure must have 2 or 3 elements');
}

/**
 * Holder-side: keep only the disclosures for which keep(disclosure) is true.
 * A disclosure nested inside another is only useful if its parent is kept.
 */
export function present(combined, keep) {
  const { jwt, disclosures } = splitSdJwt(combined);
  const kept = disclosures.filter((d) => keep(decodeDisclosure(d)));
  return [jwt, ...kept].join('~') + '~';
}

/** The holder's view: the fully reconstructed payload (all disclosures applied). */
export function unpackSdJwt(combined) {
  const { jwt, disclosures } = splitSdJwt(combined);
  const { header, payload } = decodeJws(jwt);
  return { header, payload: reconstruct(payload, disclosures.map(decodeDisclosure)), disclosures: disclosures.map(decodeDisclosure) };
}

/**
 * Verifier-side: check the issuer signature and each disclosure; return the
 * payload with disclosed values substituted and undisclosed digests removed.
 * With keyBinding: { aud, nonce, maxAgeSeconds }, a valid KB-JWT signed by the
 * key in `cnf` is required.
 */
export function verifySdJwt(combined, issuerPublicJwk, { typ, keyBinding } = {}) {
  const { jwt, disclosures, kbJwt, withoutKb } = splitSdJwt(combined);
  const { header, payload } = verifyJws(jwt, issuerPublicJwk, { typ });
  if (payload._sd_alg && payload._sd_alg !== 'sha-256') throw new JoseError('bad_alg', 'unsupported _sd_alg');
  const decoded = disclosures.map(decodeDisclosure);
  const seen = new Set();
  for (const d of decoded) {
    if (seen.has(d.digest)) throw new JoseError('duplicate_disclosure', 'disclosure presented twice');
    seen.add(d.digest);
  }
  const used = new Set();
  const result = reconstruct(payload, decoded, used);
  if (used.size !== decoded.length) throw new JoseError('unreferenced_disclosure', 'a disclosure does not match any digest');
  let kb = null;
  if (keyBinding) {
    if (!kbJwt) throw new JoseError('missing_key_binding', 'presentation has no Key Binding JWT');
    if (!payload.cnf?.jwk) throw new JoseError('missing_cnf', 'credential has no cnf key to bind to');
    kb = verifyJws(kbJwt, payload.cnf.jwk, { typ: KB_JWT_TYP }).payload;
    if (kb.aud !== keyBinding.aud) throw new JoseError('kb_wrong_audience', 'key binding is for a different audience');
    if (keyBinding.nonce !== undefined && kb.nonce !== keyBinding.nonce) throw new JoseError('kb_wrong_nonce', 'key binding nonce does not match');
    if (!Number.isSafeInteger(kb.iat)) throw new JoseError('kb_bad_iat', 'key binding iat must be an integer NumericDate');
    if (Math.abs(nowSeconds() - kb.iat) > (keyBinding.maxAgeSeconds ?? 60)) throw new JoseError('kb_stale', 'key binding is stale');
    if (kb.sd_hash !== sdHash(withoutKb)) throw new JoseError('kb_sd_hash', 'key binding does not cover these disclosures');
  }
  return { header, payload: result, disclosedCount: decoded.length, kb };
}

function reconstruct(payload, decoded, used = new Set()) {
  const byDigest = new Map(decoded.map((d) => [d.digest, d]));
  const walk = (node) => {
    if (Array.isArray(node)) {
      const out = [];
      for (const el of node) {
        if (el && typeof el === 'object' && !Array.isArray(el) && Object.keys(el).length === 1 && '...' in el) {
          const d = byDigest.get(el['...']);
          if (d && d.name === undefined) {
            used.add(d.digest);
            out.push(walk(d.value));
          }
        } else {
          out.push(walk(el));
        }
      }
      return out;
    }
    if (node !== null && typeof node === 'object') {
      const out = {};
      for (const [name, value] of Object.entries(node)) {
        if (name === '_sd' || name === '_sd_alg') continue;
        out[name] = walk(value);
      }
      for (const digest of node._sd ?? []) {
        const d = byDigest.get(digest);
        if (d && d.name !== undefined) {
          if (d.name in out) throw new JoseError('claim_collision', `disclosed claim ${d.name} already present`);
          used.add(d.digest);
          out[d.name] = walk(d.value);
        }
      }
      return out;
    }
    return node;
  };
  return walk(payload);
}

/** Hash of a presented SD-JWT, bound into the holder's proof of possession. */
export const sdHash = (presented) => sha256b64u(Buffer.from(presented, 'ascii'));
