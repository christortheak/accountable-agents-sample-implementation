// Privacy analysis helpers for the simulator: what a relying party learned,
// and whether two relying parties could link what they received.
import { b64u } from '../lib/crypto.js';

// Not agent identifiers: per-request times, the relying party's own endpoint,
// and credential-type and status-list URIs shared by every credential of a kind.
const SKIP_KEYS = new Set(['iat', 'exp', 'typ', 'alg', 'vct', 'uri']);

/** All values in a presentation that could serve as a correlation handle. */
export function correlationHandles(received, publicValues) {
  const handles = new Map(); // value -> where it was found
  const add = (value, where) => {
    if (typeof value === 'string' && value.length >= 16 && !publicValues.has(value)) handles.set(value, where);
    if (typeof value === 'number' && value >= 1e9) handles.set(String(value), where); // long-lived timestamps
  };
  const walk = (node, where) => {
    if (Array.isArray(node)) node.forEach((n, i) => walk(n, `${where}[${i}]`));
    else if (node && typeof node === 'object') {
      for (const [k, v] of Object.entries(node)) if (!SKIP_KEYS.has(k)) walk(v, `${where}.${k}`);
    } else add(node, where);
  };
  const jws = (token, where) => {
    const [h, p, s] = token.split('.');
    walk(b64u.decodeJson(h), `${where}.header`);
    walk(b64u.decodeJson(p), `${where}.payload`);
    add(s, `${where}.signature`);
  };
  const sdJwt = (combined, where) => {
    const [jwt, ...rest] = combined.split('~').filter(Boolean);
    jws(jwt, where);
    for (const d of rest) {
      if (d.includes('.')) jws(d, `${where}.key_binding`);
      else walk(b64u.decodeJson(d), `${where}.disclosure`);
    }
  };
  for (const r of received) {
    if (!r.presentation) continue;
    const pres = b64u.decodeJson(r.presentation);
    sdJwt(pres.accountability, 'accountability');
    if (pres.authorization) sdJwt(pres.authorization, 'authorization');
    if (pres.approval) sdJwt(pres.approval, 'approval');
    // RFC 9421 parameters: keyid (the per-RP key's thumbprint) and nonce.
    for (const m of String(r.signatureInput ?? '').matchAll(/;(keyid|nonce)="([^"]+)"/g)) add(m[2], `signature-input.${m[1]}`);
    add(String(r.signature ?? '').replace(/^sig1=:|:$/g, ''), 'signature');
  }
  return handles;
}

/** Values two relying parties both received (excluding public constants). */
export function sharedHandles(receivedA, receivedB, publicValues) {
  const a = correlationHandles(receivedA, publicValues);
  const b = correlationHandles(receivedB, publicValues);
  return [...a.keys()].filter((k) => b.has(k)).map((k) => ({ value: k, whereA: a.get(k), whereB: b.get(k) }));
}

export function publicValuesOf(trust, extra = []) {
  const set = new Set([...extra, trust.trustAnchor.entity_id]);
  for (const e of [...trust.registries, ...trust.recordKeepers, ...trust.doc.verifiers, ...trust.doc.resolution_authorities]) {
    set.add(e.id);
    set.add(e.name);
    if (e.url) set.add(e.url);
    for (const k of e.jwks?.keys ?? []) set.add(k.kid); // issuers' public key ids
  }
  return set;
}

export { whatWasLearned } from '../rp/learned.js';
