// HTTP Message Signatures (RFC 9421) with Ed25519, and Content-Digest (RFC 9530).
//
// Used for every authenticated call between parties (principal → registry,
// agent → record keeper, registry → registry, ...) and, with the agent's
// presentation key, for agent → relying-party requests (the Web Bot Auth
// pattern).
//
// keyid conventions in this profile:
//   "principal:<id>", "registration:<id>", "verifier:<entity>", "registry:<entity>"
//       a key the receiving service already knows
//   "jkt:<RFC 7638 thumbprint>"
//       a self-presented key, carried in the request body as `signer_jwk`
import crypto from 'node:crypto';
import { thumbprint, publicOf, randomId, nowSeconds } from './crypto.js';

export const DEFAULT_COMPONENTS = ['@method', '@target-uri', 'content-digest', 'content-type'];

export function contentDigest(body) {
  return `sha-256=:${crypto.createHash('sha256').update(body ?? '').digest('base64')}:`;
}

const sfString = (s) => `"${String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;

function serializeParams(components, params) {
  const list = `(${components.map(sfString).join(' ')})`;
  const order = ['created', 'expires', 'nonce', 'alg', 'keyid', 'tag'];
  return (
    list +
    order
      .filter((k) => params[k] !== undefined)
      .map((k) => `;${k}=${typeof params[k] === 'number' ? params[k] : sfString(params[k])}`)
      .join('')
  );
}

function componentValue(name, { method, url, headers }) {
  const u = new URL(url);
  switch (name) {
    case '@method':
      return method.toUpperCase();
    case '@target-uri':
      return u.href;
    case '@authority':
      return u.host.toLowerCase();
    case '@path':
      return u.pathname;
    case '@query':
      return u.search || '?';
    default: {
      if (name.startsWith('@')) throw new Error(`unsupported derived component ${name}`);
      const v = headers[name.toLowerCase()];
      if (v === undefined) throw new Error(`covered header ${name} is missing`);
      return String(Array.isArray(v) ? v.join(', ') : v).trim();
    }
  }
}

function signatureBase(components, serializedParams, request) {
  const lines = components.map((c) => `${sfString(c)}: ${componentValue(c, request)}`);
  lines.push(`"@signature-params": ${serializedParams}`);
  return lines.join('\n');
}

/**
 * Sign a request. Returns the headers to send (content-digest, signature-input,
 * signature) merged over the given headers.
 */
export function signRequest({ method, url, headers = {}, body = '', key, keyid, components = DEFAULT_COMPONENTS, tag, nonce, created, expires, label = 'sig1' }) {
  const lower = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
  if (components.includes('content-digest')) lower['content-digest'] = contentDigest(body);
  const params = { created: created ?? nowSeconds(), expires, nonce: nonce ?? randomId('n', 12), alg: 'ed25519', keyid, tag };
  const serialized = serializeParams(components, params);
  const base = signatureBase(components, serialized, { method, url, headers: lower });
  const sig = crypto.sign(null, Buffer.from(base, 'utf8'), crypto.createPrivateKey({ key: key.privateJwk, format: 'jwk' }));
  return { ...lower, 'signature-input': `${label}=${serialized}`, signature: `${label}=:${sig.toString('base64')}:` };
}

// --- parsing (the subset of RFC 8941 structured fields that signatures use) ---

function splitTopLevel(value, sep) {
  const out = [];
  let cur = '';
  let quote = false;
  let depth = 0;
  for (let i = 0; i < value.length; i++) {
    const ch = value[i];
    if (quote) {
      cur += ch;
      if (ch === '\\') cur += value[++i] ?? '';
      else if (ch === '"') quote = false;
      continue;
    }
    if (ch === '"') quote = true;
    if (ch === '(') depth++;
    if (ch === ')') depth--;
    if (ch === sep && depth === 0) {
      out.push(cur.trim());
      cur = '';
    } else cur += ch;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

const unquote = (s) => (s.startsWith('"') ? s.slice(1, -1).replace(/\\(.)/g, '$1') : /^-?\d+$/.test(s) ? Number(s) : s);

function parseDictionary(header) {
  const dict = {};
  for (const member of splitTopLevel(header ?? '', ',')) {
    const eq = member.indexOf('=');
    dict[member.slice(0, eq).trim()] = member.slice(eq + 1).trim();
  }
  return dict;
}

function parseSignatureInput(value) {
  const [list, ...paramParts] = splitTopLevel(value, ';');
  if (!list.startsWith('(') || !list.endsWith(')')) throw new Error('malformed signature input');
  const components = list.slice(1, -1).trim() ? splitTopLevel(list.slice(1, -1), ' ').map(unquote) : [];
  const params = {};
  for (const p of paramParts) {
    const eq = p.indexOf('=');
    params[p.slice(0, eq)] = unquote(p.slice(eq + 1));
  }
  return { components, params, serialized: value };
}

export class SignatureError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

/**
 * Verify a signed request.
 *   resolveKey(keyid, params) -> public JWK (may be async). For "jkt:" keyids the
 *   key is taken from body.signer_jwk and checked against the thumbprint.
 * Returns { keyid, jwk, thumbprint, params, components }.
 */
export async function verifyRequest({ method, url, headers, body, resolveKey, maxAgeSeconds = 120, required = ['@method', '@target-uri', 'content-digest'], tag, replay, label }) {
  const inputs = parseDictionary(headers['signature-input']);
  const sigs = parseDictionary(headers.signature);
  const chosen = label ?? Object.keys(inputs)[0];
  if (!chosen || !inputs[chosen] || !sigs[chosen]) throw new SignatureError('missing_signature', 'request is not signed (RFC 9421)');
  const { components, params, serialized } = parseSignatureInput(inputs[chosen]);
  for (const c of required) if (!components.includes(c)) throw new SignatureError('insufficient_coverage', `signature must cover ${c}`);
  if (tag && params.tag !== tag) throw new SignatureError('wrong_tag', `expected signature tag ${tag}`);
  if (params.alg && params.alg !== 'ed25519') throw new SignatureError('bad_alg', 'only ed25519 is accepted');
  const now = nowSeconds();
  if (typeof params.created !== 'number' || Math.abs(now - params.created) > maxAgeSeconds) throw new SignatureError('stale_signature', 'signature creation time outside allowed window');
  if (params.expires && params.expires < now) throw new SignatureError('expired_signature', 'signature expired');
  if (components.includes('content-digest') && headers['content-digest'] !== contentDigest(body)) {
    throw new SignatureError('digest_mismatch', 'Content-Digest does not match the body');
  }

  const keyid = params.keyid;
  let jwk;
  if (typeof keyid === 'string' && keyid.startsWith('jkt:')) {
    let parsed;
    try {
      parsed = typeof body === 'string' && body ? JSON.parse(body) : {};
    } catch {
      parsed = {};
    }
    jwk = parsed.signer_jwk;
    if (!jwk || thumbprint(jwk) !== keyid.slice(4)) throw new SignatureError('unknown_key', 'signer_jwk missing or does not match keyid');
  } else {
    jwk = await resolveKey(keyid, params);
  }
  if (!jwk) throw new SignatureError('unknown_key', `key ${keyid} not recognized`);

  const base = signatureBase(components, serialized, { method, url, headers });
  const sigB64 = sigs[chosen].replace(/^:|:$/g, '');
  const ok = crypto.verify(null, Buffer.from(base, 'utf8'), crypto.createPublicKey({ key: publicOf(jwk), format: 'jwk' }), Buffer.from(sigB64, 'base64'));
  if (!ok) throw new SignatureError('bad_signature', 'HTTP message signature verification failed');
  const verified = { keyid, jwk, thumbprint: thumbprint(jwk), params, components };
  if (replay) consumeNonce(replay, verified, maxAgeSeconds);
  return verified;
}

/**
 * Record a verified signature's nonce in a replay cache. The replay identity is
 * the verifying key's thumbprint, not the keyid spelling. Callers that check
 * more than the signature (e.g. key binding) call this only after every check
 * has passed, so a rejected request never consumes a nonce.
 */
export function consumeNonce(replay, { thumbprint: jkt, params }, maxAgeSeconds = 120) {
  if (!params.nonce) throw new SignatureError('missing_nonce', 'signature must carry a nonce');
  const id = `${jkt}|${params.nonce}`;
  const now = nowSeconds();
  if (replay.has(id)) throw new SignatureError('replayed_request', 'nonce already used');
  // Keep the entry until the signature's creation time leaves the accepted window.
  replay.set(id, Math.max(now, typeof params.created === 'number' ? params.created : now) + maxAgeSeconds);
  if (replay.size > 20000) for (const [k, exp] of replay) if (exp < now) replay.delete(k);
}
