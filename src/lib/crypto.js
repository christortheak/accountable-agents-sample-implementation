// Cryptographic building blocks. Everything here is standard:
//   - JWS compact serialization with EdDSA/Ed25519 (RFC 7515, RFC 8037)
//   - JWK thumbprints (RFC 7638)
//   - JWE compact serialization, ECDH-ES + A256GCM over X25519 (RFC 7516, RFC 7518, RFC 8037)
//   - JSON Canonicalization Scheme for hashing (RFC 8785)
import crypto from 'node:crypto';

export const b64u = {
  encode: (data) => Buffer.from(typeof data === 'string' ? Buffer.from(data, 'utf8') : data).toString('base64url'),
  decode: (s) => Buffer.from(s, 'base64url'),
  encodeJson: (obj) => Buffer.from(JSON.stringify(obj), 'utf8').toString('base64url'),
  decodeJson: (s) => JSON.parse(Buffer.from(s, 'base64url').toString('utf8')),
};

export const sha256 = (data) => crypto.createHash('sha256').update(data).digest();
export const sha256b64u = (data) => b64u.encode(sha256(data));
export const hmac = (key, data) => crypto.createHmac('sha256', key).update(data).digest();
export const randomBytes = (n) => crypto.randomBytes(n);

// Crockford-style base32 (lowercase) for human-friendly identifiers.
const B32 = '0123456789abcdefghjkmnpqrstvwxyz';
export function base32(buf) {
  let bits = 0, value = 0, out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export const randomId = (prefix, bytes = 16) => `${prefix}_${base32(crypto.randomBytes(bytes))}`;

// RFC 8785 JSON Canonicalization Scheme. Used wherever a hash must be
// reproducible by another party (log leaves, commitments, digests).
// JCS serializes numbers and strings exactly as ECMAScript JSON.stringify does
// and sorts object members by UTF-16 code units, which is JavaScript's default
// string order; non-finite numbers are not representable.
export function canonicalize(value) {
  if (typeof value === 'number' && !Number.isFinite(value)) throw new Error('JCS cannot represent non-finite numbers');
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`).join(',')}}`;
}

export const digestOf = (value) => sha256b64u(canonicalize(value));

export const nowSeconds = () => Math.floor(Date.now() / 1000);

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

export function thumbprint(publicJwk) {
  // RFC 7638: required members only, lexicographic order.
  if (publicJwk.kty !== 'OKP') throw new Error(`unsupported kty ${publicJwk.kty}`);
  return sha256b64u(JSON.stringify({ crv: publicJwk.crv, kty: publicJwk.kty, x: publicJwk.x }));
}

export function publicOf(jwk) {
  const { d, ...pub } = jwk;
  return pub;
}

const keyObjectCache = new Map();
function privateKeyObject(jwk) {
  const id = `priv:${jwk.x}`;
  if (!keyObjectCache.has(id)) keyObjectCache.set(id, crypto.createPrivateKey({ key: jwk, format: 'jwk' }));
  return keyObjectCache.get(id);
}
function publicKeyObject(jwk) {
  const id = `pub:${jwk.crv}:${jwk.x}`;
  if (!keyObjectCache.has(id)) keyObjectCache.set(id, crypto.createPublicKey({ key: publicOf(jwk), format: 'jwk' }));
  return keyObjectCache.get(id);
}

/** A key holder: { privateJwk, publicJwk, kid }. kid is the RFC 7638 thumbprint. */
export function keyFromJwk(privateJwk) {
  const publicJwk = publicOf(privateJwk);
  const kid = thumbprint(publicJwk);
  return { privateJwk: { ...privateJwk, kid }, publicJwk: { ...publicJwk, kid }, kid };
}

export function generateSigningKey() {
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  return keyFromJwk(privateKey.export({ format: 'jwk' }));
}

export function generateEncryptionKey() {
  const { privateKey } = crypto.generateKeyPairSync('x25519');
  return keyFromJwk(privateKey.export({ format: 'jwk' }));
}

// ---------------------------------------------------------------------------
// JWS (compact, EdDSA)
// ---------------------------------------------------------------------------

/**
 * Sign a JSON payload. `key` is a key holder from generateSigningKey().
 * header.kid defaults to the key thumbprint; pass embedJwk to include the public key.
 */
export function signJws(payload, key, { typ, kid, embedJwk = false, extraHeader = {} } = {}) {
  const header = { alg: 'EdDSA', ...(typ ? { typ } : {}), kid: kid ?? key.kid, ...extraHeader };
  if (embedJwk) header.jwk = publicOf(key.publicJwk);
  const signingInput = `${b64u.encodeJson(header)}.${b64u.encodeJson(payload)}`;
  const signature = crypto.sign(null, Buffer.from(signingInput), privateKeyObject(key.privateJwk));
  return `${signingInput}.${b64u.encode(signature)}`;
}

export function decodeJws(jws) {
  if (typeof jws !== 'string') throw new JoseError('malformed', 'JWS must be a string');
  const parts = jws.split('.');
  if (parts.length !== 3) throw new JoseError('malformed', 'JWS must have three parts');
  try {
    return {
      header: b64u.decodeJson(parts[0]),
      payload: b64u.decodeJson(parts[1]),
      signingInput: `${parts[0]}.${parts[1]}`,
      signature: b64u.decode(parts[2]),
    };
  } catch {
    throw new JoseError('malformed', 'JWS header or payload is not valid JSON');
  }
}

/** Verify a JWS against a public JWK. Returns { header, payload } or throws JoseError. */
export function verifyJws(jws, publicJwk, { typ } = {}) {
  const decoded = decodeJws(jws);
  if (decoded.header.alg !== 'EdDSA') throw new JoseError('bad_alg', `unsupported alg ${decoded.header.alg}`);
  if (typ && decoded.header.typ !== typ) throw new JoseError('bad_typ', `expected typ ${typ}, got ${decoded.header.typ}`);
  const ok = crypto.verify(null, Buffer.from(decoded.signingInput), publicKeyObject(publicJwk), decoded.signature);
  if (!ok) throw new JoseError('bad_signature', 'signature verification failed');
  return { header: decoded.header, payload: decoded.payload };
}

/** Verify a JWS whose header carries its own public key (jwk). Returns the key's thumbprint too. */
export function verifySelfSignedJws(jws, opts) {
  const { header } = decodeJws(jws);
  if (!header.jwk) throw new JoseError('missing_key', 'JWS header has no jwk');
  const result = verifyJws(jws, header.jwk, opts);
  return { ...result, jwk: header.jwk, thumbprint: thumbprint(header.jwk) };
}

export class JoseError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

// ---------------------------------------------------------------------------
// JWE (compact, ECDH-ES direct key agreement + A256GCM, X25519)
// Used for the "sealed registration reference": only the registry can open it.
// ---------------------------------------------------------------------------

function concatKdf(sharedSecret, keyBits, algId) {
  // RFC 7518 §4.6.2 Concat KDF with SHA-256; one round suffices for 256-bit keys.
  const lenPrefixed = (buf) => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(buf.length);
    return Buffer.concat([len, buf]);
  };
  const keyLen = Buffer.alloc(4);
  keyLen.writeUInt32BE(keyBits);
  const otherInfo = Buffer.concat([
    lenPrefixed(Buffer.from(algId)),
    lenPrefixed(Buffer.alloc(0)), // PartyUInfo
    lenPrefixed(Buffer.alloc(0)), // PartyVInfo
    keyLen,
  ]);
  const counter = Buffer.from([0, 0, 0, 1]);
  return sha256(Buffer.concat([counter, sharedSecret, otherInfo])).subarray(0, keyBits / 8);
}

export function sealJwe(payload, recipientPublicJwk) {
  const ephemeral = crypto.generateKeyPairSync('x25519');
  const shared = crypto.diffieHellman({ privateKey: ephemeral.privateKey, publicKey: publicKeyObject(recipientPublicJwk) });
  const header = {
    alg: 'ECDH-ES',
    enc: 'A256GCM',
    kid: recipientPublicJwk.kid ?? thumbprint(recipientPublicJwk),
    epk: ephemeral.publicKey.export({ format: 'jwk' }),
  };
  const protectedHeader = b64u.encodeJson(header);
  const cek = concatKdf(shared, 256, 'A256GCM');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', cek, iv);
  cipher.setAAD(Buffer.from(protectedHeader, 'ascii'));
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(payload), 'utf8'), cipher.final()]);
  return `${protectedHeader}..${b64u.encode(iv)}.${b64u.encode(ciphertext)}.${b64u.encode(cipher.getAuthTag())}`;
}

export function openJwe(jwe, recipientPrivateJwk) {
  const parts = String(jwe).split('.');
  if (parts.length !== 5) throw new JoseError('malformed', 'JWE must have five parts');
  const [protectedHeader, encryptedKey, iv, ciphertext, tag] = parts;
  const header = b64u.decodeJson(protectedHeader);
  if (header.alg !== 'ECDH-ES' || header.enc !== 'A256GCM' || encryptedKey !== '') {
    throw new JoseError('bad_alg', 'unsupported JWE algorithm');
  }
  const shared = crypto.diffieHellman({
    privateKey: privateKeyObject(recipientPrivateJwk),
    publicKey: crypto.createPublicKey({ key: header.epk, format: 'jwk' }),
  });
  const cek = concatKdf(shared, 256, 'A256GCM');
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', cek, b64u.decode(iv));
    decipher.setAAD(Buffer.from(protectedHeader, 'ascii'));
    decipher.setAuthTag(b64u.decode(tag));
    const plaintext = Buffer.concat([decipher.update(b64u.decode(ciphertext)), decipher.final()]);
    return { header, payload: JSON.parse(plaintext.toString('utf8')) };
  } catch {
    throw new JoseError('bad_ciphertext', 'JWE could not be decrypted');
  }
}
