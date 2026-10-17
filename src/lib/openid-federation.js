// OpenID Federation 1.0, as used by this profile.
//
// The federation's governance body is the Trust Anchor. It publishes its
// Entity Configuration and issues Subordinate Statements about each member
// (registries, record keepers, identity verifiers, resolution authorities).
// Online members publish their own self-signed Entity Configurations.
// Registries issue Trust Marks to the record keepers they accredit.
//
// Entity types defined by this profile (metadata keys):
//   aaf_trust_anchor, aaf_registry, aaf_record_keeper,
//   aaf_identity_verifier, aaf_resolution_authority
import { signJws, verifyJws, decodeJws, nowSeconds, publicOf } from './crypto.js';

export const ENTITY_STATEMENT_TYP = 'entity-statement+jwt';
export const TRUST_MARK_TYP = 'trust-mark+jwt';
export const WELL_KNOWN = '/.well-known/openid-federation';
export const ENTITY_TYPES = ['aaf_registry', 'aaf_record_keeper', 'aaf_identity_verifier', 'aaf_resolution_authority'];

export const hostOf = (entityId) => new URL(entityId).host;

/** Trust Mark type a registry issues to a record keeper accredited for one role. */
export const trustMarkType = (trustAnchorId, role) => `${trustAnchorId}/trust-marks/record-keeper/${role}`;

export const jwksOf = (...keys) => ({ keys: keys.filter(Boolean).map((k) => ({ ...publicOf(k.publicJwk), use: k.publicJwk.crv === 'X25519' ? 'enc' : 'sig' })) });

/** A self-signed Entity Configuration (iss = sub). */
export function entityConfiguration({ entityId, key, jwks, metadata, authorityHints = [], trustMarks = [], extra = {}, lifetime = 86400 }) {
  const now = nowSeconds();
  return signJws(
    {
      iss: entityId, sub: entityId, iat: now, exp: now + lifetime, jwks, metadata,
      ...(authorityHints.length ? { authority_hints: authorityHints } : {}),
      ...(trustMarks.length ? { trust_marks: trustMarks } : {}),
      ...extra,
    },
    key,
    { typ: ENTITY_STATEMENT_TYP },
  );
}

/** A Subordinate Statement: the superior vouches for the subordinate's keys and metadata. */
export function subordinateStatement({ issuer, key, sub, jwks, metadata, lifetime = 86400 }) {
  const now = nowSeconds();
  return signJws({ iss: issuer, sub, iat: now, exp: now + lifetime, jwks, metadata }, key, { typ: ENTITY_STATEMENT_TYP });
}

export function issueTrustMark({ issuer, key, sub, type, lifetime = 365 * 86400 }) {
  const now = nowSeconds();
  return signJws({ iss: issuer, sub, trust_mark_type: type, iat: now, exp: now + lifetime }, key, { typ: TRUST_MARK_TYP });
}

/** Verify an entity statement against a JWKS; checks typ, iss, sub and expiry. */
export function verifyEntityStatement(jwt, jwks, { iss, sub } = {}) {
  const { header } = decodeJws(jwt);
  const key = jwks.keys.find((k) => k.kid === header.kid && k.use !== 'enc') ?? jwks.keys.find((k) => k.use !== 'enc');
  const { payload } = verifyJws(jwt, key, { typ: ENTITY_STATEMENT_TYP });
  if (iss && payload.iss !== iss) throw new Error(`statement issued by ${payload.iss}, expected ${iss}`);
  if (sub && payload.sub !== sub) throw new Error(`statement about ${payload.sub}, expected ${sub}`);
  if (payload.exp < nowSeconds()) throw new Error('entity statement expired');
  return payload;
}
