// OpenID Connect for Identity Assurance 1.0: the `verified_claims` structure
// for KYC/KYB results and for attested principal attributes.
//
//   verified_claims: {
//     verification: { trust_framework, assurance_level, time, verification_process, evidence: [...] },
//     claims: { ...the claims that were verified }
//   }

/** verified_claims for a principal's identity, built by an identity verifier. */
export function identityVerifiedClaims({ principalType, identity, assurance, method = '', evidenceRef }) {
  const time = new Date().toISOString();
  const person = principalType === 'natural_person';
  const evidence = person
    ? [{
        type: 'document',
        check_details: [{ check_method: 'vcrypt', txn: evidenceRef }, ...(/liveness|biometric/i.test(method) ? [{ check_method: 'bvr', txn: evidenceRef }] : [])],
        time,
        document_details: { type: 'idcard' },
      }]
    : [
        { type: 'electronic_record', check_details: [{ check_method: 'data', txn: evidenceRef }], time, record: { type: 'company_register_extract', source: { name: 'company register (simulated)' } } },
        ...(/beneficial/i.test(method)
          ? [{ type: 'electronic_record', check_details: [{ check_method: 'data', txn: evidenceRef }], time, record: { type: 'beneficial_ownership_register', source: { name: 'beneficial ownership register (simulated)' } } }]
          : []),
      ];
  return {
    verification: {
      trust_framework: person ? 'nist_800_63A' : 'aaf_kyb',
      assurance_level: assurance,
      time,
      verification_process: evidenceRef,
      evidence,
    },
    claims: identity,
  };
}

/** verified_claims for one attribute (licensure, insurance, charter...), attested from a named source. */
export function attributeVerifiedClaims({ name, value, source }) {
  const time = new Date().toISOString();
  return {
    verification: {
      trust_framework: 'aaf_attributes',
      time,
      evidence: [{ type: 'electronic_record', check_details: [{ check_method: 'data' }], time, record: { type: name, source: { name: source } } }],
    },
    claims: { [name]: value },
  };
}

export const attributeName = (vc) => Object.keys(vc.claims)[0];
export const attributeSource = (vc) => vc.verification.evidence?.[0]?.record?.source?.name ?? null;

/** Plain-language summary of an IDA verification block. */
export function describeVerification(v) {
  const methods = (v.evidence ?? []).map((e) => (e.type === 'document' ? `document check (${e.check_details.map((c) => c.check_method).join(', ')})` : `${e.record?.type?.replace(/_/g, ' ')}`));
  return `${v.trust_framework}${v.assurance_level ? ` ${v.assurance_level}` : ''}: ${methods.join('; ')}`;
}

/** An attribute as a relying party sees it after disclosure. */
export function normalizeAttribute(a) {
  const name = attributeName(a);
  return { name, value: a.claims[name], source: attributeSource(a), verifier: a.verification.verifier ?? null, valid_until: a.valid_until ?? null };
}
