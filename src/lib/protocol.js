// Wire-level constants of the agent-to-counterparty presentation protocol.
export const HEADERS = {
  presentation: 'aaf-presentation', // base64url JSON: { v, accountability, authorization?, approval? } (SD-JWT VCs + KB-JWTs)
  // The request itself carries RFC 9421 Signature-Input / Signature and RFC 9530 Content-Digest.
  selfAsserted: 'aaf-claim', // an unverifiable, self-asserted claim (for contrast)
  humanApproval: 'aaf-human-approval', // id of a passkey-approved request (human path)
  approvalRef: 'aaf-approval-ref', // id of a passkey-approved action (agent step-up)
};
export const COUNTERPARTY_METADATA_PATH = '/.well-known/aaf-counterparty';

/**
 * Accountability classifications a counterparty can reach. The paper's
 * conclusion asks a pilot to tell these cases apart; a failed lookup or an
 * unlabeled client is not treated as proof that no principal exists.
 */
export const CLASSIFICATION = {
  DISCLOSED: 'ACCOUNTABLE_DISCLOSED', // verified principal, identity disclosed by consent
  PROTECTED: 'ACCOUNTABLE_PROTECTED', // verified principal, identity protected but recoverable by the directory
  UNSUPPORTED: 'UNSUPPORTED', // a claim was made but could not be established
  UNLABELED: 'UNLABELED', // nothing was presented
  REVOKED: 'REVOKED', // established, but the registration is no longer active
  LOOKUP_FAILED: 'LOOKUP_FAILED', // could not be checked; not evidence that no principal exists
  HUMAN: 'HUMAN_APPROVED', // no agent credentials, but the account holder approved this request with a passkey
};
