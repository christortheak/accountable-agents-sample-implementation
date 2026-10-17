// Credential formats: every credential an agent presents is an IETF SD-JWT VC
// (typ dc+sd-jwt) with a `vct` naming its type, a `status` entry in an IETF
// Token Status List, and (where it is holder-bound) a `cnf` key that the
// holder proves with a Key Binding JWT.
export const SD_JWT_VC_TYP = 'dc+sd-jwt';

/** Credential type identifiers, namespaced under the federation's Trust Anchor. */
export const vct = (trustAnchorId, kind) => `${trustAnchorId}/vct/${kind}/1`;
export const VCT_KINDS = { accountability: 'accountability', authorization: 'authorization', approval: 'approval' };

/** Signature tag for agent-to-relying-party requests (RFC 9421), cf. Web Bot Auth's "web-bot-auth". */
export const AGENT_SIGNATURE_TAG = 'aaf-agent';
export const AGENT_SIGNED_COMPONENTS = ['@method', '@target-uri', 'content-digest', 'content-type', 'aaf-presentation'];
