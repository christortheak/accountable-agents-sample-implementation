// Relying-party policy: proportionate participation rules (framework §5.2).
//
// rules = {
//   'commerce.purchase': [
//     { label, when?: (params) => bool, require: {
//         accountability: 'none' | 'established' | 'disclosed' | 'agent_or_human',
//         liveStatus?: bool (default true), authorization?: bool,
//         attributes?: [names], provenance?: bool,
//         account?: 'owner'        (acting on an account: holder's passkey, or an agent they authorized)
//         humanApproval?: bool     (step-up: the holder's passkey approval for each such action) } },
//     ...first matching tier wins
//   ]
// }
import { CLASSIFICATION as C } from '../lib/protocol.js';

export function pickTier(rules, action, params) {
  const tiers = rules[action];
  if (!tiers) return null;
  return tiers.find((t) => !t.when || t.when(params)) ?? null;
}

export function decide(tier, v) {
  if (!tier) return { decision: 'deny', reasons: ['action not offered'], tier: null };
  const req = tier.require;
  const allow = (reasons = []) => ({ decision: 'allow', reasons, tier: tier.label });
  const deny = (reasons) => ({ decision: 'deny', reasons, tier: tier.label });
  const stepUp = (reasons) => ({ decision: 'step_up', reasons, tier: tier.label });
  const needsAccountability = req.accountability && req.accountability !== 'none';

  switch (v.classification) {
    case C.UNLABELED:
      // The human path: the account gate decides, on a passkey approval.
      if (req.accountability === 'agent_or_human') return { ...deny(['no agent credentials presented']), humanPath: true };
      return needsAccountability ? deny(['no accountability information presented']) : allow(['open tier: no accountability required']);
    case C.UNSUPPORTED:
      return needsAccountability ? deny([`accountability claim not established: ${v.failure}`]) : allow(['open tier: unsupported claim ignored']);
    case C.REVOKED:
      return deny([`registration no longer active (${v.status?.reason ?? 'revoked'})`]);
    case C.LOOKUP_FAILED:
      if (!needsAccountability) return allow(['open tier']);
      return {
        decision: 'deferred',
        reasons: ['registry could not be reached, so status is unknown; consequential access withheld pending verification (not treated as evidence that no principal exists)'],
        tier: tier.label,
      };
    case C.PROTECTED:
      if (req.accountability === 'disclosed') return stepUp(["this tier requires the principal's identity to be disclosed"]);
      break;
    default:
      break;
  }

  for (const name of req.attributes ?? []) {
    const attr = v.attributes.find((a) => a.name === name);
    if (!attr) return stepUp([`requires a verified principal attribute: ${name}`]);
    if (attr.valid_until && attr.valid_until < new Date().toISOString().slice(0, 7)) return deny([`attribute ${name} has expired`]);
  }
  if (req.provenance && !v.records.some((r) => r.role === 'provenance')) return stepUp(['requires disclosure of the agent bill of materials']);
  if (req.authorization) {
    if (!v.authorization) return deny(['no authorization presented']);
    if (!v.authorization.valid) return deny([`authorization not accepted: ${v.authorization.reason}`]);
    if (!v.authority?.permitted) return deny(v.authority?.reasons ?? ['authority does not cover this action']);
  }
  return allow();
}
