// Authority, expressed as OAuth Rich Authorization Requests (RFC 9396)
// `authorization_details` objects:
//
//   { type: 'commerce', actions: ['purchase'], max_amount: { value, currency }, categories: [...] }
//
// `type` and `actions` are RAR's common fields (actions omitted = every action
// of the type). The other members are this profile's constraint types; unknown
// constraint types fail closed. Prohibitions use the same shape. A requested
// action is named "type.action" (e.g. "commerce.purchase").

export const KNOWN_CONSTRAINTS = ['max_amount', 'categories', 'max_units', 'regions', 'requires_approval'];
const RAR_COMMON = ['type', 'actions', 'locations', 'datatypes', 'identifier', 'privileges'];

/** "commerce.purchase" -> { type: 'commerce', action: 'purchase' }; "commerce.*" -> { type: 'commerce', action: '*' } */
export function parseAction(name) {
  const i = name.lastIndexOf('.');
  return i < 0 ? { type: name, action: '*' } : { type: name.slice(0, i), action: name.slice(i + 1) };
}

/** Build an authorization_details entry from shorthand ({ action: 'commerce.purchase', constraints }), or pass RAR through. */
export function toRar(p) {
  if (p.type) return p;
  const { type, action } = parseAction(p.action);
  return { type, ...(action === '*' ? {} : { actions: [action] }), ...(p.constraints ?? {}) };
}

export const constraintsOf = (detail) => Object.fromEntries(Object.entries(detail).filter(([k]) => !RAR_COMMON.includes(k)));

/** Does an authorization_details entry cover the requested action? */
export function detailMatches(detail, actionName) {
  const { type, action } = parseAction(actionName);
  if (detail.type !== '*' && detail.type !== type) return false;
  return !detail.actions || detail.actions.includes('*') || detail.actions.includes(action);
}

/** Does entry `outer` cover every action entry `inner` could? */
function detailCovers(outer, inner) {
  if (outer.type !== '*' && outer.type !== inner.type) return false;
  if (!outer.actions || outer.actions.includes('*')) return true;
  if (!inner.actions) return false;
  return inner.actions.every((a) => outer.actions.includes(a));
}

function checkConstraint(name, constraint, params, context) {
  switch (name) {
    case 'max_amount': {
      const amount = params.amount;
      if (!amount) return `missing amount (limit ${fmtMoney(constraint)})`;
      if (amount.currency !== constraint.currency) return `currency ${amount.currency} not authorized (limit is in ${constraint.currency})`;
      if (amount.value > constraint.value) return `amount ${fmtMoney(amount)} exceeds authorized limit ${fmtMoney(constraint)}`;
      return null;
    }
    case 'categories':
      if (!params.category) return 'missing category';
      return constraint.includes(params.category) ? null : `category "${params.category}" not authorized`;
    case 'max_units': {
      if (params.units === undefined) return `missing units (limit ${constraint.value} ${constraint.unit})`;
      if (params.unit && params.unit !== constraint.unit) return `unit ${params.unit} not authorized`;
      return params.units <= constraint.value ? null : `${params.units} ${constraint.unit} exceeds authorized ${constraint.value}`;
    }
    case 'regions':
      if (!params.region) return 'missing region';
      return constraint.includes(params.region) ? null : `region "${params.region}" not authorized`;
    case 'requires_approval': {
      const approval = context.approval;
      if (!approval) return `requires approval by ${constraint.role}; none presented`;
      if (!approval.valid) return `approval by ${constraint.role} is not valid: ${approval.reason}`;
      if (approval.role !== constraint.role) return `approval is from role ${approval.role}, not ${constraint.role}`;
      return null;
    }
    default:
      return `unrecognized constraint "${name}"`;
  }
}

const fmtMoney = (m) => `${m.value} ${m.currency}`;

/**
 * Evaluate a requested action against (disclosed) authorization_details and
 * prohibitions. context.approval: { valid, role, reason } when an approval was presented.
 */
export function evaluate({ permissions = [], prohibitions = [] }, { action, params = {} }, context = {}) {
  if (prohibitions.some((p) => detailMatches(p, action))) return { permitted: false, reasons: [`action ${action} is prohibited by the grant`] };
  const candidates = permissions.filter((p) => detailMatches(p, action));
  if (!candidates.length) return { permitted: false, reasons: [`no disclosed permission covers ${action}`] };
  let best = null;
  for (const permission of candidates) {
    const failures = Object.entries(constraintsOf(permission))
      .map(([name, c]) => checkConstraint(name, c, params, context))
      .filter(Boolean);
    if (!failures.length) return { permitted: true, reasons: [], matched: permission };
    if (!best || failures.length < best.length) best = failures;
  }
  return { permitted: false, reasons: best };
}

function constraintAtLeastAsStrict(name, child, parent) {
  if (child === undefined) return false;
  switch (name) {
    case 'max_amount':
      return child.currency === parent.currency && child.value <= parent.value;
    case 'max_units':
      return child.unit === parent.unit && child.value <= parent.value;
    case 'categories':
    case 'regions':
      return child.every((c) => parent.includes(c));
    case 'requires_approval':
      return child.role === parent.role;
    default:
      return false;
  }
}

/**
 * Check that a delegated (child) grant only narrows its parent.
 * Grants carry authorization_details and prohibitions. Returns { ok, errors, effectiveProhibitions }.
 */
export function checkAttenuation(child, parent) {
  const errors = [];
  const parentDelegation = parent.delegation ?? { allowed: false, max_depth: 0 };
  if (!parentDelegation.allowed || (parentDelegation.max_depth ?? 0) < 1) errors.push('parent grant does not allow further delegation');
  const childDepth = child.delegation?.allowed ? child.delegation.max_depth ?? 0 : 0;
  if (childDepth > (parentDelegation.max_depth ?? 0) - 1) errors.push('child grant allows deeper delegation than the parent permits');
  if (child.exp > parent.exp) errors.push('child grant outlives its parent');

  for (const cd of child.authorization_details ?? []) {
    if ((parent.prohibitions ?? []).some((pr) => detailCovers(pr, cd) || (cd.actions ?? []).some((a) => detailMatches(pr, `${cd.type}.${a}`)))) {
      errors.push(`permission ${describePermission(cd)} is prohibited by the parent grant`);
      continue;
    }
    for (const name of Object.keys(constraintsOf(cd))) if (!KNOWN_CONSTRAINTS.includes(name)) errors.push(`unrecognized constraint "${name}" on ${cd.type}`);
    const covered = (parent.authorization_details ?? []).some(
      (pd) => detailCovers(pd, cd) && Object.entries(constraintsOf(pd)).every(([name, pc]) => constraintAtLeastAsStrict(name, cd[name], pc)),
    );
    if (!covered) errors.push(`permission ${describePermission(cd)} exceeds the parent grant`);
  }
  const effectiveProhibitions = dedupe([...(parent.prohibitions ?? []), ...(child.prohibitions ?? [])]);
  return { ok: errors.length === 0, errors, effectiveProhibitions };
}

const dedupe = (list) => [...new Map(list.map((p) => [JSON.stringify(p), p])).values()];

export function describeConstraints(constraints = {}) {
  const parts = Object.entries(constraints).map(([k, v]) => {
    if (k === 'max_amount') return `≤ ${fmtMoney(v)}`;
    if (k === 'max_units') return `≤ ${v.value} ${v.unit}`;
    if (k === 'requires_approval') return `with approval of ${v.role}`;
    if (Array.isArray(v)) return `${k}: ${v.join('/')}`;
    return `${k}: ${JSON.stringify(v)}`;
  });
  return parts.length ? `(${parts.join(', ')})` : '';
}

export function describePermission(detail) {
  const d = toRar(detail);
  const actions = d.actions?.length ? d.actions.map((a) => `${d.type}.${a}`).join(' | ') : `${d.type}.*`;
  return `${actions} ${describeConstraints(constraintsOf(d))}`.trim();
}
