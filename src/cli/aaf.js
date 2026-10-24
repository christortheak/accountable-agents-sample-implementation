#!/usr/bin/env node
// aaf: take part in an Accountable Agents federation from the command line.
//
// Keys and state live in $AAF_HOME (default ~/.aaf). Run `aaf help`.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { keyFromJwk, decodeJws } from '../lib/crypto.js';
import { discoverFederation, fetchTrustAnchor, loadTrustAnchor, loadKeys, DATA_DIR } from '../lib/trust.js';
import { describePermission } from '../lib/scope.js';
import { decodeDisclosure, splitSdJwt } from '../lib/sd-jwt.js';
import { Principal } from '../actors/principal.js';
import { Agent } from '../actors/agent.js';
import { IdentityVerifier, ResolutionAuthority } from '../actors/authorities.js';

const HOME = process.env.AAF_HOME ?? path.join(os.homedir(), '.aaf');
const file = (...p) => path.join(HOME, ...p);
const readJson = (f) => (fs.existsSync(f) ? JSON.parse(fs.readFileSync(f, 'utf8')) : null);
const writeJson = (f, v) => {
  fs.mkdirSync(path.dirname(f), { recursive: true, mode: 0o700 });
  fs.writeFileSync(f, JSON.stringify(v, null, 2), { mode: 0o600 });
};

class UsageError extends Error {}
const fail = (msg) => {
  throw new UsageError(msg);
};

// --- arguments -------------------------------------------------------------

function parseArgs(argv) {
  const positional = [];
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const [k, inline] = a.slice(2).split('=', 2);
      if (inline !== undefined) flags[k] = inline;
      else if (argv[i + 1] !== undefined && !argv[i + 1].startsWith('--')) flags[k] = argv[++i];
      else flags[k] = true;
    } else positional.push(a);
  }
  return { positional, flags };
}

// --- state -------------------------------------------------------------------

async function federation() {
  let cfg = readJson(file('config.json'));
  if (!cfg) {
    // On the federation's own server (operators), fall back to the local trust anchor record.
    try {
      cfg = { trust_anchor: loadTrustAnchor() };
    } catch {
      fail('not initialized: run `aaf init <trust-anchor-url>` (or `aaf init --local`)');
    }
  }
  const trust = await discoverFederation(cfg.trust_anchor);
  return { cfg, trust };
}

function loadPrincipal(trust) {
  const s = readJson(file('principal.json')) ?? fail('no principal yet: run `aaf enroll --name "…"`');
  const p = new Principal({ type: s.type, identity: s.identity, contact: s.contact, registry: trust.registry(s.registry), trust });
  p.key = keyFromJwk(s.key);
  p.id = s.id;
  p.receipts = s.receipts ?? [];
  return p;
}

function savePrincipal(p) {
  writeJson(file('principal.json'), { type: p.type, identity: p.identity, contact: p.contact, registry: p.registry.id, key: p.key.privateJwk, id: p.id, receipts: p.receipts });
}

function loadAgent(trust, name) {
  const s = readJson(file('agents', `${name}.json`)) ?? fail(`no agent named ${name} (see \`aaf agent list\`)`);
  const a = new Agent({ name, trust });
  a.longTermKey = keyFromJwk(s.key);
  a.attach({ registry: trust.registry(s.registry), registrationId: s.registration_id, receipt: s.receipt, records: s.records });
  a.grants = (s.grants ?? []).map((g) => ({ grantId: g.grant_id, rk: trust.recordKeeper(g.rk), grant: g.grant }));
  return a;
}

function saveAgent(a) {
  writeJson(file('agents', `${a.name}.json`), {
    name: a.name, key: a.longTermKey.privateJwk, registry: a.registry.id, registration_id: a.registrationId, receipt: a.receipt, records: a.records,
    grants: a.grants.map((g) => ({ grant_id: g.grantId, rk: g.rk.id, grant: g.grant })),
  });
}

const agentNames = () => (fs.existsSync(file('agents')) ? fs.readdirSync(file('agents')).filter((f) => f.endsWith('.json')).map((f) => f.slice(0, -5)) : []);

function defaultRecords(trust) {
  const auth = trust.recordKeepers.find((r) => r.roles.includes('authorization'));
  const activity = trust.recordKeepers.find((r) => r.roles.includes('activity'));
  return [...(auth ? [{ role: 'authorization', rk: auth.id }] : []), ...(activity ? [{ role: 'activity', rk: activity.id }] : [])];
}

function constraintsFrom(flags) {
  const c = {};
  const pair = (v, name) => {
    const [value, unit] = String(v).split(':');
    if (!unit || Number.isNaN(Number(value))) fail(`--${name} expects <number>:<unit>, e.g. 50:USD`);
    return { value: Number(value), unit };
  };
  if (flags['max-amount']) {
    const { value, unit } = pair(flags['max-amount'], 'max-amount');
    c.max_amount = { value, currency: unit };
  }
  if (flags['max-units']) c.max_units = pair(flags['max-units'], 'max-units');
  if (flags.categories) c.categories = String(flags.categories).split(',');
  if (flags.regions) c.regions = String(flags.regions).split(',');
  if (flags['requires-approval']) c.requires_approval = { role: String(flags['requires-approval']) };
  return c;
}

function delegationFrom(flags) {
  const depth = flags.delegable === undefined ? 0 : Number(flags.delegable === true ? 1 : flags.delegable);
  return { allowed: depth > 0, max_depth: depth };
}

function operatorKeysDir(flags) {
  return flags.keys ? path.resolve(flags.keys) : path.join(DATA_DIR, 'keys');
}

// --- commands ----------------------------------------------------------------

const commands = {
  async init({ positional, flags }) {
    let trustAnchor;
    if (flags.local) {
      trustAnchor = loadTrustAnchor();
    } else {
      const url = positional[0] ?? fail('usage: aaf init <trust-anchor-url> [--pin <key thumbprint>] [--entity-id <trust anchor entity id>]   or   aaf init --local');
      // Trust on first use, over HTTPS (or a pinned key thumbprint). Running init again with a new pin is an explicit re-pin.
      if (flags.pin === true || flags['entity-id'] === true) fail('--pin and --entity-id each need a value');
      const { thumbprint: kid, ...anchor } = await fetchTrustAnchor(url, { pin: flags.pin, entityId: flags['entity-id'] });
      trustAnchor = anchor;
      console.log(`Trust anchor key: ${kid}`);
      if (!flags.pin) console.log('Compare it with the key your operator published before relying on this federation.');
      if (!anchor.entity_id_checked) console.log(`Trust anchor entity identifier ${anchor.entity_id} is as the trust anchor states it; pass --entity-id to check it.`);
    }
    const trust = await discoverFederation(trustAnchor);
    writeJson(file('config.json'), { trust_anchor: trustAnchor });
    console.log(`Joined "${trust.doc.federation}" (${trust.registries.length} registr${trust.registries.length === 1 ? 'y' : 'ies'}, ${trust.recordKeepers.length} record keeper(s)). State is kept in ${HOME}.`);
  },

  async federation() {
    const { trust } = await federation();
    console.log(`${trust.doc.federation}  (trust anchor ${trust.trustAnchor.entity_id})`);
    for (const r of trust.registries) console.log(`  registry       ${r.id}  ${r.name}  [${r.chain}]`);
    for (const r of trust.recordKeepers) console.log(`  record keeper  ${r.id}  ${r.name}  roles: ${r.roles.join(', ')}  [${r.chain}]`);
    for (const v of trust.doc.verifiers) console.log(`  verifier       ${v.id}  ${v.name}`);
    for (const a of trust.doc.resolution_authorities) console.log(`  authority      ${a.id}  ${a.name}`);
  },

  async enroll({ flags }) {
    const { trust } = await federation();
    if (readJson(file('principal.json'))) fail(`already enrolled (${file('principal.json')})`);
    const name = flags.name ?? fail('usage: aaf enroll --name "Jane Author" [--type natural_person|legal_person] [--jurisdiction US] [--registration-number …]');
    const registry = flags.registry ? trust.registry(flags.registry) : trust.registries[0];
    if (!registry) fail('no such registry in the federation');
    const identity = { legal_name: name, jurisdiction: flags.jurisdiction ?? 'US', ...(flags['registration-number'] ? { registration_number: flags['registration-number'] } : {}) };
    const p = new Principal({ type: flags.type ?? 'natural_person', identity, contact: flags.contact ?? null, registry, trust });
    await p.enroll();
    savePrincipal(p);
    const request = { principal_id: p.id, registry: registry.id, type: p.type, identity };
    writeJson(file('verification-request.json'), request);
    console.log(`Enrolled with ${registry.name} as ${p.id} (verification pending).`);
    console.log(`Send ${file('verification-request.json')} to your identity verifier (in a pilot, the operator).`);
  },

  async whoami() {
    const { trust } = await federation();
    const p = loadPrincipal(trust);
    console.log(`${p.identity.legal_name} (${p.type}), principal ${p.id} at ${p.registry.id}`);
    for (const n of agentNames()) {
      const a = loadAgent(trust, n);
      console.log(`  agent ${n}: ${a.registrationId}, ${a.grants.length} grant(s)`);
    }
  },

  async notifications() {
    const { trust } = await federation();
    const list = await loadPrincipal(trust).notifications();
    if (!list.length) console.log('No notifications.');
    for (const x of list) console.log(`${x.at}  ${x.kind}${x.agent_label ? `  [${x.agent_label}]` : ''}  ${x.summary ?? x.case ?? x.offer_id ?? ''}`);
  },

  async disclose({ flags }) {
    const { trust } = await federation();
    const p = loadPrincipal(trust);
    const audiences = String(flags.to ?? fail('usage: aaf disclose --to <rp-id>[,<rp-id>] --claims legal_name[,jurisdiction,…] [--attributes a,b]')).split(',');
    const res = await p.setDisclosurePolicy({ identity: { audiences, claims: String(flags.claims ?? 'legal_name').split(',') }, attributes: flags.attributes ? String(flags.attributes).split(',') : [] });
    console.log(`Identity may now be disclosed to ${res.policy.identity.audiences.join(', ')}: ${res.policy.identity.claims.join(', ')}`);
  },

  async agent({ positional, flags }) {
    const sub = positional[0];
    const { trust } = await federation();
    if (sub === 'list') {
      for (const n of agentNames()) {
        const a = loadAgent(trust, n);
        const r = decodeJws(a.receipt).payload;
        console.log(`${n}  ${a.registrationId}  depth ${r.depth}${r.expires_at ? `  expires ${r.expires_at}` : ''}  grants: ${a.grants.length}`);
      }
      return;
    }
    if (sub === 'forget') {
      const name = positional[1] ?? fail('usage: aaf agent forget <name>');
      fs.rmSync(file('agents', `${name}.json`), { force: true });
      console.log(`Deleted the local keys for ${name}. (Its registration is unchanged; use \`aaf revoke\` to end it.)`);
      return;
    }
    if (sub !== 'register') fail('usage: aaf agent register <name> [--parent <agent>] [--expires-in <seconds>] [--max-depth <n>] [--label "…"]   |   aaf agent list   |   aaf agent forget <name>');
    const name = positional[1] ?? fail('agent name required');
    if (readJson(file('agents', `${name}.json`))) fail(`agent ${name} already exists`);
    const agent = new Agent({ name, trust });
    const opts = { label: flags.label ?? name, records: defaultRecords(trust), expiresIn: flags['expires-in'] ? Number(flags['expires-in']) : null, lineage: flags['max-depth'] !== undefined ? { max_depth: Number(flags['max-depth']) } : null };
    let res;
    if (flags.parent) {
      const parent = loadAgent(trust, flags.parent);
      res = await parent.registerSubagent(agent, opts);
    } else {
      const p = loadPrincipal(trust);
      res = await p.registerAgent(agent, opts);
      savePrincipal(p);
    }
    saveAgent(agent);
    console.log(`Registered ${name} as ${res.registration_id} (depth ${res.depth}${res.expires_at ? `, expires ${res.expires_at}` : ''}) in ${res.issuance_ms} ms.`);
  },

  async grant({ positional, flags }) {
    const [name, action] = positional;
    if (!name || !action) fail('usage: aaf grant <agent> <action> [--max-amount 50:USD] [--categories a,b] [--max-units 8:gpu-hour] [--regions a,b] [--requires-approval <role>] [--delegable <depth>] [--days 30] [--purpose "…"]');
    const { trust } = await federation();
    const p = loadPrincipal(trust);
    const agent = loadAgent(trust, name);
    const rk = trust.recordKeepers.find((r) => r.roles.includes('authorization'));
    const permissions = [{ action, constraints: constraintsFrom(flags) }];
    const res = await p.grant(agent, { rk, permissions, delegation: delegationFrom(flags), purpose: flags.purpose, validForDays: Number(flags.days ?? 30) });
    saveAgent(agent);
    console.log(`Granted ${permissions.map(describePermission).join('; ')} to ${name} (grant ${res.grant_id}, held by ${rk.id}).`);
  },

  async delegate({ positional, flags }) {
    const [parentName, childName, action] = positional;
    if (!parentName || !childName || !action) fail('usage: aaf delegate <parent-agent> <child-agent> <action> [constraint flags] [--delegable <depth>] [--days <n>]   (default: 7 days, or until the parent grant ends if sooner)');
    const days = flags.days === undefined ? undefined : Number(flags.days);
    if (flags.days === true || (days !== undefined && !(days > 0))) fail('--days must be a positive number of days');
    const { trust } = await federation();
    const parent = loadAgent(trust, parentName);
    const child = loadAgent(trust, childName);
    const res = await parent.delegate(child, { permissions: [{ action, constraints: constraintsFrom(flags) }], delegation: delegationFrom(flags), validForDays: days });
    saveAgent(child);
    console.log(`${parentName} delegated ${action} to ${childName} (grant ${res.grant_id}).`);
  },

  async act({ positional, flags }) {
    const [name, rpUrl, action] = positional;
    if (!name || !rpUrl || !action) fail('usage: aaf act <agent> <relying-party-url> <action> [--params \'{"…"}\'] [--ephemeral] [--disclose identity,provenance,purpose] [--approval-ref <id>] [--json]');
    const { trust } = await federation();
    const agent = loadAgent(trust, name);
    const params = flags.params ? JSON.parse(flags.params) : {};
    const disclose = flags.disclose ? Object.fromEntries(String(flags.disclose).split(',').map((k) => [k, true])) : undefined;
    const r = await agent.act(rpUrl.replace(/\/$/, ''), action, params, {
      mode: flags.ephemeral ? 'ephemeral' : 'pairwise', disclose, headers: flags['approval-ref'] ? { 'aaf-approval-ref': flags['approval-ref'] } : undefined,
    });
    if (flags.json) {
      console.log(JSON.stringify({ decision: r.decision, classification: r.classification, reasons: r.reasons, tier: r.tier, ppid: r.ppid, result: r.result, approval_request: r.approval_request }, null, 2));
      return;
    }
    console.log(`${String(r.decision).toUpperCase()}  [${r.classification}${r.tier ? `, ${r.tier}` : ''}]${r.reasons?.length ? `  ${r.reasons.join('; ')}` : ''}`);
    console.log(`  presented as ${r.ppid} (${r.mode}), in ${r.latencyMs} ms`);
    const shown = (sd) => (sd ? splitSdJwt(sd).disclosures.map(decodeDisclosure).map((d) => d.name ?? (d.value.type ? describePermission(d.value) : d.value.role ?? Object.keys(d.value.claims ?? {})[0] ?? 'value')) : []);
    console.log(`  disclosed: ${[...shown(r.presentation.accountability), ...shown(r.presentation.authorization)].join(', ') || 'nothing optional'}`);
    if (r.result) console.log(`  result: ${JSON.stringify(r.result)}`);
    if (r.approval_request) console.log(`  approval needed: request ${r.approval_request.request_id} (${r.approval_request.purpose})`);
  },

  async revoke({ positional, flags }) {
    const name = positional[0] ?? fail('usage: aaf revoke <agent> [--reason principal_request|compromised|authority_ended|superseded]');
    const { trust } = await federation();
    const agent = loadAgent(trust, name);
    const parentName = flags.parent;
    const res = parentName ? await loadAgent(trust, parentName).revokeSubagent(agent, flags.reason ?? 'principal_request') : await loadPrincipal(trust).revokeAgent(agent, flags.reason ?? 'principal_request');
    console.log(`${name}: ${res.status}${res.cascades_to ? ` (and ${res.cascades_to} sub-agent(s))` : ''}`);
  },

  async transfer({ positional, flags }) {
    const sub = positional[0];
    const { trust } = await federation();
    const p = loadPrincipal(trust);
    if (sub === 'offer') {
      const name = positional[1] ?? fail('usage: aaf transfer offer <agent> --to <principal-id> [--end-subagents]');
      const to = flags.to ?? fail('--to <principal-id> required');
      const res = await p.offerTransfer(loadAgent(trust, name), { id: to }, { subtree: flags['end-subagents'] ? 'end' : 'move' });
      console.log(`Offered ${name} to ${to}: offer ${res.offer_id} (expires ${res.expires_at}). The recipient runs: aaf transfer accept ${res.offer_id} --as <name>`);
      console.log(`Once accepted, your local keys for ${name} stop working; remove them with: aaf agent forget ${name}`);
    } else if (sub === 'accept') {
      const offerId = positional[1] ?? fail('usage: aaf transfer accept <offer-id> --as <agent-name>');
      const name = flags.as ?? fail('--as <agent-name> required');
      if (readJson(file('agents', `${name}.json`))) fail(`agent ${name} already exists`);
      const agent = new Agent({ name, trust });
      const res = await p.acceptTransfer(offerId, agent);
      const receipt = decodeJws(res.receipt).payload;
      agent.attach({ registry: p.registry, registrationId: receipt.sub, receipt: res.receipt, records: receipt.records });
      savePrincipal(p);
      saveAgent(agent);
      console.log(`Accepted: ${name} is now your agent (${receipt.sub}), with a fresh key, new PPIDs and no grants yet. ${res.descendants_moved} sub-agent(s) came with it.`);
    } else fail('usage: aaf transfer offer|accept …');
  },

  // Operator commands use the federation's own keys (data/keys on the server).
  async operator({ positional, flags }) {
    const sub = positional[0];
    const { trust } = await federation();
    const keysDir = operatorKeysDir(flags);
    if (sub === 'thumbprint') {
      console.log(trust.trustAnchor.jwks.keys[0].kid);
      return;
    }
    if (sub === 'verify') {
      const source = positional[1] ?? fail('usage: aaf operator verify <verification-request.json | -> [--assurance high] [--method "…"] [--keys <dir>]');
      const request = source === '-' ? JSON.parse(fs.readFileSync(0, 'utf8')) : readJson(path.resolve(source)) ?? fail('request file not found');
      const verifierId = flags.verifier ?? trust.doc.verifiers[0]?.id ?? fail('the federation has no identity verifier');
      const verifier = new IdentityVerifier({ id: verifierId, keys: loadKeys(verifierId, keysDir) });
      const principal = { id: request.principal_id, type: request.type, identity: request.identity, registry: trust.registry(request.registry) };
      const res = await verifier.verify(principal, { assurance: flags.assurance ?? (request.type === 'natural_person' ? 'IAL2' : 'high'), method: flags.method ?? 'verified by the pilot team from personal knowledge' });
      console.log(`Verified ${request.identity.legal_name} (${request.principal_id}): ${res.trust_framework} ${res.assurance_level}.`);
    } else if (sub === 'resolve') {
      const ppid = positional[1] ?? fail('usage: aaf operator resolve <ppid> --case "…" [--rp <relying-party-id>] [--related] [--no-notify] [--sealed-ref <jwe>] [--keys <dir>]');
      const authorityId = flags.authority ?? trust.doc.resolution_authorities[0]?.id ?? fail('the federation has no resolution authority');
      const authority = new ResolutionAuthority({ id: authorityId, name: authorityId, keys: loadKeys(authorityId, keysDir) });
      const order = authority.order({
        caseId: flags.case ?? fail('--case required'), ppids: [ppid], relyingParty: flags.rp, requester: flags.requester ?? 'pilot demonstration',
        scope: ['root_principal_identity', 'chain', ...(flags.related ? ['related_ppids'] : [])], notifyPrincipal: !flags['no-notify'],
      });
      const registry = trust.registry(trust.registries.find((r) => ppid.startsWith(`ppid:${new URL(r.id).host}:`))?.id) ?? fail('no registry issued that PPID');
      const res = await authority.resolve(registry, { order, ppid, sealedRef: flags['sealed-ref'] });
      console.log(JSON.stringify(res.result, null, 2));
    } else fail('usage: aaf operator thumbprint|verify|resolve …');
  },

  help() {
    console.log(`aaf: take part in an Accountable Agents federation (state in ${HOME})

  aaf init <trust-anchor-url> [--pin <thumbprint>]    join a federation (or: aaf init --local)
  aaf federation                                      list its members
  aaf enroll --name "…" [--type …] [--jurisdiction …]  become a principal (verification follows)
  aaf whoami | aaf notifications
  aaf disclose --to <rp-id> --claims legal_name        consent to disclose identity to a relying party
  aaf agent register <name> [--parent <agent>] [--expires-in <s>] [--max-depth <n>]
  aaf agent list | aaf agent forget <name>
  aaf grant <agent> <action> [--max-amount 50:USD] [--categories a,b] [--delegable <n>] [--days 30]
  aaf delegate <parent> <child> <action> [constraints]
  aaf act <agent> <relying-party-url> <action> [--params '{…}'] [--ephemeral] [--disclose identity]
  aaf revoke <agent> [--reason …] [--parent <agent>]
  aaf transfer offer <agent> --to <principal-id> [--end-subagents]
  aaf transfer accept <offer-id> --as <name>

  Operators (on the federation's server, or with --keys <dir>):
  aaf operator thumbprint                             the trust anchor key participants should pin
  aaf operator verify <verification-request.json | -> [--assurance …]
  aaf operator resolve <ppid> --case "…" [--rp <id>] [--related] [--no-notify]`);
  },
};

export async function main(argv) {
  const [cmd = 'help', ...rest] = argv;
  const fn = commands[cmd] ?? commands.help;
  return fn(parseArgs(rest));
}

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((err) => {
    console.error(err instanceof UsageError ? err.message : `error: ${err.message}`);
    process.exit(1);
  });
}
