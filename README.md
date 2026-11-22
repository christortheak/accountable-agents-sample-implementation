# Accountable Agents Framework: reference implementation

A working implementation of the framework described in *The Accountable Agents Framework (AAF): A Blueprint for AI Agent IDs* (draft of 21 November 2026). The paper's conclusion invites "a reference implementation of a realistic workflow"; this is one. It has four parts:

- **A specification**: [`spec/AAF-SPEC.md`](spec/AAF-SPEC.md) (profile 0.4), with real example artifacts in [`spec/examples/`](spec/examples/). Its [§3](spec/AAF-SPEC.md#3-requirements-traceability) maps every requirement in the paper's Appendix A to the code and a test.
- **Running services**: an OpenID Federation trust anchor, two federated directories (US and EU), and two records services (authorization and provenance; activity).
- **A transaction simulator**: seven scenarios that check the expected outcome of each step. Scenario 4 is the pilot the paper calls for: a disclosed organization, a privacy-protected person, unsupported claims, and revoked or compromised credentials.
- **A pilot kit** for running a live federation with invited participants: an `aaf` command-line tool, a standalone counterparty, and Docker and HTTPS configuration.

| Guide | For |
|---|---|
| [docs/TESTING.md](docs/TESTING.md) | running the simulations, tests and passkey demo, locally or in GitHub Codespaces |
| [docs/PARTICIPATING.md](docs/PARTICIPATING.md) | taking part in a pilot: enrolling, registering agents, transacting |
| [docs/DEPLOYING.md](docs/DEPLOYING.md) | running a live pilot federation on a server |
| [SECURITY.md](SECURITY.md) | known limitations and how to report a problem |

It needs only Node.js 22 or later and has no dependencies. All cryptography uses Node's built-in Ed25519, X25519, AES-GCM, SHA-256 and zlib.

## How it maps to the paper

The code, APIs and wire formats use the paper's terms. Where a term needs a concrete form, it takes this one:

| The paper's term | Here |
|---|---|
| directory | a **directory**: the service that holds identities and issues IDs, the **records services** it accredits, and the identity verifiers it relies on |
| presentation, claims | the `AAF-Presentation` header: an accountability credential (the ID), and optionally authority and an approval |
| ID | written `aaf:<directory>:…`; fields that carry one are named `aaf_id` |
| PPID (reusable) / unlinkable ID | an ID whose `id_mode` is `pairwise` / `unlinkable` (used once) |
| identity escrow, attribution | the directory traces an ID to its principal under a legal order from a designated authority |
| principal record, agent record | the principal record, and the agent's registration |

Against the paper's Appendix A:

- **Met:** every required property (PV-1, PV-3, PV-5, AG-1, AG-2, PR-1 to PR-7, PR-9, PR-10, RV-1, RV-2, ES-1, DR-1, DR-2), with one gap in RV-1: a directory cannot yet withdraw a single attribute before it expires.
- **Optional properties built:** human and legal-entity proofing (PV-2), delegation (AG-3), key replacement (AG-5), agent PPIDs (PR-8).
- **Optional properties not built:** Sybil resistance across directories (PV-4), several principals per agent (AG-4), principal and group PPIDs (PR-8), multi-party escrow (ES-2), conformity assessment (DR-3).
- **Beyond the paper:** accredited records services, transfer of agents between principals, incident relay, bills of materials, activity logs, and passkey-bound account access. These are extensions, not requirements of the paper.

Two limits matter most. The directory issues each ID on demand for a named counterparty, so it learns which services an agent uses. And there is one trust anchor, though each counterparty can choose which directories it accepts. [Spec §16](spec/AAF-SPEC.md#16-limitations-and-open-questions) lists the rest.

## Built on existing standards

Existing specifications are used wherever one fits. The profile's own designs are limited to what none of them covers: the chain from a running agent to a verified principal, IDs and their attribution under escrow, lineages and transfer, legal orders, and incident relay.

| Concern | Specification |
|---|---|
| Federation, trust anchor, accreditation of records services | OpenID Federation 1.0 (entity statements, trust marks) |
| KYC/KYB results and principal attributes | OpenID Connect for Identity Assurance (`verified_claims`) |
| Credentials an agent presents | SD-JWT VC with Key Binding |
| Revocation status | IETF Token Status List |
| Signed requests, including agent requests (the Web Bot Auth pattern) | RFC 9421 HTTP Message Signatures; RFC 9530 Content-Digest |
| Authority | RFC 9396 Rich Authorization Requests |
| Exchanging a grant for an audience-specific credential; delegation chains | RFC 8693 Token Exchange (nested `act`); RFC 7523 client assertions |
| Human approvals; a service's human path; binding account access to specific agents | W3C Web Authentication (passkeys) |
| Bills of materials | CycloneDX 1.6 |
| Canonical JSON; Merkle logs | RFC 8785; RFC 9162 |

[Spec §15](spec/AAF-SPEC.md#15-reuse-of-existing-specifications) accounts for every part, and says which of the implementation options in the paper's Appendix C were chosen.

## Quick start

```bash
git clone https://github.com/christortheak/accountable-agents-sample-implementation.git && cd accountable-agents-sample-implementation
```

```bash
npm run sim
```

This runs every scenario. If the services are not already running, it starts them inside the simulator process. It prints a narrated transcript and writes [`reports/simulation-report.md`](reports/simulation-report.md).

To run the services as separate, persistent processes with live dashboards:

```bash
npm start
```

Then, in a second terminal:

```bash
npm run sim
```

| Service | Entity identifier | Local dashboard |
|---|---|---|
| Trust anchor | `https://federation.aaf.test` | http://127.0.0.1:4100/ |
| Directory A (United States) | `https://directory-a.aaf.test` | http://127.0.0.1:4101/ |
| Directory B (European Union) | `https://directory-b.aaf.test` | http://127.0.0.1:4102/ |
| Ledgerline Records (authorization + provenance) | `https://records-1.aaf.test` | http://127.0.0.1:4201/ |
| Tessera Logs (activity) | `https://records-2.aaf.test` | http://127.0.0.1:4202/ |

Every service publishes its OpenID Federation Entity Configuration at `/.well-known/openid-federation`.

## Passkey demo (real passkeys)

```bash
npm run demo
```

Then open **http://localhost:4300** in Chrome, Safari, Edge or Firefox. Use `localhost`, not `127.0.0.1`, because passkeys are bound to a domain. You play the administrator of an account at a model-hosting platform:

1. Register a passkey with Touch ID, Face ID or your device PIN.
2. Approve your organization's accountable agent. You see what kind of principal stands behind it and how it was verified, without anyone being named.
3. Replay the Hugging Face attack. The stolen token gets the rogue agents nothing, and their principal is notified on the first attempt.
4. Approve a single deletion with your passkey, then watch the agent fail to reuse that approval.

The demo uses the running federation if `npm start` is up, and otherwise starts its own.

Other commands:

| Command | What it does |
|---|---|
| `npm run sim -- payment hf` | Run selected scenarios, by id or number (`--list` shows them). |
| `npm run sim -- --fresh` | Run against a throwaway federation with temporary state. |
| `npm test` | Run the unit tests, service tests and every scenario as integration tests. |
| `npm run shop` | Start the sandbox shop (a standalone counterparty) at http://127.0.0.1:4400. |
| `node src/cli/aaf.js help` | The `aaf` command-line tool for principals, agents and operators (see docs/PARTICIPATING.md). |
| `npm run reset` | Wipe all state and keys, then regenerate the federation. Needed after upgrading from an earlier profile: IDs and credentials changed format in 0.3, and 0.4 renamed services, fields and commands to the paper's terms. |
| `node scripts/examples.js` | Regenerate the spec's example artifacts. |

## The scenarios

| # | id | Paper requirements shown | What it shows |
|---|---|---|---|
| 1 | `payment` | PR-5 to PR-8, PR-10, RV-1, ES-1 | A shopping agent at two merchants and a BSA-regulated bank. The merchants learn only an ID and the purchasing permission. The bank sets acceptance criteria (kind of principal, assurance level, chain length) and is shown those. A refusal above the limit is flagged as a SAR candidate; then revocation, and attribution by a regulator without tipping off the subject. Also an automated check that the merchants cannot link what they received. |
| 2 | `filing` | PR-4, PR-10 | Identity and authority checked separately. The agent cannot submit alone. The officer approves with a passkey, bound to the exact document, and a revoked officer's approval is refused. A dispute is settled from both sides' signed logs. A healthcare variant proves licensure without naming the provider. |
| 3 | `hf` | RV-1, ES-1; paper §3.3 (rogue agents) | The Hugging Face incident replayed three ways. Branch A: unidentified agents are denied. Branch B, the framework alone: accountable agents using a stolen account token are logged from the first request; the principal is notified, revocation stops the attack, and a court order yields the principal, its agents and the model. Branch C, the framework plus passkeys: the platform binds account access to passkey-approved agents, so the stolen token is refused at the first request and nothing is read. Also rent-a-principal: the sham sponsor is identified, and a court order has the directory revoke the agent. |
| 4 | `compute` | the pilot in the paper's conclusion; PR-7, ES-1 | Paid GPUs for a disclosed organization, a privacy-protected person using single-use IDs, unsupported claims, a directory outage (`deferred`), and revoked or compromised credentials. |
| 5 | `federation` | AG-3; several directories | A delegating agent in the US directory registers a sub-agent in the EU directory. Over-delegation is rejected. The incident relay, revocation and attribution cross directories. |
| 6 | `audit` | paper §3.5 (verifiable activity records) | A compromised activity records service rewrites a refusal. The counterparty proves the tampering from its receipt, and the directory's chain of custody is unaffected. |
| 7 | `lineage` | AG-3, AG-5; transfer (an extension) | Short-lived sub-agents that expire with their parents; lineage depth budgets; deregistration cutting off a branch. Transfer of an agent and its sub-agents to another principal: both sign, IDs and authority start over, and the old principal remains answerable for the time before. |

## Code layout

| Component | Code |
|---|---|
| Trust anchor (governance body) | [`src/trustanchor/`](src/trustanchor/) |
| Directory: principal and agent records, IDs, status, identity escrow | [`src/directory/`](src/directory/) |
| Records services (the part of a directory that keeps authorizations, bills of materials and activity logs) | [`src/records/`](src/records/) |
| Principal, agent, provider, identity verifier, court or regulator (designated authority) | [`src/actors/`](src/actors/) |
| Counterparty: verification, acceptance criteria, policy, evidence, passkey accounts | [`src/counterparty/`](src/counterparty/) |
| Browser demo (real passkeys) | [`src/demo/`](src/demo/) |
| `aaf` command-line tool | [`src/cli/`](src/cli/) |
| Standalone counterparty (sandbox shop) | [`src/counterparty/standalone.js`](src/counterparty/standalone.js) |
| Deployment: Dockerfile, Compose, Caddy (HTTPS), and a local check of all three | [`deploy/`](deploy/), with config templates in [`config/`](config/) |
| Standards building blocks (RFC 9421, SD-JWT, status lists, OpenID Federation, IDA, RAR, WebAuthn, CBOR, Merkle logs) | [`src/lib/`](src/lib/) |

Runtime state lives in `data/`, which is git-ignored because it holds generated private keys and admin tokens. Set `AAF_DATA_DIR` to put it elsewhere. Each service's database is its own append-only Merkle log, replayed at start-up.

## Status

This is a reference implementation for discussion, not production software. Locally it uses plain HTTP and simulated KYC; the pilot kit adds HTTPS but is meant for a small invited group, not open use. Keys are kept in files. [SECURITY.md](SECURITY.md) lists the known limitations and how to report a problem, and [spec §16](spec/AAF-SPEC.md#16-limitations-and-open-questions) lists the design limits and open questions.

Licensed under the [MIT License](LICENSE).
