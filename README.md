# Accountable Agents Framework: reference implementation

A working implementation of the framework described in *The Accountable Agents Framework* (forthcoming). It has three parts:

- **A specification**: [`spec/AAF-SPEC.md`](spec/AAF-SPEC.md) (profile 0.2), with real example artifacts in [`spec/examples/`](spec/examples/).
- **Running services**: an OpenID Federation trust anchor, two federated registries (US and EU), and two record keepers (authorization and provenance; activity).
- **A transaction simulator**: seven scenarios that act out the paper's scenarios and check the expected outcome of each step.
- **A pilot kit** for running a live federation with invited participants: an `aaf` command-line tool, a standalone relying party, and Docker and HTTPS configuration.

| Guide | For |
|---|---|
| [docs/TESTING.md](docs/TESTING.md) | running the simulations, tests and passkey demo, locally or in GitHub Codespaces |
| [docs/PARTICIPATING.md](docs/PARTICIPATING.md) | taking part in a pilot: enrolling, registering agents, transacting |
| [docs/DEPLOYING.md](docs/DEPLOYING.md) | running a live pilot federation on a server |
| [SECURITY.md](SECURITY.md) | known limitations and how to report a problem |

It needs only Node.js 22 or later and has no dependencies. All cryptography uses Node's built-in Ed25519, X25519, AES-GCM, SHA-256 and zlib.

## Built on existing standards

Existing specifications are used wherever one fits. The profile's own designs are limited to what none of them covers: the chain from a running agent to a verified legal person, PPIDs and their resolution, lineages and transfer, legal orders, and incident relay.

| Concern | Specification |
|---|---|
| Federation, trust anchor, accreditation of record keepers | OpenID Federation 1.0 (entity statements, trust marks) |
| KYC/KYB results and principal attributes | OpenID Connect for Identity Assurance (`verified_claims`) |
| Credentials an agent presents | SD-JWT VC with Key Binding |
| Revocation status | IETF Token Status List |
| Signed requests, including agent requests (the Web Bot Auth pattern) | RFC 9421 HTTP Message Signatures; RFC 9530 Content-Digest |
| Authority | RFC 9396 Rich Authorization Requests |
| Exchanging a grant for an audience-specific credential; delegation chains | RFC 8693 Token Exchange (nested `act`); RFC 7523 client assertions |
| Human approvals; a service's human path; binding account access to specific agents | W3C Web Authentication (passkeys) |
| Bills of materials | CycloneDX 1.6 |
| Canonical JSON; Merkle logs | RFC 8785; RFC 9162 |

[Spec §15](spec/AAF-SPEC.md#15-reuse-of-existing-specifications) accounts for every part.

## Quick start

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
| Registry A (United States) | `https://registry-a.aaf.test` | http://127.0.0.1:4101/ |
| Registry B (European Union) | `https://registry-b.aaf.test` | http://127.0.0.1:4102/ |
| Ledgerline Records (authorization + provenance) | `https://records-1.aaf.test` | http://127.0.0.1:4201/ |
| Tessera Logs (activity) | `https://records-2.aaf.test` | http://127.0.0.1:4202/ |

Every service publishes its OpenID Federation Entity Configuration at `/.well-known/openid-federation`.

## Passkey demo (real passkeys)

```bash
npm run demo
```

Then open **http://localhost:4300** in Chrome, Safari, Edge or Firefox. Use `localhost`, not `127.0.0.1`, because passkeys are bound to a domain. You play the administrator of an account at a model-hosting platform:

1. Register a passkey with Touch ID, Face ID or your device PIN.
2. Approve your organization's accountable agent. You see who stands behind it without anyone being named.
3. Replay the Hugging Face attack. The stolen token gets the rogue agents nothing, and their principal is notified on the first attempt.
4. Approve a single deletion with your passkey, then watch the agent fail to reuse that approval.

The demo uses the running federation if `npm start` is up, and otherwise starts its own.

Other commands:

| Command | What it does |
|---|---|
| `npm run sim -- payment hf` | Run selected scenarios, by id or number (`--list` shows them). |
| `npm run sim -- --fresh` | Run against a throwaway federation with temporary state. |
| `npm test` | Run the unit tests, service tests and every scenario as integration tests. |
| `npm run rp` | Start the sandbox shop (a standalone relying party) at http://127.0.0.1:4400. |
| `node src/cli/aaf.js help` | The `aaf` command-line tool for principals, agents and operators (see docs/PARTICIPATING.md). |
| `npm run reset` | Wipe all state and keys, then regenerate the federation. Needed after upgrading from profile 0.1. |
| `node scripts/examples.js` | Regenerate the spec's example artifacts. |

## The scenarios

| # | id | Paper section | What it shows |
|---|---|---|---|
| 1 | `payment` | §4, Scenario 1 | A shopping agent at two merchants and a BSA-regulated bank. Pairwise PPIDs, selective disclosure, a refusal above the limit flagged as a SAR candidate, revocation, and resolution by a regulator without tipping off the subject. Also an automated check that the merchants cannot link what they received. |
| 2 | `filing` | §4, Scenario 2 | Identity and authority checked separately. The agent cannot submit alone. The officer approves with a passkey, bound to the exact document, and a revoked officer's approval is refused. A dispute is settled from both sides' signed logs. A healthcare variant proves licensure without naming the provider. |
| 3 | `hf` | §4, Scenario 3 | The Hugging Face incident replayed three ways. Branch A: unidentified agents are denied. Branch B, the framework alone: accountable agents using stolen credentials are logged from the first request; the principal is notified, revocation stops the attack, and a court order yields the principal, its agents and the model. Branch C, the framework plus passkeys: the platform binds account access to passkey-approved agents, so the stolen token is refused at the first request and nothing is read. Also covers rent-a-principal. |
| 4 | `compute` | §5.6, open challenge | Paid GPUs for a disclosed organization, a privacy-protected person using ephemeral PPIDs, unsupported claims, a registry outage (`deferred`), and revoked or compromised credentials. |
| 5 | `federation` | §3.1, Figure 0 | A parent agent in the US registry registers a sub-agent in the EU registry. Over-delegation is rejected. The incident relay, revocation and resolution cross registries. |
| 6 | `audit` | §3.1–3.2 | A compromised activity record keeper rewrites a refusal. The relying party proves the tampering from its receipt, and the registry's chain of custody is unaffected. |
| 7 | `lineage` | §3.1–3.2 | Ephemeral sub-agents that expire with their parents; lineage depth budgets; deregistration cutting off a branch. Transfer of an agent and its sub-agents to another principal: both sign, PPIDs and authority start over, and the old principal remains answerable for the time before. |

## Code layout

| Paper component | Code |
|---|---|
| Trust anchor (governance body) | [`src/trustanchor/`](src/trustanchor/) |
| Registry | [`src/registry/`](src/registry/) |
| Record keepers | [`src/recordkeeper/`](src/recordkeeper/) |
| Principal, agent, provider, identity verifier, court or regulator | [`src/actors/`](src/actors/) |
| Relying party: verification, classification, policy, evidence, passkey accounts | [`src/rp/`](src/rp/) |
| Browser demo (real passkeys) | [`src/demo/`](src/demo/) |
| `aaf` command-line tool | [`src/cli/`](src/cli/) |
| Standalone relying party (sandbox shop) | [`src/rp/standalone.js`](src/rp/standalone.js) |
| Deployment: Dockerfile, Compose, Caddy (HTTPS), and a local check of all three | [`deploy/`](deploy/), with config templates in [`config/`](config/) |
| Standards building blocks (RFC 9421, SD-JWT, status lists, OpenID Federation, IDA, RAR, WebAuthn, CBOR, Merkle logs) | [`src/lib/`](src/lib/) |

Runtime state lives in `data/`, which is git-ignored because it holds generated private keys and admin tokens. Set `AAF_DATA_DIR` to put it elsewhere. Each service's database is its own append-only Merkle log, replayed at start-up.

## Status

This is a reference implementation for discussion, not production software. Locally it uses plain HTTP and simulated KYC; the pilot kit adds HTTPS but is meant for a small invited group, not open use. Keys are kept in files. [SECURITY.md](SECURITY.md) lists the known limitations and how to report a problem, and [spec §16](spec/AAF-SPEC.md#16-limitations-and-open-questions) lists the design limits and open questions.

Licensed under the [MIT License](LICENSE).
