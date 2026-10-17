# Running the simulations and tests

Everything runs on one machine with **Node.js 22 or later**. There are no dependencies to install.

```bash
git clone <repository-url> && cd <repository>
npm run sim
```

## Run in the browser instead (GitHub Codespaces)

On the repository's GitHub page, choose **Code → Codespaces → Create codespace**. When the terminal opens, run `npm run sim` or `npm test`. Dashboards open through the **Ports** tab. Codespaces runs on your own GitHub account's free monthly allowance.

The passkey demo does not work in Codespaces, because passkeys are tied to the `localhost` domain the demo uses. Run that one on your own computer.

## The simulator

| Command | What it does |
|---|---|
| `npm run sim` | Runs all seven scenarios and writes `reports/simulation-report.md`. |
| `npm run sim -- --list` | Lists the scenarios with their numbers and ids. |
| `npm run sim -- payment hf` | Runs selected scenarios, by id or number. |
| `npm run sim -- --fresh` | Runs against a throwaway federation with temporary keys and state. |

If the services are already running (`npm start`), the simulator uses them. Otherwise it starts them inside its own process for the length of the run.

### Reading the output

Each scenario is a short story with numbered steps. The markers mean:

| Marker | Meaning |
|---|---|
| `▸ Actor: …` | something a party did |
| `✓` / `✗` | one check a relying party performed (signature, status, trust mark, authority …) |
| `● Relying party → ALLOW / DENY / STEP_UP / DEFERRED [CLASSIFICATION]` | its decision, and why |
| `◆ What X learned` | what the relying party now knows, and what stayed hidden |
| `✔ expected:` / `✘ UNEXPECTED:` | the scenario's own assertion about the outcome |

The summary at the end counts the assertions per scenario. `All expectations met.` means every step behaved as the framework says it should. The same text, in Markdown, is saved to `reports/simulation-report.md`.

## The automated tests

```bash
npm test
```

This runs 17 tests:
- **Unit tests** for the building blocks: JWS and JWE, SD-JWT with key binding, RFC 9162 Merkle proofs, RFC 8785 canonical JSON, RFC 9421 HTTP message signatures, the Token Status List, RAR authority, and WebAuthn.
- **Service tests:** state survives a restart, and requests are refused when they are unverified, replayed or signed with the wrong key.
- **Every simulator scenario**, run as an integration test.
- **The passkey demo**, driven with a simulated passkey.
- **The pilot kit:** the HTTPS fix, the `aaf` command-line tool end to end, and the standalone relying party.

## Watching it happen

```bash
npm start
```

This starts the trust anchor, two registries and two record keepers as separate processes. Run `npm run sim` in a second terminal, then open the dashboards:

| Service | Dashboard |
|---|---|
| Trust anchor | http://127.0.0.1:4100/ |
| Registry A (US) | http://127.0.0.1:4101/ |
| Registry B (EU) | http://127.0.0.1:4102/ |
| Ledgerline Records (authorization + provenance) | http://127.0.0.1:4201/ |
| Tessera Logs (activity) | http://127.0.0.1:4202/ |

Stop everything with Ctrl+C in the first terminal.

## Trying it by hand

With `npm start` running, start the sandbox shop in a second terminal:

```bash
npm run rp
```

Then act as a participant in a third terminal; `docs/PARTICIPATING.md` explains each step. On your own machine you are also the operator, so you verify yourself:

```bash
node src/cli/aaf.js init --local
```

```bash
node src/cli/aaf.js enroll --name "Your Name"
```

```bash
node src/cli/aaf.js operator verify ~/.aaf/verification-request.json
```

```bash
node src/cli/aaf.js agent register helper
```

```bash
node src/cli/aaf.js grant helper commerce.purchase --max-amount 50:USD
```

```bash
node src/cli/aaf.js act helper http://127.0.0.1:4400 commerce.purchase --params '{"amount":{"value":12,"currency":"USD"}}'
```

The shop's page at http://127.0.0.1:4400/ shows each decision and what the shop learned.

## The passkey demo

```bash
npm run demo
```

Open **http://localhost:4300** in Chrome, Safari, Edge or Firefox. Use `localhost`, not `127.0.0.1`: passkeys are bound to a domain. The page walks through four steps:
1. registering a passkey;
2. approving your organization's agent;
3. replaying the Hugging Face attack with a stolen token;
4. approving one deletion with your passkey.

## Other commands

| Command | What it does |
|---|---|
| `node scripts/examples.js` | Regenerates the decoded example artifacts in `spec/examples/`. |
| `npm run reset` | Deletes all local state and keys in `data/` and generates a fresh federation. |
| `deploy/test/check.sh` | Runs the pilot deployment (Docker, Caddy, HTTPS) on this machine and walks through it as a participant and operator. Needs Docker; see [DEPLOYING.md](DEPLOYING.md#check-it-on-one-machine-first). |

## Troubleshooting

- **`EADDRINUSE` (port already in use):** another copy of the services is running. Stop it, or run with `--fresh`, which uses different ports.
- **"trust anchor configuration not found":** run `npm run setup`, or let `npm start` / `npm run sim` do it.
- **Odd failures after updating the code:** run `npm run reset`. Old state in `data/` may not match the new code.
