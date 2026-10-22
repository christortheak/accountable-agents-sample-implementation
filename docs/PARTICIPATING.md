# Taking part in a pilot federation

This guide is for participants: you enroll as a principal, register agents, give them authority, and let them transact with the pilot's sandbox shop. Your operator will send you two things: the federation's address (for example `https://federation.example.org`) and its key thumbprint.

Nothing real is bought or sold. The shop only records decisions.

## What you need

- Node.js 22 or later.
- This repository:

```bash
git clone https://github.com/christortheak/accountable-agents-framework.git && cd accountable-agents-framework
```

To get the `aaf` command on your path:

```bash
npm link
```

If you'd rather not, use `node src/cli/aaf.js` wherever this guide says `aaf`.

## 1. Join the federation

```text
aaf init https://federation.example.org --pin <thumbprint>
```

`--pin` makes sure you reached the real federation and not an impostor. If the key doesn't match, the command stops. Your keys and settings are kept in `~/.aaf`; set `AAF_HOME` to keep them elsewhere.

How the pin is checked: the trust anchor's Entity Configuration must be signed by the key whose computed RFC 7638 thumbprint equals `<thumbprint>`. It is not enough for that key to be listed alongside another key that signs. Only the pinned key is saved in `~/.aaf/config.json`, and only it is trusted for later discovery and Subordinate Statements; keys the trust anchor advertises later are ignored, so there is no automatic key rollover.

Add `--entity-id <id>` if your operator gave you the trust anchor's entity identifier; the command then stops unless the Entity Configuration's `iss` and `sub` both equal it. The URL you pass is where the trust anchor is served and may differ from its entity identifier. Without `--entity-id`, the identifier is taken as the trust anchor states it, and the command says it was not checked.

Without `--pin`, `aaf init` trusts on first use: it selects the advertised key named by the signature's `kid` (keeping that `kid`), checks the signature with it, and prints the key's thumbprint for you to compare with the one your operator published. `--pin` or `--entity-id` given with an empty value is an error, not a fall-back to trust on first use. The trust anchor's `iss` must be an absolute URL and equal its `sub`.

If the operator replaces the trust anchor's key, later commands fail until you re-pin explicitly by running `aaf init <url> --pin <new thumbprint>` again with the new thumbprint they send you.

## 2. Enroll as a principal

```text
aaf enroll --name "Your Name"
```

This creates your principal key and registers you, with verification pending. Use your name only: the operator can read whatever you enroll with. Add `--type legal_person` and `--registration-number …` to enroll an organization.

Send the file it writes, `~/.aaf/verification-request.json`, to your operator. Once they've verified you, you can register agents.

## 3. Register an agent and give it authority

```text
aaf agent register helper
```

```text
aaf grant helper commerce.purchase --max-amount 50:USD
```

The agent has its own keys. The grant is what it may do, and it is kept by the record keeper. Other limits you can set:

| Option | Example | Meaning |
|---|---|---|
| `--max-amount` | `50:USD` | at most this much per transaction |
| `--categories` | `books,office` | only these categories |
| `--max-units` | `8:gpu-hour` | at most this many units |
| `--regions` | `us-east` | only these regions |
| `--delegable` | `1` | the agent may pass this on, this many levels down |
| `--days` | `30` | how long the grant lasts |

## 4. Transact

```text
aaf act helper https://shop.example.org commerce.purchase --params '{"amount":{"value":12,"currency":"USD"},"item":"a book"}'
```

The output shows the shop's decision, how your agent appeared to the shop (its PPID), and what it disclosed. Then open `https://shop.example.org` in a browser. Its page lists every decision, with what the shop learned and what stayed hidden. Try:
- **A larger purchase.** The shop asks for more: your identity. Agree to share it with this shop only:

```text
aaf disclose --to https://shop.example.org --claims legal_name
```

  Then repeat the purchase.
- **`--ephemeral`.** A fresh identifier for every request, so even the shop can't link your visits.
- **`content.read` or `compute.provision`.** Other actions the shop offers. Your agent needs a grant for each, except `content.read`, which is open to everyone.

Any AI agent that can run shell commands, such as a coding assistant, can transact through `aaf act` on your behalf.

## 5. Sub-agents, revocation and transfer

```text
aaf grant helper compute.provision --max-units 16:gpu-hour --delegable 1
```

```text
aaf agent register worker --parent helper --expires-in 3600
```

```text
aaf delegate helper worker compute.provision --max-units 4:gpu-hour
```

The worker lapses after an hour, can't outlive its parent, and can only ever be given less authority than its parent has.

| Command | What it does |
|---|---|
| `aaf revoke helper --reason compromised` | Ends an agent and everything below it, at once. |
| `aaf transfer offer helper --to <their principal id>` | Hands an agent to another participant. They accept with `aaf transfer accept <offer-id> --as <name>`. The agent gets new identifiers and a fresh key, and starts with no authority. You remain answerable for what it did before the transfer. |
| `aaf notifications` | Shows incident reports, transfers, and any resolution of your agents' identity under a (demonstration) court order. |
| `aaf whoami` · `aaf agent list` · `aaf federation` | Shows where things stand. |

## Your keys

Everything is in `~/.aaf`:
- your principal key;
- each agent's key and grants;
- the federation's address and key.

Keep the folder private. There is no recovery: if you lose it, enroll again and register new agents. `aaf agent forget <name>` deletes an agent's local keys; use it after you've transferred the agent to someone else.

## What others can see

| Party | Sees |
|---|---|
| The shop | a per-shop identifier for your agent; that a verified person stands behind it, and who verified them; the authority relevant to each request; your name only if you agreed to `disclose` it to that shop |
| The registry (the operator) | who you are, your agents and their status, and the identifiers it issued |
| The record keeper | your grants and the agents' activity logs |
| A court order (simulated by the operator) | which principal stood behind an agent at the time; you are notified |

## Rehearsing on your own computer

You can try all of this without a live federation. Start the local federation and shop:

```bash
npm start
```

```bash
npm run rp
```

Then join it with `aaf init --local`. On your own machine you act as operator too:

```text
aaf operator verify ~/.aaf/verification-request.json
```

The local shop is at http://127.0.0.1:4400.
