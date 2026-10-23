# Deploying a pilot federation

This guide is for whoever runs a small, live federation that invited participants (for example a paper's authors) can use with their own agents. It is a **testbed, not production software**: read [Before you start](#before-you-start).

## What you get

One server runs four public services behind HTTPS, each on its own subdomain:

| Service | Example address | What it does |
|---|---|---|
| Trust anchor | `https://federation.example.org` | the federation's governance body: lists members and vouches for their keys (OpenID Federation) |
| Registry | `https://registry.example.org` | verifies principals, registers agents, issues PPIDs and credentials, publishes status, resolves under orders |
| Record keeper | `https://records.example.org` | authorization records and token exchange, provenance, activity logs |
| Sandbox shop | `https://shop.example.org` | a relying party where agents transact; its home page shows every decision and what it learned |

As the operator you also play two roles that can't be automated in a pilot:
- **Identity verifier:** you confirm who each participant is, for example from personal knowledge, and record it with one command. The federation calls this "verified by the pilot team"; it is not a KYC check.
- **Resolution authority:** a mock court, used only to demonstrate how identity is resolved under a legal order.

## Before you start

- **Not production.** There is no rate limiting. Replay protection is kept in memory, so it resets when a service restarts. Service keys can't be rotated, and the only copy of each is on the server's disk.
- **Invite only.** Run it for a small, invited group and keep it to the pilot's lifetime.
- **Personal data.** The registry stores the identity claims each participant enrolls with, and you, as operator, can read them. Ask participants to enroll with a name only, and agree in advance how long the pilot keeps data.
- **Keep secrets private.** Your configured copies (`deploy/.env`, `config/*.pilot.json`) and everything in the data volumes are kept out of git. Never commit them.

## Prerequisites

- A Linux server (1 vCPU and 1 GB of RAM is plenty) with Docker and Docker Compose, and ports 80 and 443 open.
- A domain you control, with four DNS names pointing at the server's public IP address. For example: `federation`, `registry`, `records` and `shop`, each `.example.org`.
- The server must be able to reach its own public addresses, because the services talk to each other through them. On most cloud servers this works without any extra setup.

## Check it on one machine first

You can run the whole deployment on any machine with Docker before you set up DNS or a server, including a laptop:

```bash
deploy/test/check.sh
```

It uses the same image, Compose file and Caddyfile as a real pilot. The pilot's services get made-up `*.pilot.test` names and certificates from Caddy's own local CA. Then it plays both the participant and the operator, and checks each step:
- joining with a pinned key, and refusing a wrong one;
- enrolling and verifying;
- registering an agent and granting it authority;
- purchases the shop allows, asks for more on, and denies;
- `/admin` blocked;
- resolving a PPID;
- a restart that keeps every key and record.

It takes a few minutes and removes everything afterwards (`--keep` leaves it running). It runs as its own Compose project on 127.0.0.1:8443, so it can't touch a real pilot on the same server. The one thing it can't check is that Let's Encrypt issues certificates for your domains; that happens on the first real start.

On a Mac, Docker can come from [Colima](https://github.com/abiosoft/colima): `brew install colima docker docker-compose docker-buildx`, then `colima start`. Homebrew's notes explain the one line to add to `~/.docker/config.json` so `docker compose` finds its plugins.

## 1. Get the code and configure it

On the server:

```bash
git clone https://github.com/christortheak/accountable-agents-framework.git aaf && cd aaf
```

```bash
cp deploy/.env.example deploy/.env
```

```bash
cp config/federation.pilot.example.json config/federation.pilot.json
```

```bash
cp config/rp.pilot.example.json config/rp.pilot.json
```

In all three copies, replace `example.org` with your domain. The names must match exactly across the files:
- `deploy/.env` tells the HTTPS proxy which names to serve.
- `config/federation.pilot.json` gives each service's `id` and `publicUrl`.
- `config/rp.pilot.json` gives the shop's `id`, its `publicUrl`, and the trust anchor's address.

You can also change the names of the services, the federation's policies, and the shop's rules: which actions it offers and what each requires. Policy tiers are explained in the specification, §10.3.

## 2. Start it

```bash
docker compose -f deploy/docker-compose.yml up -d --build
```

On the first start:
1. The federation container generates every service's keys into its data volume.
2. Caddy obtains HTTPS certificates for the four names.
3. The registry, record keeper and shop discover one another through the trust anchor.
4. The registry accredits the record keeper by issuing trust marks.

This can take a minute while certificates are issued. Follow it with:

```bash
docker compose -f deploy/docker-compose.yml logs -f
```

Then open each address in a browser: every service has a status page at `/`. The `/admin` paths are blocked at the proxy, because they are only used from inside the server.

## 3. Tell participants how to join

Participants need the trust anchor's address and its **key thumbprint**, so their tool can tell they reached the real federation. Print the thumbprint with:

```bash
docker compose -f deploy/docker-compose.yml exec federation node src/cli/aaf.js operator thumbprint
```

Send both to participants through a channel they already trust, together with [PARTICIPATING.md](PARTICIPATING.md). They join with:

```text
aaf init https://federation.example.org --pin <thumbprint>
```

Participants may also pass `--entity-id <trust anchor entity id>` to check the identifier (the `trustAnchor.id` in your federation config). A standalone relying party takes the same settings in its config: `"trustAnchor": { "url": …, "pin": "<thumbprint>", "entityId": "<id>" }`; with `pin` null or omitted it trusts on first use, and with `entityId` omitted the identifier is not checked. Any other non-string or empty `pin`, and an `entityId` that is present but not an absolute URL string (including null), stops startup instead.

The pinned key stays the only trusted trust anchor key; newly advertised keys are not picked up. If you replace the trust anchor's key, send participants the new thumbprint: each re-pins with `aaf init … --pin <new>` (and relying parties update `pin` and restart).

**Migration from earlier versions.** A participant's existing `~/.aaf/config.json` keeps working while the trust anchor key is unchanged, but discovery now verifies Subordinate Statements with that saved key rather than with whatever keys the trust anchor currently advertises. Re-running `aaf init <url> --pin <thumbprint>` saves just the pinned key.

Other intentional compatibility changes: trust on first use now saves only the key that signed (with its advertised `kid`), not every advertised key; an empty-string `pin` in a relying-party config, previously treated as no pin, is now refused; and a trust anchor whose `iss` is not an absolute URL equal to its `sub` is refused.

## 4. Verify participants

Each participant runs `aaf enroll` and sends you the `verification-request.json` file it writes. Check that the person and the claims are right, then record the verification:

```bash
docker compose -f deploy/docker-compose.yml exec -T federation node src/cli/aaf.js operator verify - < verification-request.json
```

From then on, the participant can register agents.

## 5. Demonstrate resolution (optional)

To show how a court order identifies the principal behind an agent, take a PPID from the shop's page:

```bash
docker compose -f deploy/docker-compose.yml exec federation node src/cli/aaf.js operator resolve <ppid> --case "pilot demonstration" --rp https://shop.example.org
```

The participant is notified that their agent was resolved, unless you add `--no-notify`. Each resolution is also logged in the registry's transparency log.

## Running it

| Task | Command |
|---|---|
| See status | `docker compose -f deploy/docker-compose.yml ps` |
| Follow logs | `docker compose -f deploy/docker-compose.yml logs -f federation` |
| Back up the federation's keys and records | `docker compose -f deploy/docker-compose.yml exec -T federation tar czf - -C /data . > federation-backup.tgz` |
| Update to newer code | `git pull`, then `docker compose -f deploy/docker-compose.yml up -d --build` (state is kept) |
| Restart | `docker compose -f deploy/docker-compose.yml restart` |

Back up after first start and regularly afterwards. The federation volume holds the only copies of the service keys. If they are lost, participants have to rejoin a new federation.

Backups contain private keys and participants' identity claims. Store them encrypted and delete them when the pilot ends.

## Ending the pilot

Tell participants first. Then stop everything and delete all data, including keys, records and certificates:

```bash
docker compose -f deploy/docker-compose.yml down -v
```

Delete any backups too. Participants can remove their local state with `rm -rf ~/.aaf`.

## Running without Docker

The same services run directly with Node.js 22 or later. Use any HTTPS reverse proxy that forwards each name to its port, as `deploy/Caddyfile` does:

```bash
AAF_CONFIG=config/federation.pilot.json AAF_STARTUP_TIMEOUT_SECONDS=120 npm start
```

```bash
node src/rp/standalone.js --config config/rp.pilot.json
```

Services listen on the ports in the config, on all interfaces if `listenHost` is `0.0.0.0`. They verify request signatures against the `publicUrl`, because that is the address callers sign. If the proxy serves a different name, every signed request fails.

## Adding more

- **A second registry or record keeper** on the same server is another entry in `config/federation.pilot.json`, plus a matching domain in `deploy/.env` and the `Caddyfile`. The local configuration (`config/federation.json`) shows a two-registry federation.
- **A service run by a different operator** on their own server is not automated yet. The trust anchor would need that service's public keys added to its records by hand.
- **Another relying party** can run anywhere: another copy of `config/rp.pilot.json` with its own id, domain and rules, pointing at the trust anchor.
