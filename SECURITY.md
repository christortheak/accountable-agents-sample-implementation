# Security

This is a **reference implementation for research and discussion**, not production software. It exists to show that the Accountable Agents Framework can be built from existing standards, and to let people test it in a small pilot.

## Known limitations

- Replay protection is held in memory and resets when a service restarts.
- Service keys are stored on disk unencrypted and cannot be rotated.
- There is no rate limiting or abuse protection.
- Identity verification is simulated, or done by hand by a pilot's operator. It is not a KYC check.
- In ephemeral mode, relying parties cannot link an agent's presentations, but the registry could (blind credentials are not implemented).
- Logs use RFC 9162 Merkle trees with JSON receipts, not IETF SCITT, and nobody independently witnesses the registry's log.
- The simulator's passkeys come from a software authenticator that sets "user verified" without a person present. The browser demo uses real passkeys.
- Operator endpoints (`/admin/*`) are protected only by a bearer token. Public deployments must block them at the proxy, as `deploy/Caddyfile` does.

The specification lists these and other design limits in §16.

## Secrets

Generated keys, admin tokens and service state live in `data/`, which is git-ignored. A deployment's own configuration (`deploy/.env`, `config/*.pilot.json`) and participants' state (`~/.aaf`) are never committed either. If you find anything secret in the repository, please report it.

## Reporting a problem

Please use GitHub's private vulnerability reporting: the repository's **Security** tab, then **Report a vulnerability**. Don't open a public issue. We will acknowledge reports as soon as we can.
