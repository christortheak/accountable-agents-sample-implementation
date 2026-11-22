# Security

This is a **sample implementation for research and discussion**, not production software. It exists to show that the Accountable Agents Framework can be built from existing standards, and to let people test it in a small pilot.

## Known limitations

- Replay protection is held in memory and resets when a service restarts.
- Service keys are stored on disk unencrypted and cannot be rotated.
- There is no rate limiting or abuse protection.
- Identity verification is simulated, or done by hand by a pilot's operator. It is not a KYC check.
- With single-use IDs, counterparties cannot link an agent's presentations, but the directory could. It issues each ID on demand for a named counterparty, so it also learns which services an agent uses (blind credentials and batch issuance are not implemented).
- The rule for "one principal record per verified identity" keys people by name, jurisdiction and date of birth. That shows where the rule sits; it is not strong enough for real use.
- Legal orders are checked for a designated authority's signature, but anyone holding a valid order can submit it.
- Logs use RFC 9162 Merkle trees with JSON receipts, not IETF SCITT, and nobody independently witnesses the directory's log.
- The simulator's passkeys come from a software authenticator that sets "user verified" without a person present. The browser demo uses real passkeys.
- Operator endpoints (`/admin/*`) are protected only by a bearer token. Public deployments must block them at the proxy, as `deploy/Caddyfile` does.

The specification lists these and other design limits in §16.

## Secrets

Generated keys, admin tokens and service state live in `data/`, which is git-ignored. A deployment's own configuration (`deploy/.env`, `config/*.pilot.json`) and participants' state (`~/.aaf`) are never committed either. If you find anything secret in the repository, please report it.

## Reporting a problem

Please use GitHub's private vulnerability reporting: the repository's **Security** tab, then **Report a vulnerability**. Don't open a public issue. We will acknowledge reports as soon as we can.
