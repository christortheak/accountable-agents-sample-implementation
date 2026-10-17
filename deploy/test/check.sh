#!/bin/sh
# Check the pilot deployment on one machine before going live. Needs Docker with Compose, and curl.
#
# It runs the real image, Compose file and Caddyfile under made-up *.pilot.test names, with
# certificates from Caddy's own local CA, then walks through what a participant and the operator
# do (docs/PARTICIPATING.md, docs/DEPLOYING.md) and checks each step. Nothing is reachable beyond
# 127.0.0.1, and it uses its own Compose project (aaf-pilot-test), so it never touches a real pilot.
#
#   deploy/test/check.sh          run the check, then remove its containers and data
#   deploy/test/check.sh --keep   leave it running afterwards
#   deploy/test/check.sh --down   remove a run left behind by --keep or a failure
set -eu
cd "$(dirname "$0")/../.."

compose() { docker compose -p aaf-pilot-test -f deploy/docker-compose.yml -f deploy/test/docker-compose.test.yml "$@"; }
aaf() { compose run --rm -T participant "$@"; }
operator() { compose exec -T federation node src/cli/aaf.js operator "$@"; }
remove() { compose --profile participant down -v --remove-orphans; }

step() { printf '\n== %s\n' "$*"; }
ok() { printf '   ok: %s\n' "$*"; }
die() {
  printf '\n   FAILED: %s\n\n' "$*" >&2
  compose logs --tail 25 federation shop caddy >&2 || true
  printf '\nLeft running for inspection. Logs: docker compose -p aaf-pilot-test logs\nRemove it with: %s --down\n' "$0" >&2
  exit 1
}
# Retry a check once a second until it passes or the time runs out.
wait_for() {
  n=$1 what=$2
  shift 2
  until "$@" >/dev/null 2>&1; do
    n=$((n - 1))
    [ "$n" -gt 0 ] || die "$what did not come up in time"
    sleep 1
  done
}
# An HTTP status code through Caddy, as a browser on this machine would see it (-k: the local CA isn't trusted here).
status() { curl -sk -o /dev/null -w '%{http_code}' --resolve "$1:8443:127.0.0.1" "https://$1:8443$2"; }
started() { [ "$(compose logs federation 2>/dev/null | grep -c 'Federation running')" -ge "$1" ]; }
shop_up() { [ "$(status shop.pilot.test /)" = 200 ]; }
purchase() { aaf act helper https://shop.pilot.test commerce.purchase --params "{\"amount\":{\"value\":$1,\"currency\":\"USD\"},\"item\":\"a book\"}" --json; }
expect() {
  out=$(purchase "$2") || die "the $2 USD purchase failed to run: $out"
  printf '%s\n' "$out" | grep -q "\"decision\": \"$1\"" || die "expected $1 for $2 USD, got: $out"
  ok "$2 USD: $1"
}

keep=0
case "${1:-}" in
  --down) remove; exit 0 ;;
  --keep) keep=1 ;;
  '') ;;
  *) echo "usage: $0 [--keep | --down]" >&2; exit 2 ;;
esac

step "Generate the configs from the pilot templates (example.org -> pilot.test)"
mkdir -p deploy/test/out
sed 's/example\.org/pilot.test/g' config/federation.pilot.example.json > deploy/test/out/federation.pilot.json
sed 's/example\.org/pilot.test/g' config/rp.pilot.example.json > deploy/test/out/rp.pilot.json
ok "deploy/test/out/"

step "Build the image"
compose build federation

step "Start the federation, the shop and Caddy"
remove >/dev/null 2>&1 || true
compose up -d
wait_for 180 "the federation" started 1
wait_for 60 "the shop" shop_up
[ "$(compose exec -T federation id -u)" != 0 ] || die "the federation runs as root"
ok "running, as an unprivileged user"

step "Operator: print the trust anchor's key thumbprint"
thumb=$(operator thumbprint) || die "operator thumbprint"
ok "$thumb"

step "Participant: join, pinning that key"
aaf init https://federation.pilot.test --pin "$thumb" || die "aaf init"
if compose run --rm -T -e AAF_HOME=/tmp/aaf participant init https://federation.pilot.test --pin not-the-key >/dev/null 2>&1; then
  die "a wrong pin was accepted"
fi
ok "joined; a wrong pin is refused"

step "Participant: enroll; operator: verify them"
aaf enroll --name "Pilot Check" || die "aaf enroll"
compose run --rm -T --entrypoint cat participant /data/aaf/verification-request.json | operator verify - || die "operator verify"

step "Participant: register an agent and grant it purchases up to 50 USD"
aaf agent register helper || die "aaf agent register"
aaf grant helper commerce.purchase --max-amount 50:USD || die "aaf grant"

step "Participant: transact with the shop"
expect allow 12
expect step_up 30
aaf disclose --to https://shop.pilot.test --claims legal_name || die "aaf disclose"
expect allow 30
expect deny 60

step "Public pages, and operator endpoints blocked"
for host in federation registry records shop; do
  [ "$(status $host.pilot.test /)" = 200 ] || die "https://$host.pilot.test/ is not serving"
done
for host in federation registry records; do
  [ "$(status $host.pilot.test /admin/trust-marks)" = 404 ] || die "/admin is reachable on $host.pilot.test"
done
ok "all four status pages serve over HTTPS; /admin returns 404"

step "Operator: resolve the agent's identifier under a (demonstration) order"
ppid=$(purchase 5 | sed -n 's/.*"ppid": "\([^"]*\)".*/\1/p')
[ -n "$ppid" ] || die "no PPID in the shop's answer"
operator resolve "$ppid" --case "pilot check" --rp https://shop.pilot.test | grep -q "Pilot Check" || die "operator resolve"
ok "$ppid resolved to Pilot Check"

step "Restart everything: keys, registrations and grants survive"
compose restart
wait_for 180 "the restarted federation" started 2
wait_for 60 "the restarted shop" shop_up
[ "$(operator thumbprint)" = "$thumb" ] || die "the trust anchor's key changed on restart"
expect allow 12

step "All checks passed"
if [ "$keep" = 1 ]; then
  echo "Still running. Status pages: curl -k --resolve shop.pilot.test:8443:127.0.0.1 https://shop.pilot.test:8443/"
  echo "Remove it with: $0 --down"
else
  remove >/dev/null 2>&1
  echo "Removed the test containers and their data."
fi
