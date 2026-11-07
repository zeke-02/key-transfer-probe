#!/usr/bin/env bash
# Runs the live checks from a laptop. The laptop only ever sees proofs and sealed
# boxes, so it's in the same position as anyone watching the network.
#
#   ./check.sh transfer <a> <b>   a generates, b pulls, proofs must match
#   ./check.sh replay <a> <b>     a must refuse replayed and mismatched documents
#   ./check.sh refuse <a> <c>     c isn't the pinned release, so a must refuse it
#   ./check.sh restore <a> <b>    after redeploying a: a is empty, then pulls from b
set -euo pipefail

STATE=.check-state

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }

get() { curl -sS --max-time 120 "https://$1$2"; }
code() { curl -sS --max-time 120 -o /tmp/key-transfer-probe.out -w '%{http_code}' "$@"; }
post() { code -X POST -H 'Content-Type: application/json' "https://$1$2" -d "${3:-}"; }
body() { cat /tmp/key-transfer-probe.out; }
nonce() { openssl rand -hex 32; }

proofs_match() {
  local challenge left right
  challenge=$(nonce)
  left=$(get "$1" "/prove?challenge=$challenge" | jq -r '.proof // empty')
  right=$(get "$2" "/prove?challenge=$challenge" | jq -r '.proof // empty')
  [ -n "$left" ] && [ "$left" = "$right" ]
}

finish() {
  # finish <holder> <holder nonce> <doc file>
  jq -n --arg h "$2" --arg r "$(nonce)" --rawfile d <(base64 < "$3" | tr -d '\n') \
    '{holder_nonce: $h, requester_nonce: $r, document: $d}' > /tmp/key-transfer-probe.req
  code -X POST -H 'Content-Type: application/json' "https://$1/transfer/finish" \
    --data-binary @/tmp/key-transfer-probe.req
}

case "${1:-}" in
  transfer)
    a=$2 b=$3
    status=$(post "$a" /generate)
    [ "$status" = 200 ] || fail "generate answered $status: $(body)"
    status=$(post "$b" /pull "{\"peer\":\"$a\"}")
    [ "$status" = 200 ] || fail "pull answered $status: $(body)"
    body | jq .
    proofs_match "$a" "$b" || fail "proofs differ"
    get "$a" /status | jq -r .transfer_key_fp > "$STATE"
    pass "$b holds the key $a generated"
    ;;
  replay)
    a=$2 b=$3
    doc=$(mktemp)
    # A genuine document from b, bound to a nonce a never issued for this exchange.
    curl -sS --max-time 120 -o "$doc" "https://$b/attest?nonce=$(nonce)"
    status=$(post "$a" /transfer/begin)
    [ "$status" = 200 ] || fail "begin answered $status: $(body)"
    held=$(body | jq -r .holder_nonce)
    status=$(finish "$a" "$held" "$doc")
    [ "$status" = 403 ] || fail "document for another nonce answered $status: $(body)"
    pass "document for another nonce refused: $(body | jq -r .error)"

    status=$(post "$a" /transfer/begin)
    held=$(body | jq -r .holder_nonce)
    curl -sS --max-time 120 -o "$doc" "https://$b/attest?nonce=$held"
    status=$(finish "$a" "$held" "$doc")
    [ "$status" = 200 ] || fail "genuine document answered $status: $(body)"
    pass "genuine document accepted, and the laptop got only a sealed box"
    status=$(finish "$a" "$held" "$doc")
    [ "$status" = 403 ] || fail "second use of a nonce answered $status: $(body)"
    pass "second use of a nonce refused: $(body | jq -r .error)"
    ;;
  refuse)
    a=$2 c=$3
    status=$(post "$c" /pull "{\"peer\":\"$a\"}")
    [ "$status" != 200 ] || fail "$c was given the key"
    body | grep -q 'refused at verify' || fail "failed for another reason ($status): $(body)"
    [ "$(get "$c" "/prove?challenge=x" | jq -r '.proof // empty')" = "" ] || fail "$c can prove the key"
    pass "$c refused: $(body | jq -r .error)"
    ;;
  restore)
    a=$2 b=$3
    fp=$(get "$a" /status | jq -r .transfer_key_fp)
    [ -f "$STATE" ] || fail "run transfer first, so there's an old key to compare"
    [ "$fp" != "$(cat "$STATE")" ] || fail "$a kept its attested key, so it wasn't a full redeploy"
    [ "$(get "$a" /status | jq -r .has_key)" = false ] || fail "$a still has the key"
    pass "$a came back empty with a new attested key"
    status=$(post "$a" /pull "{\"peer\":\"$b\"}")
    [ "$status" = 200 ] || fail "pull answered $status: $(body)"
    proofs_match "$a" "$b" || fail "proofs differ after restore"
    pass "$a restored the original key from $b"
    ;;
  *)
    sed -n 2,9p "$0"
    exit 2
    ;;
esac
