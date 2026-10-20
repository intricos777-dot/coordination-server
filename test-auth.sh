#!/usr/bin/env bash
# Watermark: Living_Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
TID="test-fixture-$$"
# Verify the credential gate. Every assertion is an observed HTTP status.
set -uo pipefail
B=http://127.0.0.1:4126
ENV=/home/livings/.config/coordination-server/coordination-server.env
ADMIN=$(grep '^COORD_ADMIN_TOKEN=' "$ENV" | cut -d= -f2-)
pass=0; fail=0
# The hub rate-limits /api/ at 100 requests per 60s window. This suite makes
# ~25 calls, so back-to-back runs trip the limiter and later assertions get
# 429 instead of the status they are actually testing. Wait out a window a
# prior run opened rather than weakening assertions to accept 429.
sleep "${RATE_WAIT:-0}"
chk() { # label expected actual
  if [ "$2" = "$3" ]; then echo "  [PASS] $1 -> $3"; pass=$((pass+1))
  else echo "  [FAIL] $1 -> got $3, want $2"; fail=$((fail+1)); fi
}
code() { curl -s -m 10 -o /dev/null -w '%{http_code}' "$@"; }

echo "=== 1. the original attack must now fail ==="
chk "invented agent + nonsense secret" 403 \
  "$(code -X POST $B/api/auth/token -H 'Content-Type: application/json' \
      -d '{"agentId":"totally-made-up-agent","secret":"literally-anything"}')"
chk "no secret at all" 400 \
  "$(code -X POST $B/api/auth/token -H 'Content-Type: application/json' \
      -d '{"agentId":"another-fake"}')"

echo
echo "=== 2. data routes must reject anonymous callers ==="
for p in /api/agents /api/sessions /api/capabilities /api/federation/peers; do
  chk "GET $p anonymous" 401 "$(code $B$p)"
done
chk "GET /api/agents with junk bearer" 401 \
  "$(code $B/api/agents -H 'Authorization: Bearer not-a-real-token')"

echo
echo "=== 3. /health and /api/auth stay open ==="
chk "GET /health" 200 "$(code $B/health)"

echo
echo "=== 4. admin enrolment ==="
chk "enrol without admin token" 401 \
  "$(code -X POST $B/admin/agents/enroll -H 'Content-Type: application/json' \
      -d '{"agentId":"$TID"}')"
chk "enrol with wrong admin token" 401 \
  "$(code -X POST $B/admin/agents/enroll -H 'X-Admin-Token: wrong' \
      -H 'Content-Type: application/json' -d '{"agentId":"$TID"}')"

ENROLLED=$(curl -s -m 10 -X POST $B/admin/agents/enroll \
  -H "X-Admin-Token: $ADMIN" -H 'Content-Type: application/json' \
  -d "{\"agentId\":\"$TID\",\"capabilities\":[\"message\",\"session\"]}")
echo "  enrol response keys: $(echo "$ENROLLED" | tr ',' '\n' | cut -d: -f1 | tr -d ' "{' | tr '\n' ' ')"
SECRET=$(echo "$ENROLLED" | sed -n 's/.*"secret":"\([^"]*\)".*/\1/p')
if [ -n "$SECRET" ]; then echo "  [PASS] secret returned once (len ${#SECRET})"; pass=$((pass+1))
else echo "  [FAIL] no secret in enrol response"; fail=$((fail+1)); fi

echo
echo "=== 5. enrolled agent: wrong secret refused, right secret accepted ==="
# The wrong secret must be >= 32 chars and multi-class, or the strength gate
# rejects it as a malformed request (400) before credential verification (401)
# is ever reached. Both refusals are correct; these assert each path.
chk "wrong secret (valid shape)" 401 \
  "$(code -X POST $B/api/auth/token -H 'Content-Type: application/json' \
      -d "{\"agentId\":\"$TID\",\"secret\":\"WrongSecret-Value-Entirely-XY9\"}")"
chk "short/weak secret rejected as malformed" 400 \
  "$(code -X POST $B/api/auth/token -H 'Content-Type: application/json' \
      -d "{\"agentId\":\"$TID\",\"secret\":\"tooshort\"}")"
chk "right secret" 200 \
  "$(code -X POST $B/api/auth/token -H 'Content-Type: application/json' \
      -d "{\"agentId\":\"$TID\",\"secret\":\"$SECRET\"}")"

TOKJSON=$(curl -s -m 10 -X POST $B/api/auth/token -H 'Content-Type: application/json' \
  -d "{\"agentId\":\"$TID\",\"secret\":\"$SECRET\"}")
TOKEN=$(echo "$TOKJSON" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
echo "  token minted: ${#TOKEN} chars"

echo
echo "=== 6. authenticated access works ==="
chk "GET /api/agents with token" 200 "$(code $B/api/agents -H "Authorization: Bearer $TOKEN")"
chk "GET /api/sessions with token" 200 "$(code $B/api/sessions -H "Authorization: Bearer $TOKEN")"
chk "POST /api/auth/verify" 200 \
  "$(code -X POST $B/api/auth/verify -H "Authorization: Bearer $TOKEN" -d '{}')"

echo
echo "=== 7. secrets are NOT stored in plaintext ==="
REG=/home/livings/var/lib/coordination-server/agent-credentials.json
if [ -f "$REG" ]; then
  if grep -qF "$SECRET" "$REG" 2>/dev/null; then
    echo "  [FAIL] plaintext secret found in registry"; fail=$((fail+1))
  else
    echo "  [PASS] registry holds no plaintext secret"; pass=$((pass+1))
  fi
  echo "  registry perms: $(stat -c '%a %U' "$REG")"
  echo "  registry entries: $(grep -c '"hash"' "$REG")"
else
  echo "  [FAIL] registry not created at $REG"; fail=$((fail+1))
fi

echo
echo "=== 8. disable takes effect immediately ==="
curl -s -m 10 -X POST "$B/admin/agents/$TID/disable" -H "X-Admin-Token: $ADMIN" >/dev/null
chk "disabled agent rejected at token" 401 \
  "$(code -X POST $B/api/auth/token -H 'Content-Type: application/json' \
      -d "{\"agentId\":\"$TID\",\"secret\":\"$SECRET\"}")"
chk "already-issued token now rejected" 401 "$(code $B/api/agents -H "Authorization: Bearer $TOKEN")"
curl -s -m 10 -X POST "$B/admin/agents/$TID/enable" -H "X-Admin-Token: $ADMIN" >/dev/null
chk "re-enabled agent works again" 200 \
  "$(code -X POST $B/api/auth/token -H 'Content-Type: application/json' \
      -d "{\"agentId\":\"$TID\",\"secret\":\"$SECRET\"}")"

echo
echo "=== 9. clean up the fixture agent ==="
curl -s -m 10 -X DELETE "$B/admin/agents/$TID" -H "X-Admin-Token: $ADMIN" >/dev/null
# A removed agent is now simply unknown, so the token route answers 403
# (unknown-agent) — not 401 and not 404. Either way it cannot get a token.
chk "fixture removed, can no longer authenticate" 403 \
  "$(code -X POST $B/api/auth/token -H 'Content-Type: application/json' \
      -d "{\"agentId\":\"$TID\",\"secret\":\"$SECRET\"}")"

echo
echo "PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ]
