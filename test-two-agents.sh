#!/usr/bin/env bash
# Watermark: Living_Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
# Copyright (c) 2026 Living Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
# Licensed under Living Sin Proprietary License (LSPL-1.0)
# See LICENSE file for details.
# End-to-end: prove hermes and opencode can each authenticate, and that a
# session/message flow works between them. Prints no secret.
set -uo pipefail
B=http://127.0.0.1:4126
CONF=/home/livings/.config/coordination-server/agents
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1 -> $3"; pass=$((pass+1));
        else echo "  [FAIL] $1 -> got $3 want $2"; fail=$((fail+1)); fi; }

tok() { # agent -> token
  local a=$1 s
  s=$(grep '^COORD_AGENT_SECRET=' "$CONF/$a.env" | cut -d= -f2-)
  curl -s -m 10 -X POST "$B/api/auth/token" -H 'Content-Type: application/json' \
    -d "{\"agentId\":\"$a\",\"secret\":\"$s\"}" \
    | sed -n 's/.*"token":"\([^"]*\)".*/\1/p'
}

echo "=== both agents authenticate independently ==="
TH=$(tok hermes);   TO=$(tok opencode)
chk "hermes token"   "yes" "$([ -n "$TH" ] && echo yes || echo no)"
chk "opencode token" "yes" "$([ -n "$TO" ] && echo yes || echo no)"
[ "$TH" != "$TO" ] && echo "  [PASS] tokens are distinct" && pass=$((pass+1)) \
                   || { echo "  [FAIL] tokens identical"; fail=$((fail+1)); }

echo
echo "=== each can read coordination state ==="
for pair in "hermes:$TH" "opencode:$TO"; do
  a=${pair%%:*}; t=${pair#*:}
  chk "$a GET /api/agents"   200 "$(curl -s -m 10 -o /dev/null -w '%{http_code}' $B/api/agents -H "Authorization: Bearer $t")"
  chk "$a GET /api/sessions" 200 "$(curl -s -m 10 -o /dev/null -w '%{http_code}' $B/api/sessions -H "Authorization: Bearer $t")"
done

echo
echo "=== session visibility: hermes creates one over the WebSocket, opencode reads over REST ==="
# NOTE: there is no POST /api/sessions. Sessions are created by an agent
# connecting on the WebSocket and sending a 'create_session' frame; the REST
# side is read-only. So exercise the real path.
node test-ws-session.mjs 2>&1 | sed 's/^/  /'
WSRC=$?
if [ "$WSRC" -eq 0 ]; then pass=$((pass+2)); else fail=$((fail+1)); fi

echo
echo "=== cross-agent auth is still required ==="
chk "opencode token on a new session list" 200 \
  "$(curl -s -m 10 -o /dev/null -w '%{http_code}' $B/api/sessions -H "Authorization: Bearer $TO")"
chk "no token rejected" 401 \
  "$(curl -s -m 10 -o /dev/null -w '%{http_code}' $B/api/sessions)"

echo
echo "PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ]
