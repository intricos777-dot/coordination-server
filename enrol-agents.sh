#!/usr/bin/env bash
# Enrol the real agents and drop each secret into a 0600 config.
# Secrets are shown once by the server; this writes them straight to disk
# and never echoes them to the terminal.
set -euo pipefail
B=http://127.0.0.1:4126
ENV=/home/livings/.config/coordination-server/coordination-server.env
CONF=/home/livings/.config/coordination-server/agents
ADMIN=$(grep '^COORD_ADMIN_TOKEN=' "$ENV" | cut -d= -f2-)
mkdir -p "$CONF"; chmod 700 "$CONF"

CAPS='["message","session","capability:issue","capability:delegate","federation"]'

for a in hermes opencode; do
  echo "=== $a ==="
  # remove the test-fixture agent if present, so we start from known state
  curl -s -m 10 -X DELETE "$B/admin/agents/$a" -H "X-Admin-Token: $ADMIN" >/dev/null 2>&1 || true

  RESP=$(curl -s -m 10 -X POST "$B/admin/agents/enroll" \
    -H "X-Admin-Token: $ADMIN" -H 'Content-Type: application/json' \
    -d "{\"agentId\":\"$a\",\"capabilities\":$CAPS}")
  SECRET=$(printf '%s' "$RESP" | sed -n 's/.*"secret":"\([^"]*\)".*/\1/p')
  if [ -z "$SECRET" ]; then echo "  FAILED to enrol: $RESP"; exit 1; fi

  umask 077
  cat > "$CONF/$a.env" <<EOF
# Coordination hub credential for agent '$a'.
# 0600, outside every git repository. Never commit.
COORD_AGENT_ID=$a
COORD_AGENT_SECRET=$SECRET
COORD_LISTEN_URL=ws://127.0.0.1:4126/ws
EOF
  chmod 600 "$CONF/$a.env"

  # prove the credential actually works, without printing the secret
  CODE=$(curl -s -m 10 -o /dev/null -w '%{http_code}' -X POST "$B/api/auth/token" \
    -H 'Content-Type: application/json' \
    -d "{\"agentId\":\"$a\",\"secret\":\"$SECRET\"}")
  echo "  enrolled; stored $CONF/$a.env ($(stat -c '%a' "$CONF/$a.env"))"
  echo "  token request with stored secret -> HTTP $CODE"
done

echo
echo "=== enrolled agents ==="
curl -s -m 10 "$B/admin/agents" -H "X-Admin-Token: $ADMIN" \
  | tr ',' '\n' | grep -E 'agentId|capabilities|selfRegister' | head -12
