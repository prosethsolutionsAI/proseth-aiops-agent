#!/usr/bin/env bash
#
# Proseth AIOps collector - turn an Ubuntu/Debian box at a customer site into a
# collector that dials OUT to the Proseth AIOps platform.
#
#   curl -fsSLO https://raw.githubusercontent.com/prosethsolutionsAI/proseth-aiops-agent/main/install.sh
#   sudo bash install.sh
#
# Unattended (the platform's "Copy install command" fills these in):
#   sudo AIOPS_NONINTERACTIVE=1 AIOPS_PLATFORM_HOST=203.0.113.10 AIOPS_PLATFORM_PORT=9443 \
#        AIOPS_COLLECTOR_NAME=acme-dc AIOPS_TOKEN=pax_... [AIOPS_ALERTS=1] bash install.sh
#
# Re-running is safe: it updates in place and keeps every existing answer.
# Nothing connects to this machine except (opt-in) the customer's own monitoring
# server on the alert port.
set -uo pipefail

SERVICE="proseth-aiops-agent"
PREFIX="/opt/proseth-aiops-agent"
CONFIG_DIR="/etc/proseth-aiops-agent"
CONFIG="$CONFIG_DIR/config.json"
STATE_DIR="/var/lib/proseth-aiops-agent"
RUN_USER="proseth-aiops"
REPO="https://github.com/prosethsolutionsAI/proseth-aiops-agent"
TARBALL="https://codeload.github.com/prosethsolutionsAI/proseth-aiops-agent/tar.gz/refs/heads/main"
DEFAULT_PORT=9443
DEFAULT_ALERT_PORT=9917

say()  { echo "==> $*"; }
ok()   { echo "    ok   $*"; }
warn() { echo "    !!   $*"; }
die()  { echo; echo "Stopped: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Run this with sudo."
NONINTERACTIVE="${AIOPS_NONINTERACTIVE:-}"

ask() {  # ask <prompt> <default> <var> [secret]
  local prompt="$1" default="$2" __var="$3" secret="${4:-}" reply=""
  if [ -n "$NONINTERACTIVE" ]; then printf -v "$__var" '%s' "$default"; return; fi
  if [ -n "$default" ] && [ -z "$secret" ]; then printf "  %s [%s]: " "$prompt" "$default"
  elif [ -n "$default" ]; then printf "  %s [(unchanged)]: " "$prompt"
  else printf "  %s: " "$prompt"; fi
  read -r reply
  printf -v "$__var" '%s' "${reply:-$default}"
}

cfg() { python3 -c "import json,sys;print(json.load(open('$CONFIG')).get(sys.argv[1],''))" "$1" 2>/dev/null || true; }

echo
echo "  Proseth AIOps collector setup"
echo "  This machine connects OUT to the platform. Nothing connects in."
echo

E_HOST=""; E_PORT=""; E_NAME=""; E_TOKEN=""; E_ALERT_SECRET=""; E_ALERT_PORT=""
if [ -f "$CONFIG" ]; then
  E_HOST=$(cfg platform_host); E_PORT=$(cfg platform_port); E_NAME=$(cfg collector_name)
  E_TOKEN=$(cfg token); E_ALERT_SECRET=$(cfg alert_secret); E_ALERT_PORT=$(cfg alert_port)
  say "Existing configuration found - press Enter to keep each value."
fi
E_HOST="${AIOPS_PLATFORM_HOST:-$E_HOST}"
E_PORT="${AIOPS_PLATFORM_PORT:-$E_PORT}"
E_NAME="${AIOPS_COLLECTOR_NAME:-$E_NAME}"
E_TOKEN="${AIOPS_TOKEN:-$E_TOKEN}"

say "Platform"
ask "Platform address (IP or name)" "$E_HOST" P_HOST
[ -n "$P_HOST" ] || die "The platform address is required."
ask "Collector port" "${E_PORT:-$DEFAULT_PORT}" P_PORT
case "$P_PORT" in (''|*[!0-9]*) die "'$P_PORT' is not a port." ;; esac
ask "Collector name (as created in the platform)" "${E_NAME:-$(hostname -s)}" C_NAME
ask "Token (pax_...)" "$E_TOKEN" C_TOKEN secret
case "$C_TOKEN" in pax_*) : ;; *) die "That is not a collector token - they start with 'pax_'." ;; esac

say "Alerts (optional)"
ALERT_SECRET="$E_ALERT_SECRET"; ALERT_PORT="${E_ALERT_PORT:-$DEFAULT_ALERT_PORT}"
if [ -n "$NONINTERACTIVE" ]; then
  case "${AIOPS_ALERTS:-}" in 1|y|yes|true) WANT=y ;; 0|n|no|false) WANT=n ;;
    *) [ -n "$ALERT_SECRET" ] && WANT=y || WANT=n ;; esac
else
  DEF=N; [ -n "$ALERT_SECRET" ] && DEF=Y
  printf "  Accept alerts from monitoring tools on this network? [%s]: " "$DEF"
  read -r WANT; WANT="${WANT:-$DEF}"
fi
case "${WANT,,}" in
  y|yes) ask "Alert port" "$ALERT_PORT" ALERT_PORT
         [ -n "$ALERT_SECRET" ] || { ALERT_SECRET="$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')"; NEW_SECRET=1; } ;;
  *) ALERT_SECRET="" ;;
esac

say "Checking this machine can reach $P_HOST:$P_PORT"
if timeout 8 bash -c "exec 3<>/dev/tcp/$P_HOST/$P_PORT" 2>/dev/null; then
  if curl -fsSk --max-time 8 "https://$P_HOST:$P_PORT/api/health" 2>/dev/null | grep -q proseth-aiops; then
    ok "reached the Proseth AIOps platform"
  else
    warn "something answered on $P_PORT, but it is not the platform (NAT pointing elsewhere?)"
  fi
else
  warn "could not open $P_HOST:$P_PORT - an outbound firewall rule is usually the cause"
  [ -n "$NONINTERACTIVE" ] || { printf "  Carry on anyway? [y/N]: "; read -r C; case "${C,,}" in y|yes) : ;; *) die "Nothing was changed." ;; esac; }
fi

say "Installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq python3 python3-venv python3-pip openssh-client ca-certificates curl >/dev/null 2>&1 \
  || die "Package installation failed. Check this machine can reach the Ubuntu archives."
ok "base packages"

resolve_source() {
  local here=""
  here="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
  if [ -n "$here" ] && [ -f "$here/proseth_aiops_agent/agent.py" ]; then SRC="$here"; return; fi
  say "Fetching the agent"
  FETCHED="$(mktemp -d)"
  curl -fsSL "$TARBALL" | tar -xz -C "$FETCHED" 2>/dev/null || die "Could not download the agent from $REPO."
  for cand in "$FETCHED"/*/; do
    [ -f "$cand/proseth_aiops_agent/agent.py" ] && SRC="${cand%/}" && break
  done
  [ -n "${SRC:-}" ] || die "The download did not contain the agent."
}
SRC=""; FETCHED=""
resolve_source
VERSION="$(sed -n 's/^VERSION = "\(.*\)"/\1/p' "$SRC/proseth_aiops_agent/agent.py" | head -1)"

say "Installing the agent $VERSION"
id -u "$RUN_USER" >/dev/null 2>&1 || useradd --system --home-dir "$STATE_DIR" --shell /usr/sbin/nologin "$RUN_USER"
install -d -m 755 "$PREFIX"
install -d -m 700 -o "$RUN_USER" -g "$RUN_USER" "$STATE_DIR"
# Stage, then swap: safe when SRC is PREFIX (setup re-runs from /opt), and a
# failed copy leaves the working agent in place.
STAGE="$(mktemp -d)"
cp -r "$SRC/proseth_aiops_agent" "$STAGE/" || die "Could not read the agent."
[ -d "$PREFIX/proseth_aiops_agent" ] && rm -r -- "$PREFIX/proseth_aiops_agent"
mv "$STAGE/proseth_aiops_agent" "$PREFIX/" || die "Could not install into $PREFIX."
rm -r -- "$STAGE"
[ "$SRC/install.sh" != "$PREFIX/install.sh" ] && cp "$SRC/install.sh" "$PREFIX/install.sh"
chown -R root:root "$PREFIX"
[ -x "$PREFIX/venv/bin/python" ] || python3 -m venv "$PREFIX/venv" || die "Could not create the venv."
"$PREFIX/venv/bin/pip" install -q --upgrade pip >/dev/null 2>&1
"$PREFIX/venv/bin/pip" install -q "websockets>=12" "paramiko>=3" "netmiko>=4.3" "pywinrm>=0.4.3" >/dev/null 2>&1 \
  || die "Could not install the Python dependencies (PyPI reachable?)."
ok "agent $VERSION"

say "Configuration"
install -d -m 750 -o root -g "$RUN_USER" "$CONFIG_DIR"
CA_LINE=""
if curl -fsSk --max-time 15 -o "$CONFIG_DIR/platform-ca.crt.new" "https://$P_HOST:$P_PORT/api/agent/ca.crt" \
   && grep -q "BEGIN CERTIFICATE" "$CONFIG_DIR/platform-ca.crt.new"; then
  mv "$CONFIG_DIR/platform-ca.crt.new" "$CONFIG_DIR/platform-ca.crt"; chmod 644 "$CONFIG_DIR/platform-ca.crt"
  CA_LINE="  \"ca_cert\": \"$CONFIG_DIR/platform-ca.crt\","
  ok "platform CA pinned (trust on first use) - fingerprint:"
  echo "         $(openssl x509 -noout -fingerprint -sha256 -in "$CONFIG_DIR/platform-ca.crt" 2>/dev/null | sed 's/^.*=//')"
else
  rm -f "$CONFIG_DIR/platform-ca.crt.new"
  warn "could not fetch the platform CA - traffic is encrypted but NOT authenticated until it is"
fi
ALERT_LINE=""
[ -n "$ALERT_SECRET" ] && ALERT_LINE="  \"alert_port\": $ALERT_PORT,
  \"alert_secret\": \"$ALERT_SECRET\","
cat > "$CONFIG" <<JSON
{
  "collector_name": "$C_NAME",
  "platform_host": "$P_HOST",
  "platform_port": $P_PORT,
  "tls": true,
$CA_LINE
$ALERT_LINE
  "token": "$C_TOKEN"
}
JSON
chown root:"$RUN_USER" "$CONFIG"; chmod 640 "$CONFIG"
ok "written to $CONFIG"

say "Commands and service"
cat > /usr/local/bin/proseth-aiops-agent <<EOF
#!/bin/sh
PYTHONPATH="$PREFIX" exec $PREFIX/venv/bin/python -m proseth_aiops_agent.agent "\$@"
EOF
cat > /usr/local/bin/proseth-aiops-setup <<EOF
#!/bin/sh
exec /bin/bash $PREFIX/install.sh "\$@"
EOF
cat > /usr/local/sbin/proseth-aiops-selfupdate <<'EOF'
#!/bin/bash
# Root-owned, no arguments: the ONE thing the agent may run with sudo. It hands
# the work to a transient unit so restarting the service cannot kill the update.
set -u
exec systemd-run --no-block --unit="proseth-aiops-update-$(date +%s)" /bin/bash -c \
  'T=$(mktemp -d); trap "rm -rf $T" EXIT; curl -fsSL https://codeload.github.com/prosethsolutionsAI/proseth-aiops-agent/tar.gz/refs/heads/main | tar -xz -C $T && D=$(find $T -maxdepth 1 -type d -name "proseth-aiops-agent-*" | head -1) && AIOPS_NONINTERACTIVE=1 bash $D/install.sh'
EOF
chmod 755 /usr/local/bin/proseth-aiops-agent /usr/local/bin/proseth-aiops-setup
chmod 755 /usr/local/sbin/proseth-aiops-selfupdate; chown root:root /usr/local/sbin/proseth-aiops-selfupdate
# Validated before it is installed: a broken sudoers file breaks sudo for everyone.
TMP_SUDO="$(mktemp)"
echo "$RUN_USER ALL=(root) NOPASSWD: /usr/local/sbin/proseth-aiops-selfupdate" > "$TMP_SUDO"
if visudo -cf "$TMP_SUDO" >/dev/null 2>&1; then
  install -m 440 -o root -g root "$TMP_SUDO" /etc/sudoers.d/proseth-aiops-agent; ok "one-click upgrade enabled"
else
  warn "sudoers entry did not validate - upgrade from the platform disabled"
fi
rm -f "$TMP_SUDO"

cat > /etc/systemd/system/$SERVICE.service <<EOF
[Unit]
Description=Proseth AIOps collector agent
After=network-online.target
Wants=network-online.target

[Service]
User=$RUN_USER
Group=$RUN_USER
Environment=PYTHONPATH=$PREFIX
Environment=HOME=$STATE_DIR
ExecStart=$PREFIX/venv/bin/python -m proseth_aiops_agent.agent
Restart=always
RestartSec=5
NoNewPrivileges=false

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null 2>&1
systemctl restart "$SERVICE"
ok "service $SERVICE started"
[ -n "$FETCHED" ] && rm -r -- "$FETCHED"

if [ -n "$ALERT_SECRET" ]; then
  ok "alerts accepted on port $ALERT_PORT  (POST http://<this machine>:$ALERT_PORT/alert/<zabbix|alertmanager|wazuh|generic>)"
  if [ -n "${NEW_SECRET:-}" ]; then
    echo
    echo "    Monitoring tools must send:  Authorization: Bearer <token>"
    echo "      $ALERT_SECRET"
    echo "    (shown again any time: sudo proseth-aiops-agent --alert-secret)"
  fi
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    warn "ufw is active - allow port $ALERT_PORT from the monitoring server only"
  fi
fi

say "Waiting for it to connect"
for _ in $(seq 1 15); do
  if journalctl -u "$SERVICE" --since "-1 min" -o cat 2>/dev/null | grep -q "Connected as"; then
    echo; echo "  Connected. Collector '$C_NAME' (agent $VERSION) is online."; echo; exit 0
  fi
  sleep 2
done
warn "not connected yet - see: journalctl -u $SERVICE -f"
