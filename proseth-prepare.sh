#!/bin/bash
# Proseth - one installer for every Proseth service on a Linux server.
#
# It asks which product the customer uses NOW and switches that one on; every
# other product is installed READY - sending nothing, enrolled nowhere - so an
# engineer can switch it on later with one command and the collector's address,
# with no internet needed at that point.
#
#   curl -fsSL <this file's raw URL> | sudo bash
#
# Without questions (all optional; anything missing is asked for):
#   --now aiops|agentic|both|none        the product(s) to switch on now
#   --aiops-collector IP  [--level L]    Proseth AIOps collector (level default warning)
#   --agentic-collector IP --group G     PSCyber Agentic SOC site collector and agent group
#                                        (the enrolment password is asked, or PSCYBER_ENROLL_PASSWORD)
#
# Later:
#   sudo proseth-ready status
#   sudo proseth-ready aiops   --collector <AIOPS_COLLECTOR_IP>
#   sudo proseth-ready agentic --collector <PSCYBER_COLLECTOR_IP> --group <GROUP>
#   sudo proseth-ready uninstall          (everything; remove the agent in the SOC too)
#
# What "ready" means:
#   Proseth AIOps        rsyslog present + the 'proseth-aiops-forward' script kept.
#   PSCyber Agentic SOC  the Wazuh agent installed STOPPED and DISABLED, pointed at
#                        nothing, + the 'pscyber-agent' script kept.
# The two never conflict on a server (different files, different ports).
# This file is identical in the proseth-aiops-agent and pscyber-site-onboarding
# repositories. Read it before you run it - that is why it is public.
set -uo pipefail

AIOPS_URL="https://raw.githubusercontent.com/prosethsolutionsAI/proseth-aiops-agent/main/forward.sh"
AGENTIC_URL="https://raw.githubusercontent.com/prosethsolutionsAI/pscyber-site-onboarding/main/agents/install-agent-linux.sh"
WRAPPER=/usr/local/sbin/proseth-ready
NOW=""; AIOPS_IP=""; LEVEL=warning; AGENTIC_IP=""; GROUP=""

die() { echo "proseth-prepare: $*" >&2; exit 1; }
while [ $# -gt 0 ]; do
  case "$1" in
    --now) NOW="${2:-}"; shift 2 ;;
    --aiops-collector) AIOPS_IP="${2:-}"; shift 2 ;;
    --level) LEVEL="${2:-}"; shift 2 ;;
    --agentic-collector) AGENTIC_IP="${2:-}"; shift 2 ;;
    --group) GROUP="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,/^set -uo/p' "$0" 2>/dev/null; exit 0 ;;
    *) die "unknown option '$1' (see --help)" ;;
  esac
done
[ "$(id -u)" = 0 ] || die "run it with sudo"
command -v curl >/dev/null 2>&1 || die "curl is needed for this one-time step"

# Questions come from the TERMINAL: piped from curl, stdin is this script.
ask() {  # $1 prompt, $2 variable
  { [ -r /dev/tty ] && read -r -p "  $1: " "$2" </dev/tty; } 2>/dev/null \
    || die "$1 - no terminal to ask on; pass it as an option (see --help)"
}
pick=""

if [ -z "$NOW" ]; then
  echo "Which Proseth product does this customer use NOW? (the others are installed ready, switched off)"
  echo "  1) Proseth AIOps"
  echo "  2) PSCyber Agentic SOC"
  echo "  3) both"
  echo "  4) none yet - just get the server ready"
  ask "Choose 1-4" pick
  case "$pick" in 1) NOW=aiops ;; 2) NOW=agentic ;; 3) NOW=both ;; 4) NOW=none ;; *) die "choose 1, 2, 3 or 4" ;; esac
fi
case "$NOW" in aiops|agentic|both|none) ;; *) die "--now must be aiops, agentic, both or none" ;; esac
on() { [ "$NOW" = both ] || [ "$NOW" = "$1" ]; }
if on aiops && [ -z "$AIOPS_IP" ]; then ask "Proseth AIOps collector IP" AIOPS_IP; fi
if on agentic; then
  [ -n "$AGENTIC_IP" ] || ask "PSCyber Agentic site collector IP" AGENTIC_IP
  [ -n "$GROUP" ] || ask "PSCyber agent group (the customer's Onboarding tab shows it)" GROUP
fi

work=$(mktemp -d) || die "no temp dir"
trap 'rm -rf "$work"' EXIT
FAILED=""

# Each script is downloaded to a FILE and run from it (not piped), so it keeps a
# copy of itself for switching on later without internet.
prepare() {  # $1 name, $2 url, $3 interpreter
  echo; echo "=== $1: getting ready"
  if ! curl -fsSL "$2" -o "$work/$1.sh"; then echo "could not download $2"; FAILED="$FAILED $1"; return; fi
  "$3" "$work/$1.sh" --prepare || FAILED="$FAILED $1"
}
prepare aiops "$AIOPS_URL" sh
prepare agentic "$AGENTIC_URL" bash

cat > "$WRAPPER.new" <<'EOF'
#!/bin/sh
# Proseth: one place to see and switch on what this server is ready for.
case "${1:-status}" in
  status)
    printf 'Proseth AIOps        '
    if [ -x /usr/local/sbin/proseth-aiops-forward ]; then /usr/local/sbin/proseth-aiops-forward --status; else echo "not prepared"; fi
    printf 'PSCyber Agentic SOC  '
    if [ -x /usr/local/sbin/pscyber-agent ]; then /usr/local/sbin/pscyber-agent --status | head -1; else echo "not prepared"; fi ;;
  aiops)   shift; exec /usr/local/sbin/proseth-aiops-forward "$@" ;;
  agentic) shift; exec /usr/local/sbin/pscyber-agent "$@" ;;
  uninstall)
    [ -x /usr/local/sbin/proseth-aiops-forward ] && /usr/local/sbin/proseth-aiops-forward --uninstall
    [ -x /usr/local/sbin/pscyber-agent ] && /usr/local/sbin/pscyber-agent --uninstall
    rm -f "$0"; echo "Proseth removed from this server." ;;
  *) echo "usage: proseth-ready status | uninstall"
     echo "       proseth-ready aiops   --collector IP [--level warning] | --status | --remove | --update | --uninstall"
     echo "       proseth-ready agentic --collector IP --group GROUP     | --status | --uninstall"
     exit 2 ;;
esac
EOF
chmod 755 "$WRAPPER.new" && mv -f "$WRAPPER.new" "$WRAPPER"

# Switch on what the customer uses now - through the kept copies, exactly as an
# engineer would later.
if on aiops && [[ "$FAILED" != *aiops* ]]; then
  echo; echo "=== aiops: switching on"
  "$WRAPPER" aiops --collector "$AIOPS_IP" --level "$LEVEL" || FAILED="$FAILED aiops-on"
fi
if on agentic && [[ "$FAILED" != *agentic* ]]; then
  echo; echo "=== agentic: switching on"
  "$WRAPPER" agentic --collector "$AGENTIC_IP" --group "$GROUP" || FAILED="$FAILED agentic-on"
fi

echo; echo "=== summary"
"$WRAPPER" status
echo
echo "Switch on later (no internet needed):"
echo "  sudo proseth-ready aiops   --collector <AIOPS_COLLECTOR_IP>"
echo "  sudo proseth-ready agentic --collector <PSCYBER_COLLECTOR_IP> --group <GROUP>"
[ -z "$FAILED" ] || die "something did not finish:$FAILED - see the messages above, fix, and run this again"
