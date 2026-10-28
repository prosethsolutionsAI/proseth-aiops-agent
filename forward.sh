#!/bin/sh
# Proseth AIOps - send this Linux server's logs to its collector.
#
# Nothing is installed: it configures the log service the server already runs
# (rsyslog, or syslog-ng), and only if there is none installs rsyslog with the
# distro's own package manager. Works on Ubuntu, Debian, RHEL/Rocky/Alma, CentOS,
# Fedora, SUSE and Alpine. Run it again any time to change the level.
#
#   curl -fsSL <this file's raw URL> | sudo sh -s -- --collector 203.0.113.10
#
# Options:
#   --collector IP     the collector's address (required)
#   --port N           its syslog port (default 514)
#   --level LEVEL      send this level and worse: crit | err | warning (default)
#                      | notice | info | debug. Security logs (logins, sudo) are
#                      always sent from info up, so brute force is seen.
#   --app-log PATH     ALSO send an application's own log file (repeatable)
#   --app-name NAME    name for the --app-log before it (default: file name)
#   --remove           stop forwarding (removes only what this script added)
#
# Read it before you run it - that is why it is public.
set -u

IP=""; PORT=514; LVL=warning; REMOVE=0; APPS=""; NEXT_NAME=""
die() { echo "forward.sh: $*" >&2; exit 1; }
while [ $# -gt 0 ]; do
  case "$1" in
    --collector) IP="${2:-}"; shift 2 ;;
    --port) PORT="${2:-}"; shift 2 ;;
    --level) LVL="${2:-}"; shift 2 ;;
    --app-name) NEXT_NAME="${2:-}"; shift 2 ;;
    --app-log) APPS="$APPS ${2:-}|$NEXT_NAME"; NEXT_NAME=""; shift 2 ;;
    --remove) REMOVE=1; shift ;;
    -h|--help) sed -n '2,24p' "$0" 2>/dev/null || true; exit 0 ;;
    *) die "unknown option '$1' (see --help)" ;;
  esac
done
[ "$(id -u)" = 0 ] || die "run it with sudo"

restart() { systemctl restart "$1" 2>/dev/null || rc-service "$1" restart 2>/dev/null || service "$1" restart; }

if [ "$REMOVE" = 1 ]; then
  rm -f /etc/rsyslog.d/90-proseth-aiops.conf /etc/rsyslog.d/90-proseth-imfile.conf \
        /etc/rsyslog.d/91-proseth-app-*.conf /etc/syslog-ng/conf.d/90-proseth-aiops.conf
  command -v rsyslogd >/dev/null 2>&1 && restart rsyslog
  command -v syslog-ng >/dev/null 2>&1 && restart syslog-ng
  echo "OK: log forwarding to the collector removed"; exit 0
fi

echo "$IP" | grep -Eq '^[0-9A-Za-z.:-]+$' || die "--collector IP is required (the collector's address)"
echo "$PORT" | grep -Eq '^[0-9]+$' || die "--port must be a number"
case "$LVL" in crit|err|warning|notice|info|debug) ;; *) die "--level must be crit, err, warning, notice, info or debug" ;; esac

use_rsyslog() {
  # The chosen level for everything, PLUS security logs (auth/authpriv) from info
  # up - sshd logs a failed password at info. "@@" = TCP. Each line sent once.
  printf '*.%s;auth,authpriv.none @@%s:%s\nauth,authpriv.info @@%s:%s\n' \
    "$LVL" "$IP" "$PORT" "$IP" "$PORT" > /etc/rsyslog.d/90-proseth-aiops.conf
  for spec in $APPS; do
    path="${spec%%|*}"; name="${spec#*|}"
    [ -n "$name" ] || name=$(basename "$path" .log)
    tag="app-$(echo "$name" | tr 'A-Z' 'a-z' | tr -c 'a-z0-9-\n' '-' | cut -c1-30)"
    grep -rqs 'imfile' /etc/rsyslog.conf /etc/rsyslog.d/ \
      || echo 'module(load="imfile" PollingInterval="10")' > /etc/rsyslog.d/90-proseth-imfile.conf
    cat > "/etc/rsyslog.d/91-proseth-$tag.conf" <<EOF
input(type="imfile" File="$path" Tag="$tag:" Facility="local6" Severity="info")
if \$programname == '$tag' then @@$IP:$PORT
& stop
EOF
    if id syslog >/dev/null 2>&1 && command -v su >/dev/null 2>&1 \
       && ! su -s /bin/sh syslog -c "head -c1 '$path'" >/dev/null 2>&1; then
      echo "WARNING: rsyslog (user 'syslog') cannot read $path - give it read access, e.g. setfacl -m u:syslog:r '$path'"
    fi
    echo "OK: $path is sent as $tag"
  done
  restart rsyslog && echo "OK: rsyslog sends $LVL and worse (+ security logs) to $IP:$PORT"
}

if command -v rsyslogd >/dev/null 2>&1; then
  use_rsyslog
elif command -v syslog-ng >/dev/null 2>&1; then
  [ -z "$APPS" ] || echo "NOTE: --app-log needs rsyslog; on syslog-ng add a file() source by hand."
  SRC=$(sed -n 's/^[[:space:]]*source[[:space:]]\{1,\}\([A-Za-z_][A-Za-z0-9_]*\).*/\1/p' /etc/syslog-ng/syslog-ng.conf | head -1)
  [ -n "$SRC" ] || die "could not find the syslog-ng source name in /etc/syslog-ng/syslog-ng.conf"
  mkdir -p /etc/syslog-ng/conf.d
  printf 'filter f_proseth { level(%s..emerg) or (facility(auth, authpriv) and level(info..emerg)); };\ndestination d_proseth { network("%s" port(%s) transport("tcp")); };\nlog { source(%s); filter(f_proseth); destination(d_proseth); };\n' \
    "$LVL" "$IP" "$PORT" "$SRC" > /etc/syslog-ng/conf.d/90-proseth-aiops.conf
  grep -q 'conf.d' /etc/syslog-ng/syslog-ng.conf \
    || echo '@include "/etc/syslog-ng/conf.d/*.conf"' >> /etc/syslog-ng/syslog-ng.conf
  restart syslog-ng && echo "OK: syslog-ng sends $LVL and worse (+ security logs) to $IP:$PORT"
else
  echo "No rsyslog or syslog-ng - installing rsyslog..."
  (apt-get install -y rsyslog || dnf install -y rsyslog || yum install -y rsyslog \
     || zypper -n install rsyslog || apk add rsyslog) >/dev/null 2>&1 \
    || die "could not install rsyslog - install it, then run this again"
  use_rsyslog
fi
logger -p "user.$LVL" "Proseth AIOps: log forwarding test from $(hostname)" \
  && echo "Sent a test line - search for 'forwarding test' in Log search."
