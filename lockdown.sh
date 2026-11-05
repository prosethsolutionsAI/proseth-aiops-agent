#!/bin/bash
# @PRODUCT@ - LOGIN LOCKDOWN for the machine this agent runs on.
#
# Root-owned. The agent may run it through sudo with ONE argument and nothing
# else: on | off | status. (`reapply` is for the boot unit only.) The one piece of
# text that reaches it - the contact line on the banner - is read from a file the
# agent writes and cut to 200 printable characters.
#
# on   = nobody can log in, by any route that asks a login question:
#        SSH        a drop-in (or a block on top of sshd_config) with DenyUsers *,
#                   so KEYS are refused too; the banner is shown before auth.
#                   `sshd -t` first - a config sshd rejects is never loaded.
#        console    /etc/nologin carries the banner: every PAM login path that
#                   includes pam_nologin (tty, serial, hypervisor console, cockpit)
#                   refuses non-root accounts.
#        root       its password is locked (no console / emergency-mode root) and
#                   console AUTOLOGIN overrides are set aside - no break glass.
#        sessions   people already logged in are logged out.
#        reboot     a boot unit re-applies it (systemd clears /etc/nologin at boot).
# off  = every one of those put back exactly as it was before `on`.
set -u
PRODUCT="@PRODUCT@"
NAME="@NAME@"
CONTACT_FILE="@CONTACT_FILE@"
STATE="/var/lib/$NAME-lockdown"
MAIN=/etc/ssh/sshd_config
DROP="/etc/ssh/sshd_config.d/00-$NAME-lockdown.conf"
BANNER="/etc/$NAME-lockdown.banner"
START="# $NAME-lockdown start - set by the $PRODUCT platform, removed by it"
END="# $NAME-lockdown end"
UNIT="/etc/systemd/system/$NAME-lockdown.service"
umask 022
mkdir -p "$STATE" && chmod 700 "$STATE"

die() { echo "error: $*"; exit 1; }
contact() { [ -r "$CONTACT_FILE" ] && head -c 400 "$CONTACT_FILE" | LC_ALL=C tr -cd '[:print:]' | cut -c1-200; }
sshd_bin() { command -v sshd 2>/dev/null || echo /usr/sbin/sshd; }
has_sshd() { [ -f "$MAIN" ] && [ -x "$(sshd_bin)" ]; }
reload_sshd() {
  systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null \
    || systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
}
uses_dropins() { [ -d /etc/ssh/sshd_config.d ] && grep -qiE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' "$MAIN" 2>/dev/null; }

write_banner() {
  local c; c="$(contact)"
  {
    echo "****************************************************************************"
    echo "  LOGIN DISABLED"
    echo
    echo "  This machine is a $PRODUCT agent, managed ONLY from the $PRODUCT platform."
    echo "  Interactive login has been disabled by a $PRODUCT administrator."
    [ -n "$c" ] && echo "  Contact: $c"
    echo "****************************************************************************"
  } > "$BANNER"
  chmod 644 "$BANNER"
}

ssh_files_off() {
  rm -f "$DROP"
  if grep -qF "$START" "$MAIN" 2>/dev/null; then
    awk -v s="$START" -v e="$END" '$0==s{skip=1;next} skip&&$0==e{skip=0;next} !skip' "$MAIN" > "$MAIN.$NAME.tmp" \
      && cat "$MAIN.$NAME.tmp" > "$MAIN"; rm -f "$MAIN.$NAME.tmp"
  fi
}
ssh_on() {
  has_sshd || return 0
  local block out
  block="$START
DenyUsers *
DenyGroups *
PermitRootLogin no
Banner $BANNER
$END"
  if uses_dropins; then
    printf '%s\n' "$block" > "$DROP"; chmod 644 "$DROP"
  elif ! grep -qF "$START" "$MAIN"; then
    # sshd takes the FIRST value of a keyword, so the block goes on top of the file.
    { printf '%s\n' "$block"; cat "$MAIN"; } > "$MAIN.$NAME.tmp" && cat "$MAIN.$NAME.tmp" > "$MAIN"; rm -f "$MAIN.$NAME.tmp"
  fi
  if ! out="$("$(sshd_bin)" -t 2>&1)"; then
    ssh_files_off
    die "sshd rejected the lockdown settings - nothing was changed: $out"
  fi
  reload_sshd
}
ssh_off() {
  has_sshd || return 0
  local out
  ssh_files_off
  # Unlocking must never stop half way: report it, and the other steps still run.
  if ! out="$("$(sshd_bin)" -t 2>&1)"; then OFF_ERR="sshd's own config does not validate (ours is removed; fix it at the console): $out"; return 0; fi
  reload_sshd
}

nologin_on() {
  if [ -f /etc/nologin ] && ! grep -q "$NAME-lockdown" /etc/nologin && [ ! -f "$STATE/nologin.before" ]; then
    cp -p /etc/nologin "$STATE/nologin.before"
  fi
  { cat "$BANNER"; echo "($NAME-lockdown)"; } > /etc/nologin
  chmod 644 /etc/nologin
}
nologin_off() {
  grep -q "$NAME-lockdown" /etc/nologin 2>/dev/null && rm -f /etc/nologin
  [ -f "$STATE/nologin.before" ] && mv "$STATE/nologin.before" /etc/nologin
  return 0
}

root_on() {
  [ -f "$STATE/root.before" ] || passwd -S root 2>/dev/null | awk '{print $2}' > "$STATE/root.before"
  passwd -l root >/dev/null 2>&1 || usermod -L root >/dev/null 2>&1
}
root_off() {
  local b; b="$(cat "$STATE/root.before" 2>/dev/null)"
  rm -f "$STATE/root.before"
  case "$b" in P|PS) passwd -u root >/dev/null 2>&1 || usermod -U root >/dev/null 2>&1 ;; esac
  return 0
}

# A getty drop-in with --autologin logs someone in with no question at all.
autologin_on() {
  local f
  for f in /etc/systemd/system/*getty*.service.d/*.conf; do
    [ -f "$f" ] && grep -q -- "--autologin" "$f" || continue
    mkdir -p "$STATE/autologin"
    printf '%s\n' "$f" >> "$STATE/autologin/list"
    mv "$f" "$STATE/autologin/$(echo "$f" | tr '/' '_')"
  done
  systemctl daemon-reload 2>/dev/null || true
}
autologin_off() {
  local f
  [ -f "$STATE/autologin/list" ] || return 0
  while read -r f; do
    [ -f "$STATE/autologin/$(echo "$f" | tr '/' '_')" ] && mv "$STATE/autologin/$(echo "$f" | tr '/' '_')" "$f"
  done < "$STATE/autologin/list"
  rm -rf "$STATE/autologin"
  systemctl daemon-reload 2>/dev/null || true
}

end_sessions() {
  command -v loginctl >/dev/null 2>&1 || return 0
  loginctl list-sessions --no-legend 2>/dev/null | awk '{print $1, $2}' | while read -r sid uid; do
    case "$uid" in ''|*[!0-9]*) continue ;; esac
    if [ "$uid" -eq 0 ] || [ "$uid" -ge 1000 ]; then loginctl terminate-session "$sid" 2>/dev/null; fi
  done
}

boot_unit_on() {
  cat > "$UNIT" <<EOF
[Unit]
Description=$PRODUCT - re-apply the login lockdown at boot
After=systemd-user-sessions.service ssh.service sshd.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/$NAME-lockdown reapply

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload 2>/dev/null; systemctl enable "$NAME-lockdown.service" >/dev/null 2>&1 || true
}
boot_unit_off() {
  systemctl disable "$NAME-lockdown.service" >/dev/null 2>&1 || true
  rm -f "$UNIT"; systemctl daemon-reload 2>/dev/null || true
}

status() {
  local ssh="none" nl="no" root="usable" since=""
  if has_sshd; then
    if "$(sshd_bin)" -T 2>/dev/null | grep -qiE '^denyusers \*'; then ssh="closed"; else ssh="open"; fi
  fi
  grep -q "$NAME-lockdown" /etc/nologin 2>/dev/null && nl="yes"
  case "$(passwd -S root 2>/dev/null | awk '{print $2}')" in L|LK) root="locked" ;; esac
  [ -f "$STATE/on" ] && since="$(cat "$STATE/on")"
  echo "state=$([ -f "$STATE/on" ] && echo on || echo off) since=$since ssh=$ssh nologin=$nl root=$root"
}

case "${1:-}" in
  on)
    write_banner
    ssh_on
    nologin_on
    root_on
    autologin_on
    boot_unit_on
    [ -f "$STATE/on" ] || date -u +%Y-%m-%dT%H:%M:%SZ > "$STATE/on"
    end_sessions
    status ;;
  off)
    OFF_ERR=""
    ssh_off
    nologin_off
    root_off
    autologin_off
    boot_unit_off
    rm -f "$STATE/on" "$BANNER"
    status
    [ -z "$OFF_ERR" ] || { echo "error: $OFF_ERR"; exit 1; } ;;
  reapply)
    if [ -f "$STATE/on" ]; then write_banner; ssh_on; nologin_on; root_on; autologin_on; fi
    status ;;
  status) status ;;
  *) echo "usage: $0 on|off|status"; exit 2 ;;
esac
