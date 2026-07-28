#!/usr/bin/env bash
#
# setup-warp-egress.sh — route paqet's forwarded (egress) traffic out a
# Cloudflare WARP WireGuard interface via fwmark policy routing, while the
# paqet tunnel's own control traffic keeps using the real interface.
#
# It pairs with paqet's `transport.egress_mark` option: the server stamps
# SO_MARK=<MARK> on every outbound target socket (TCP and UDP); this script
# adds an `ip rule` that steers marked packets into a dedicated routing
# table whose default route is the WARP interface. Nothing else is touched,
# so client<->server KCP traffic is unaffected.
#
# Idempotent + interactive. Run as root.
#
#   sudo ./setup-warp-egress.sh              # interactive menu
#   sudo ./setup-warp-egress.sh setup        # non-interactive actions
#   sudo ./setup-warp-egress.sh test
#   sudo ./setup-warp-egress.sh status
#   sudo ./setup-warp-egress.sh teardown
#
# Tunables (env overrides):
#   WARP_IFACE (warp)  WARP_TABLE (51820)  WARP_MARK (1)  WARP_RULE_PRIO (1000)
#
set -euo pipefail

IFACE="${WARP_IFACE:-warp}"
TABLE="${WARP_TABLE:-51820}"
MARK="${WARP_MARK:-1}"
RULE_PRIO="${WARP_RULE_PRIO:-1000}"
WGCF_DIR="/etc/warp-egress"
WG_CONF="/etc/wireguard/${IFACE}.conf"
SYSCTL_FILE="/etc/sysctl.d/99-warp-egress.conf"
MARKHEX="0x$(printf '%x' "$MARK")"

# ── output helpers ───────────────────────────────────────────────────────
if [ -t 1 ]; then
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_BLU=$'\033[36m'; C_RST=$'\033[0m'; C_B=$'\033[1m'
else
  C_RED=; C_GRN=; C_YEL=; C_BLU=; C_RST=; C_B=
fi
info() { printf '%s[*]%s %s\n' "$C_BLU" "$C_RST" "$*"; }
ok()   { printf '%s[+]%s %s\n' "$C_GRN" "$C_RST" "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_YEL" "$C_RST" "$*" >&2; }
err()  { printf '%s[x]%s %s\n' "$C_RED" "$C_RST" "$*" >&2; }
die()  { err "$*"; exit 1; }

# ── preflight ────────────────────────────────────────────────────────────
require_root() { [ "$(id -u)" -eq 0 ] || die "must run as root (try: sudo $0 ...)"; }

PKG=""
detect_pkg_mgr() {
  if command -v apt-get >/dev/null 2>&1; then PKG=apt
  elif command -v dnf >/dev/null 2>&1; then PKG=dnf
  elif command -v yum >/dev/null 2>&1; then PKG=yum
  elif command -v pacman >/dev/null 2>&1; then PKG=pacman
  else PKG=""; fi
}

pkg_install() {
  # $@ = package names
  case "$PKG" in
    apt)    apt-get update -qq && apt-get install -y "$@" ;;
    dnf)    dnf install -y "$@" ;;
    yum)    yum install -y "$@" ;;
    pacman) pacman -Sy --noconfirm "$@" ;;
    *)      return 1 ;;
  esac
}

ensure_deps() {
  local missing=()
  command -v ip      >/dev/null 2>&1 || missing+=("iproute2")
  command -v wg      >/dev/null 2>&1 || missing+=("wireguard-tools")
  command -v wg-quick>/dev/null 2>&1 || missing+=("wireguard-tools")
  command -v curl    >/dev/null 2>&1 || missing+=("curl")
  command -v iptables>/dev/null 2>&1 || missing+=("iptables")
  # de-dup
  if [ "${#missing[@]}" -gt 0 ]; then
    local uniq; uniq=$(printf '%s\n' "${missing[@]}" | sort -u | tr '\n' ' ')
    warn "missing dependencies: $uniq"
    detect_pkg_mgr
    [ -n "$PKG" ] || die "no supported package manager found; install manually: $uniq"
    info "installing via $PKG ..."
    pkg_install $uniq || die "dependency install failed; install manually: $uniq"
  fi
  # module
  modprobe wireguard 2>/dev/null || true
}

# ── wgcf (WARP account + profile generator) ──────────────────────────────
install_wgcf() {
  if command -v wgcf >/dev/null 2>&1; then return 0; fi
  info "installing wgcf ..."
  local arch ver url tmp
  case "$(uname -m)" in
    x86_64|amd64)  arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    armv7l|armv7)  arch=armv7 ;;
    *) die "unsupported arch for wgcf: $(uname -m)" ;;
  esac
  ver=$(curl -fsSL https://api.github.com/repos/ViRb3/wgcf/releases/latest \
        | grep -oE '"tag_name":[[:space:]]*"v[^"]+"' | grep -oE 'v[0-9.]+' | head -1 | tr -d v) \
    || die "could not resolve latest wgcf version (GitHub API rate limit? set it manually)"
  [ -n "$ver" ] || die "empty wgcf version from GitHub API"
  url="https://github.com/ViRb3/wgcf/releases/download/v${ver}/wgcf_${ver}_linux_${arch}"
  tmp=$(mktemp)
  info "downloading wgcf ${ver} (${arch}) ..."
  curl -fsSL "$url" -o "$tmp" || { rm -f "$tmp"; die "wgcf download failed: $url"; }
  install -m 0755 "$tmp" /usr/local/bin/wgcf
  rm -f "$tmp"
  command -v wgcf >/dev/null 2>&1 || die "wgcf install verification failed"
  ok "wgcf installed: $(wgcf version 2>/dev/null | head -1 || echo ok)"
}

wgcf_profile() {
  mkdir -p "$WGCF_DIR"; chmod 700 "$WGCF_DIR"
  ( cd "$WGCF_DIR"
    if [ ! -f wgcf-account.toml ]; then
      info "registering a new WARP account (free) ..."
      wgcf register --accept-tos || die "wgcf register failed (network?)"
    else
      info "reusing existing WARP account (wgcf-account.toml)"
    fi
    if [ ! -f wgcf-profile.conf ]; then
      wgcf generate || die "wgcf generate failed"
    fi
  )
  [ -f "$WGCF_DIR/wgcf-profile.conf" ] || die "wgcf-profile.conf not produced"
}

# ── build the wg-quick config from the wgcf profile ──────────────────────
build_wg_conf() {
  local src="$WGCF_DIR/wgcf-profile.conf"
  local priv addr6 addr4 pub endpoint
  # Split on the FIRST '=' only — base64 WireGuard keys end in '=' / '==',
  # so an '= *' field split would eat the padding and corrupt the key.
  priv=$(sed -n 's/^PrivateKey[[:space:]]*=[[:space:]]*//p' "$src" | head -1)
  pub=$(sed -n 's/^PublicKey[[:space:]]*=[[:space:]]*//p' "$src" | head -1)
  endpoint=$(sed -n 's/^Endpoint[[:space:]]*=[[:space:]]*//p' "$src" | head -1)
  # wgcf lists two Address lines (v4 /32, v6 /128)
  addr4=$(sed -n 's/^Address[[:space:]]*=[[:space:]]*//p' "$src" | grep -E '^[0-9]+\.' | head -1)
  addr6=$(sed -n 's/^Address[[:space:]]*=[[:space:]]*//p' "$src" | grep ':' | head -1)
  [ -n "$priv" ] && [ -n "$pub" ] && [ -n "$endpoint" ] || die "could not parse wgcf profile"

  local addr_line="$addr4"
  [ -n "$addr6" ] && addr_line="$addr4, $addr6"

  info "writing $WG_CONF (Table=off; fwmark $MARKHEX -> table $TABLE)"
  mkdir -p /etc/wireguard; chmod 700 /etc/wireguard
  umask 077
  {
    echo "# Managed by setup-warp-egress.sh — do not hand-edit."
    echo "[Interface]"
    echo "PrivateKey = $priv"
    echo "Address = $addr_line"
    echo "MTU = 1280"
    # NOTE: the wgcf DNS= line is deliberately dropped — wg-quick would
    # rewrite the host's /etc/resolv.conf globally. DNS is handled separately.
    echo "Table = off"
    # Default route lives only in our private table; marked packets use it.
    echo "PostUp = ip -4 route replace default dev %i table $TABLE"
    echo "PostUp = /bin/sh -c 'ip -4 rule del fwmark $MARK table $TABLE priority $RULE_PRIO 2>/dev/null; ip -4 rule add fwmark $MARK table $TABLE priority $RULE_PRIO'"
    echo "PreDown = /bin/sh -c 'ip -4 rule del fwmark $MARK table $TABLE priority $RULE_PRIO 2>/dev/null || true'"
    if [ -n "$addr6" ]; then
      echo "PostUp = ip -6 route replace default dev %i table $TABLE"
      echo "PostUp = /bin/sh -c 'ip -6 rule del fwmark $MARK table $TABLE priority $RULE_PRIO 2>/dev/null; ip -6 rule add fwmark $MARK table $TABLE priority $RULE_PRIO'"
      echo "PreDown = /bin/sh -c 'ip -6 rule del fwmark $MARK table $TABLE priority $RULE_PRIO 2>/dev/null || true'"
    fi
    echo ""
    echo "[Peer]"
    echo "PublicKey = $pub"
    echo "AllowedIPs = 0.0.0.0/0, ::/0"
    echo "Endpoint = $endpoint"
    echo "PersistentKeepalive = 25"
  } > "$WG_CONF"
  chmod 600 "$WG_CONF"
}

apply_sysctl() {
  # Loose reverse-path filtering so replies arriving on the WARP iface for
  # marked, locally-originated connections are not dropped.
  info "setting rp_filter=2 (loose) for WARP asymmetric paths"
  {
    echo "# Managed by setup-warp-egress.sh"
    echo "net.ipv4.conf.all.rp_filter = 2"
    echo "net.ipv4.conf.default.rp_filter = 2"
  } > "$SYSCTL_FILE"
  sysctl -q -p "$SYSCTL_FILE" || warn "sysctl apply reported an issue (continuing)"
}

iface_up() { ip link show "$IFACE" >/dev/null 2>&1; }

bring_up() {
  if iface_up; then
    info "$IFACE exists — reloading config"
    wg-quick down "$IFACE" >/dev/null 2>&1 || true
  fi
  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -q '^wg-quick@'; then
    systemctl enable "wg-quick@${IFACE}" >/dev/null 2>&1 || true
    systemctl restart "wg-quick@${IFACE}" || die "systemctl start wg-quick@${IFACE} failed"
  else
    warn "systemd/wg-quick unit not available — bringing up manually (won't persist across reboot)"
    wg-quick up "$IFACE" || die "wg-quick up $IFACE failed"
  fi
}

# ── actions ──────────────────────────────────────────────────────────────
do_setup() {
  require_root
  ensure_deps
  install_wgcf
  wgcf_profile
  build_wg_conf
  apply_sysctl
  bring_up
  echo
  ok "WARP egress is up."
  cat <<EOF

${C_B}Next: point paqet at this mark.${C_RST}
In your paqet SERVER config, under transport:

  transport:
    protocol: kcp
    egress_mark: ${MARK}

Then restart paqet. Only the server's forwarded TCP/UDP egress will leave
via Cloudflare WARP (source IP = Cloudflare); tunnel control traffic stays
on the real interface.

Routing summary:
  iface  : ${IFACE}
  table  : ${TABLE}   (default route -> ${IFACE})
  rule   : fwmark ${MARKHEX} -> table ${TABLE} (prio ${RULE_PRIO})

Run '${0##*/} test' to verify the marked path reaches google.com via WARP.
EOF
}

# temp-mark helpers for the test (self-cleaning via trap)
_TEST_RULES=()
_cleanup_test() {
  local r
  for r in "${_TEST_RULES[@]:-}"; do
    [ -n "$r" ] || continue
    iptables -t mangle -D OUTPUT $r 2>/dev/null || true
  done
  _TEST_RULES=()
}

_marked_curl() {
  # $1 host  $2 path  -> echoes body; marks real TCP to the host so it
  # traverses the fwmark rule exactly like paqet's egress sockets do.
  local host="$1" path="$2" ip rule body
  ip=$(getent ahostsv4 "$host" 2>/dev/null | awk '{print $1; exit}')
  [ -n "$ip" ] || { warn "could not resolve $host"; return 1; }
  rule="-d $ip -p tcp --dport 443 -j MARK --set-mark $MARK"
  iptables -t mangle -C OUTPUT $rule 2>/dev/null || iptables -t mangle -A OUTPUT $rule
  _TEST_RULES+=("$rule")
  body=$(curl -fsS --max-time 15 --resolve "${host}:443:${ip}" "https://${host}${path}" 2>/dev/null) || return 1
  printf '%s' "$body"
}

do_test() {
  require_root
  iface_up || die "$IFACE is not up — run '${0##*/} setup' first"

  info "checks:"
  ip rule show | grep -q "fwmark $MARKHEX lookup $TABLE" \
    && ok "ip rule present: fwmark $MARKHEX -> table $TABLE" \
    || { ip rule show | grep -q "fwmark $MARK lookup $TABLE" \
         && ok "ip rule present: fwmark $MARK -> table $TABLE" \
         || err "ip rule for fwmark $MARK -> table $TABLE MISSING"; }
  ip route show table "$TABLE" | grep -q "default" \
    && ok "table $TABLE has a default route: $(ip route show table "$TABLE" | grep default | head -1)" \
    || err "table $TABLE has NO default route"

  echo
  trap _cleanup_test EXIT
  info "baseline egress (unmarked, normal route):"
  local base_ip base_trace
  base_trace=$(curl -fsS --max-time 10 https://cloudflare.com/cdn-cgi/trace 2>/dev/null || true)
  base_ip=$(printf '%s' "$base_trace" | awk -F= '/^ip=/{print $2}')
  printf '    ip=%s\n' "${base_ip:-?}"

  echo
  info "marked egress (fwmark $MARK -> WARP table), via cloudflare trace:"
  local warp_trace warp_ip warp_flag
  warp_trace=$(_marked_curl cloudflare.com /cdn-cgi/trace) || { _cleanup_test; die "marked request FAILED — WARP path not working"; }
  warp_ip=$(printf '%s'   "$warp_trace" | awk -F= '/^ip=/{print $2}')
  warp_flag=$(printf '%s' "$warp_trace" | awk -F= '/^warp=/{print $2}')
  printf '    ip=%s  warp=%s\n' "${warp_ip:-?}" "${warp_flag:-?}"

  echo
  info "marked request to google.com (real TCP through the WARP table):"
  local grsp
  grsp=$(_marked_curl www.google.com / | head -c 120 || true)
  if [ -n "$grsp" ]; then ok "google.com responded through the WARP table"; else err "google.com did NOT respond through the WARP table"; fi

  _cleanup_test; trap - EXIT

  echo
  if [ "${warp_flag:-off}" = "on" ] && [ -n "$warp_ip" ] && [ "$warp_ip" != "$base_ip" ]; then
    ok "SUCCESS: marked traffic egresses via Cloudflare WARP (${warp_ip}), distinct from baseline (${base_ip:-?})."
  elif [ "${warp_flag:-off}" = "on" ]; then
    ok "marked traffic shows warp=on (egress ${warp_ip})."
  else
    err "marked traffic did NOT report warp=on — check the interface/peer handshake (wg show $IFACE)."
    return 1
  fi
}

do_status() {
  echo "${C_B}== WARP egress status ==${C_RST}"
  printf 'iface %s : ' "$IFACE"
  iface_up && ok "up" || warn "down"
  if iface_up; then
    wg show "$IFACE" 2>/dev/null | sed 's/^/    /' || true
  fi
  echo "rule:";  ip rule show | grep "lookup $TABLE" | sed 's/^/    /' || echo "    (none)"
  echo "table $TABLE routes:"; ip route show table "$TABLE" 2>/dev/null | sed 's/^/    /' || echo "    (empty)"
  echo "systemd:"; systemctl is-enabled "wg-quick@${IFACE}" 2>/dev/null | sed 's/^/    enabled=/' || true
}

do_dns_on() {
  require_root
  info "routing system DNS (udp/tcp port 53) through WARP via mark $MARK"
  for proto in udp tcp; do
    local rule="-p $proto --dport 53 -j MARK --set-mark $MARK"
    iptables -t mangle -C OUTPUT $rule 2>/dev/null || iptables -t mangle -A OUTPUT $rule
  done
  ok "system DNS now marked. NOTE: if you use systemd-resolved (127.0.0.53),"
  warn "only its upstream queries are affected; consider setting DNS=1.1.1.1 in resolved.conf."
}
do_dns_off() {
  require_root
  for proto in udp tcp; do
    iptables -t mangle -D OUTPUT -p $proto --dport 53 -j MARK --set-mark $MARK 2>/dev/null || true
  done
  ok "system DNS marking removed."
}

do_teardown() {
  require_root
  info "tearing down WARP egress ..."
  wg-quick down "$IFACE" >/dev/null 2>&1 || true
  systemctl disable "wg-quick@${IFACE}" >/dev/null 2>&1 || true
  # belt-and-suspenders rule/route cleanup in case PreDown didn't run
  ip -4 rule del fwmark "$MARK" table "$TABLE" priority "$RULE_PRIO" 2>/dev/null || true
  ip -6 rule del fwmark "$MARK" table "$TABLE" priority "$RULE_PRIO" 2>/dev/null || true
  ip route flush table "$TABLE" 2>/dev/null || true
  do_dns_off || true
  rm -f "$SYSCTL_FILE"; sysctl --system >/dev/null 2>&1 || true
  ok "WARP egress removed. (kept $WG_CONF and $WGCF_DIR — delete manually to fully purge)"
  info "remember to remove 'egress_mark' from the paqet config and restart it."
}

# ── menu ─────────────────────────────────────────────────────────────────
menu() {
  while true; do
    cat <<EOF

${C_B}=== paqet WARP egress ===${C_RST}  iface=${IFACE} table=${TABLE} mark=${MARK}
  1) Setup / update WARP egress (idempotent)
  2) Test WARP table (marked request to google.com)
  3) Show status
  4) Route system DNS through WARP (optional)
  5) Stop routing system DNS through WARP
  6) Teardown / uninstall
  0) Exit
EOF
    read -rp "select> " choice || { echo; exit 0; }
    case "$choice" in
      1) do_setup ;;
      2) do_test  || warn "test reported a failure" ;;
      3) do_status ;;
      4) do_dns_on ;;
      5) do_dns_off ;;
      6) do_teardown ;;
      0|q|quit|exit) exit 0 ;;
      *) warn "invalid choice: $choice" ;;
    esac
  done
}

main() {
  case "${1:-menu}" in
    menu|"")   require_root; menu ;;
    setup)     do_setup ;;
    test)      do_test ;;
    status)    do_status ;;
    dns-on)    do_dns_on ;;
    dns-off)   do_dns_off ;;
    teardown|uninstall) do_teardown ;;
    -h|--help|help)
      grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//' | head -40 ;;
    *) die "unknown command: $1 (try: setup|test|status|dns-on|dns-off|teardown, or no arg for menu)" ;;
  esac
}
main "$@"
