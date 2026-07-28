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
#
# Run straight from the branch tip:
#   curl -fsSL https://raw.githubusercontent.com/gitpoemer/paqet/optimize/setup-warp-egress.sh | sudo bash
#   # non-interactive one-shot:
#   curl -fsSL https://raw.githubusercontent.com/gitpoemer/paqet/optimize/setup-warp-egress.sh | sudo bash -s setup
#   sudo ./setup-warp-egress.sh test
#   sudo ./setup-warp-egress.sh status
#   sudo ./setup-warp-egress.sh failclosed   # switch fail mode live
#   sudo ./setup-warp-egress.sh failopen
#   sudo ./setup-warp-egress.sh teardown
#
# Fail mode (WARP down): setup prompts interactively (default fail-closed).
# Override non-interactively with WARP_FAILOPEN=1, or switch later with the
# failclosed/failopen subcommands (menu items 4/5).
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
GUARD_UNIT="warp-egress-guard.service"
GUARD_PATH="/etc/systemd/system/${GUARD_UNIT}"
MARKHEX="0x$(printf '%x' "$MARK")"
# Fail-closed by default: if the WARP interface is down/broken, marked
# egress is DROPPED (blackhole floor) rather than silently leaking out the
# real IP. Set WARP_FAILOPEN=1 to instead let it fall through to normal
# routing (leaks real IP on WARP outage, but keeps connectivity).
FAILOPEN="${WARP_FAILOPEN:-0}"
FAILOPEN_EXPLICIT="${WARP_FAILOPEN+1}"   # non-empty if the env var was set

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
    apt)
      # No -qq: keep apt output visible so a slow mirror/update doesn't look
      # like a freeze. Bounded timeouts so a dead mirror can't hang forever.
      info "apt-get update (fetching package lists — can take ~30s) ..."
      DEBIAN_FRONTEND=noninteractive apt-get update \
        -o Acquire::Retries=3 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 || \
        warn "apt-get update had issues; trying install anyway"
      info "apt-get install: $* ..."
      DEBIAN_FRONTEND=noninteractive apt-get install -y \
        -o Acquire::Retries=3 -o Dpkg::Options::=--force-confold "$@"
      ;;
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
  info "resolving latest wgcf version from GitHub ..."
  ver=$(curl -fsSL --max-time 20 https://api.github.com/repos/ViRb3/wgcf/releases/latest \
        | grep -oE '"tag_name":[[:space:]]*"v[^"]+"' | grep -oE 'v[0-9.]+' | head -1 | tr -d v) \
    || die "could not resolve latest wgcf version (GitHub API timeout/rate limit)"
  [ -n "$ver" ] || die "empty wgcf version from GitHub API (rate limited?)"
  url="https://github.com/ViRb3/wgcf/releases/download/v${ver}/wgcf_${ver}_linux_${arch}"
  tmp=$(mktemp)
  info "downloading wgcf ${ver} (${arch}) ..."
  curl -fSL --max-time 120 "$url" -o "$tmp" || { rm -f "$tmp"; die "wgcf download failed (timeout?): $url"; }
  install -m 0755 "$tmp" /usr/local/bin/wgcf
  rm -f "$tmp"
  command -v wgcf >/dev/null 2>&1 || die "wgcf install verification failed"
  ok "wgcf installed: $(wgcf version 2>/dev/null | head -1 || echo ok)"
}

wgcf_profile() {
  mkdir -p "$WGCF_DIR"; chmod 700 "$WGCF_DIR"
  ( cd "$WGCF_DIR"
    if [ ! -f wgcf-account.toml ]; then
      info "registering a new WARP account with Cloudflare (network, ~5-30s) ..."
      if timeout 60 wgcf register --accept-tos </dev/null; then
        ok "WARP account registered"
      else
        rc=$?
        [ "$rc" -eq 124 ] && die "wgcf register timed out after 60s (network/Cloudflare unreachable?)"
        die "wgcf register failed (rc=$rc)"
      fi
    else
      info "reusing existing WARP account (wgcf-account.toml)"
    fi
    if [ ! -f wgcf-profile.conf ]; then
      info "generating WireGuard profile ..."
      timeout 30 wgcf generate </dev/null || die "wgcf generate failed"
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
    # wg-quick only owns the PREFERRED route (metric 100). The fwmark rule
    # and the fail-closed blackhole floor live in the guard unit so they
    # persist across a WARP outage — otherwise a crash would leak marked
    # traffic out the real IP. When the iface drops, this route vanishes
    # and the guard's higher-metric blackhole takes over (fail closed).
    echo "PostUp = ip -4 route replace default dev %i table $TABLE metric 100"
    echo "PreDown = /bin/sh -c 'ip -4 route del default dev %i table $TABLE metric 100 2>/dev/null || true'"
    if [ -n "$addr6" ]; then
      echo "PostUp = ip -6 route replace default dev %i table $TABLE metric 100"
      echo "PreDown = /bin/sh -c 'ip -6 route del default dev %i table $TABLE metric 100 2>/dev/null || true'"
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

have_systemd() {
  command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]
}

# install_guard writes a self-contained guard script (values baked in) that
# owns the fwmark ip rule plus, unless fail-open, a high-metric blackhole
# default in the table. It persists via a systemd unit so a WARP outage
# fails CLOSED (marked egress dropped) instead of leaking out the real IP.
install_guard() {
  local mode; [ "$FAILOPEN" = "1" ] && mode="fail-OPEN (leaks real IP on WARP outage)" || mode="fail-closed floor"
  info "installing egress guard: fwmark $MARKHEX -> table $TABLE ($mode)"
  cat > /usr/local/sbin/warp-egress-guard <<EOF
#!/usr/bin/env bash
set -u
TABLE=$TABLE
MARK=$MARK
RULE_PRIO=$RULE_PRIO
FAILOPEN=$FAILOPEN
EOF
  cat >> /usr/local/sbin/warp-egress-guard <<'EOF'
up() {
  ip -4 rule del fwmark "$MARK" table "$TABLE" priority "$RULE_PRIO" 2>/dev/null || true
  ip -4 rule add fwmark "$MARK" table "$TABLE" priority "$RULE_PRIO"
  ip -6 rule del fwmark "$MARK" table "$TABLE" priority "$RULE_PRIO" 2>/dev/null || true
  ip -6 rule add fwmark "$MARK" table "$TABLE" priority "$RULE_PRIO" 2>/dev/null || true
  if [ "$FAILOPEN" != "1" ]; then
    ip -4 route replace blackhole default table "$TABLE" metric 1000
    ip -6 route replace blackhole default table "$TABLE" metric 1000 2>/dev/null || true
  else
    # fail-open: ensure no blackhole floor remains (idempotent mode switch)
    ip -4 route del blackhole default table "$TABLE" metric 1000 2>/dev/null || true
    ip -6 route del blackhole default table "$TABLE" metric 1000 2>/dev/null || true
  fi
}
down() {
  ip -4 rule del fwmark "$MARK" table "$TABLE" priority "$RULE_PRIO" 2>/dev/null || true
  ip -6 rule del fwmark "$MARK" table "$TABLE" priority "$RULE_PRIO" 2>/dev/null || true
  ip -4 route del blackhole default table "$TABLE" metric 1000 2>/dev/null || true
  ip -6 route del blackhole default table "$TABLE" metric 1000 2>/dev/null || true
}
case "${1:-}" in
  up)   up ;;
  down) down ;;
  *) echo "usage: $0 up|down" >&2; exit 1 ;;
esac
EOF
  chmod 755 /usr/local/sbin/warp-egress-guard

  if have_systemd; then
    cat > "$GUARD_PATH" <<EOF
[Unit]
Description=paqet WARP egress guard (fwmark rule + fail-closed floor)
After=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/warp-egress-guard up
ExecStop=/usr/local/sbin/warp-egress-guard down

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable "$GUARD_UNIT" >/dev/null 2>&1 || die "failed to enable $GUARD_UNIT"
    # restart (not just enable --now) so a re-run re-executes ExecStart and
    # applies a changed fail mode.
    systemctl restart "$GUARD_UNIT" || die "failed to start $GUARD_UNIT"
  else
    warn "no systemd — applying guard directly (will NOT persist across reboot)"
    /usr/local/sbin/warp-egress-guard up
  fi
}

iface_up() { ip link show "$IFACE" >/dev/null 2>&1; }

bring_up() {
  if iface_up; then
    info "$IFACE exists — reloading config"
    wg-quick down "$IFACE" >/dev/null 2>&1 || true
  fi
  if have_systemd && systemctl list-unit-files 2>/dev/null | grep -q '^wg-quick@'; then
    systemctl enable "wg-quick@${IFACE}" >/dev/null 2>&1 || true
    systemctl restart "wg-quick@${IFACE}" || die "systemctl start wg-quick@${IFACE} failed"
  else
    warn "systemd/wg-quick unit not available — bringing up manually (won't persist across reboot)"
    wg-quick up "$IFACE" || die "wg-quick up $IFACE failed"
  fi
}

# ── actions ──────────────────────────────────────────────────────────────
# prompt_failmode asks fail-closed vs fail-open interactively, unless the
# WARP_FAILOPEN env var was set explicitly (then honor it) or stdin is not
# a TTY (then keep the fail-closed default).
prompt_failmode() {
  [ -n "$FAILOPEN_EXPLICIT" ] && { info "fail mode from WARP_FAILOPEN=$FAILOPEN"; return 0; }
  [ -t 0 ] || return 0
  echo
  echo "When WARP is down, marked egress should:"
  echo "  1) Fail-closed  (recommended) — DROP it; never leak the real IP"
  echo "  2) Fail-open                  — fall back to the real IP (keeps"
  echo "                                  connectivity, but leaks on outage)"
  local fm; read -rp "select [1]> " fm || fm=1
  case "${fm:-1}" in
    2|open|o) FAILOPEN=1 ;;
    *)        FAILOPEN=0 ;;
  esac
}

do_setmode() {
  require_root
  FAILOPEN="$1"
  [ -x /usr/local/sbin/warp-egress-guard ] || die "guard not installed — run setup first"
  install_guard
  ok "egress is now $([ "$1" = 1 ] && echo 'FAIL-OPEN (leaks real IP on WARP outage)' || echo 'FAIL-CLOSED (drops on WARP outage)')"
}

do_setup() {
  require_root
  ensure_deps
  install_wgcf
  wgcf_profile
  build_wg_conf
  apply_sysctl
  prompt_failmode
  install_guard
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
  table  : ${TABLE}   (dev ${IFACE} metric 100 $( [ "$FAILOPEN" = 1 ] && echo '(fail-open)' || echo '+ blackhole metric 1000 = fail-closed'))
  rule   : fwmark ${MARKHEX} -> table ${TABLE} (prio ${RULE_PRIO}, persisted by ${GUARD_UNIT})

Fail-closed: if WARP drops, marked egress is DROPPED (not leaked out the
real IP). Re-run with WARP_FAILOPEN=1 to prefer connectivity over leak-safety.

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
  trap _cleanup_test EXIT INT TERM
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

  _cleanup_test; trap - EXIT INT TERM

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
  echo "guard:"
  if have_systemd; then
    printf '    %s: %s (%s)\n' "$GUARD_UNIT" \
      "$(systemctl is-active "$GUARD_UNIT" 2>/dev/null || echo inactive)" \
      "$(systemctl is-enabled "$GUARD_UNIT" 2>/dev/null || echo disabled)"
  fi
  ip route show table "$TABLE" 2>/dev/null | grep -q blackhole && echo "    fail-closed: blackhole floor present" || echo "    fail-open: no blackhole floor"
  echo "systemd:"; systemctl is-enabled "wg-quick@${IFACE}" 2>/dev/null | sed 's/^/    wg-quick enabled=/' || true
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
  # stop + remove the guard (which owns the fwmark rule + blackhole floor)
  if have_systemd; then
    systemctl disable --now "$GUARD_UNIT" >/dev/null 2>&1 || true
  elif [ -x /usr/local/sbin/warp-egress-guard ]; then
    /usr/local/sbin/warp-egress-guard down 2>/dev/null || true
  fi
  rm -f "$GUARD_PATH" /usr/local/sbin/warp-egress-guard
  have_systemd && systemctl daemon-reload >/dev/null 2>&1 || true
  # belt-and-suspenders rule/route cleanup in case the guard didn't run
  ip -4 rule del fwmark "$MARK" table "$TABLE" priority "$RULE_PRIO" 2>/dev/null || true
  ip -6 rule del fwmark "$MARK" table "$TABLE" priority "$RULE_PRIO" 2>/dev/null || true
  ip route flush table "$TABLE" 2>/dev/null || true
  ip -6 route flush table "$TABLE" 2>/dev/null || true
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
  4) Switch to fail-closed (drop on WARP outage)
  5) Switch to fail-open  (leak real IP on WARP outage)
  6) Route system DNS through WARP (optional)
  7) Stop routing system DNS through WARP
  8) Teardown / uninstall
  0) Exit
EOF
    read -rp "select> " choice || { echo; exit 0; }
    case "$choice" in
      1) do_setup ;;
      2) do_test  || warn "test reported a failure" ;;
      3) do_status ;;
      4) do_setmode 0 ;;
      5) do_setmode 1 ;;
      6) do_dns_on ;;
      7) do_dns_off ;;
      8) do_teardown ;;
      0|q|quit|exit) exit 0 ;;
      *) warn "invalid choice: $choice" ;;
    esac
  done
}

# When piped (curl ... | sudo bash) the script body IS stdin, so interactive
# `read`s hit EOF immediately. Reattach stdin to the controlling terminal so
# the menu actually waits for input.
attach_tty() {
  [ -t 0 ] && return 0
  # Test we can actually OPEN the controlling terminal (a readable /dev/tty
  # node can still fail with ENXIO when there is no controlling tty), so the
  # exec below can't blow up mid-redirect.
  if { : </dev/tty; } 2>/dev/null; then
    exec </dev/tty
  else
    die "no terminal available for the interactive menu. Either download first
  (curl -fsSL <url> -o setup-warp-egress.sh && sudo bash setup-warp-egress.sh)
  or run a non-interactive subcommand, e.g.:  ... | sudo bash -s setup"
  fi
}

main() {
  case "${1:-menu}" in
    menu|"")   require_root; attach_tty; menu ;;
    setup)     do_setup ;;
    test)      do_test ;;
    status)    do_status ;;
    failclosed|fail-closed) do_setmode 0 ;;
    failopen|fail-open)     do_setmode 1 ;;
    dns-on)    do_dns_on ;;
    dns-off)   do_dns_off ;;
    teardown|uninstall) do_teardown ;;
    -h|--help|help)
      grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//' | head -40 ;;
    *) die "unknown command: $1 (try: setup|test|status|failclosed|failopen|dns-on|dns-off|teardown, or no arg for menu)" ;;
  esac
}
main "$@"
