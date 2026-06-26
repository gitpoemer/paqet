#!/usr/bin/env bash
#
# ====== ONE-LINERS (curl-from-GitHub direct) =================================
#
#  Default install (port 443, SOCKS upstream at 127.0.0.1:1080):
#
#    curl -fsSL https://raw.githubusercontent.com/gitpoemer/paqet/optimize/setup-xray-reality-vision.sh | sudo bash
#
#  Custom override via env vars (port, SOCKS upstream, mimic'd SNI):
#
#    curl -fsSL https://raw.githubusercontent.com/gitpoemer/paqet/optimize/setup-xray-reality-vision.sh \
#      | sudo LISTEN_PORT=8443 SOCKS_HOST=127.0.0.1 SOCKS_PORT=1080 \
#             REALITY_DEST_HOST=www.cloudflare.com bash
#
#  Skip auto-printing the client URI (e.g. CI / unattended runs):
#
#    curl -fsSL https://raw.githubusercontent.com/gitpoemer/paqet/optimize/setup-xray-reality-vision.sh \
#      | sudo PRINT_CLIENT=0 bash
#
#  All optional env vars (defaults shown):
#    LISTEN_PORT=443
#    SOCKS_HOST=127.0.0.1
#    SOCKS_PORT=1080
#    REALITY_DEST_HOST=www.microsoft.com   # SNI to mimic, must be a CDN-fronted real site
#    REALITY_DEST_PORT=443
#    CONFIG_DIR=/usr/local/etc/xray        # xray's config dir (matches official installer)
#    STATE_DIR=/usr/local/etc/xray         # where keypair + UUID + shortId are persisted
#    SERVER_PUBLIC_IP=<auto-detected>      # set if your egress IP differs from ifconfig.me
#    PRINT_CLIENT=1                        # 0 to suppress the vless:// URI at the end
#
#  Re-running is safe (idempotent): existing keys/UUID/shortId are reused so
#  active clients don't get disconnected; xray is reinstalled only if a newer
#  release exists; the config is rewritten and the service restarted only when
#  something actually changed.
#
# =============================================================================
#
# setup-xray-reality-vision.sh
#
# Idempotent installer for an Xray-core server using the current DPI-
# evasion stack: VLESS protocol + REALITY transport security + the
# xtls-rprx-vision flow control.
#
# Why this combination, in 2026:
#   - VLESS: stateless, lighter than VMess; no client-side AEAD keying
#     overhead, so the wire pattern matches an idle TLS connection more
#     closely.
#   - REALITY: handshake bytes are byte-for-byte identical to a real
#     TLS-ECH handshake against a target site (default
#     www.microsoft.com). No TLS-cert is needed; the SNI of an actual
#     CDN-fronted site is borrowed. Resists active probes that try to
#     replay the handshake — REALITY's server hands probes through to
#     the real upstream.
#   - Vision (xtls-rprx-vision): splices the inner TLS data flow so the
#     outer TLS framing has the size/timing pattern of a normal
#     HTTPS browser session. The current best counter to AI-based
#     traffic classifiers as of mid-2026.
#
# Outbound traffic is forwarded to a SOCKS5 proxy on 127.0.0.1:1080
# (the user's local exit). The Xray box is a TCP front-end; the SOCKS
# tunnel is where bytes actually leave.
#
# Idempotency:
#   - Re-running this script is safe. It detects existing state and
#     reuses the UUID, REALITY keypair, and shortId rather than
#     rotating them (which would break every active client).
#   - Xray is only reinstalled when the local version differs from the
#     latest GitHub release. Config is only rewritten when its content
#     would actually change.
#   - The systemd unit is only daemon-reloaded + restarted when the
#     config or binary changed.
#
# Usage:
#   sudo ./setup-xray-reality-vision.sh                # full install + start
#   sudo PRINT_CLIENT=1 ./setup-xray-reality-vision.sh # also print client URI
#
# Override environment vars (all optional):
#   LISTEN_PORT       default 443
#   SOCKS_HOST        default 127.0.0.1
#   SOCKS_PORT        default 1080
#   REALITY_DEST_HOST default www.microsoft.com
#   REALITY_DEST_PORT default 443
#   CONFIG_DIR        default /usr/local/etc/xray
#   SERVER_PUBLIC_IP  default auto-detected via ifconfig.me

set -euo pipefail

# ---------------------------------------------------------------------------
# Tunables (all overridable via environment)
# ---------------------------------------------------------------------------
LISTEN_PORT="${LISTEN_PORT:-443}"
SOCKS_HOST="${SOCKS_HOST:-127.0.0.1}"
SOCKS_PORT="${SOCKS_PORT:-1080}"
REALITY_DEST_HOST="${REALITY_DEST_HOST:-www.microsoft.com}"
REALITY_DEST_PORT="${REALITY_DEST_PORT:-443}"
CONFIG_DIR="${CONFIG_DIR:-/usr/local/etc/xray}"
STATE_DIR="${STATE_DIR:-/usr/local/etc/xray}"
PRINT_CLIENT="${PRINT_CLIENT:-1}"

CONFIG_FILE="$CONFIG_DIR/config.json"
STATE_FILE="$STATE_DIR/.reality_state.env"

# Geo data — geoip.dat / geosite.dat from an upstream geo-rule
# release, refreshed on every script run if a newer release is
# available. Xray reads them by default from /usr/local/share/xray/.
# Override GEOFILES_REPO with any "owner/name" if you want different
# rules.
GEOFILES_REPO="${GEOFILES_REPO:-chocolate4u/Iran-v2ray-rules}"
GEOFILES_DIR="${GEOFILES_DIR:-/usr/local/share/xray}"
GEOFILES_TAG_FILE="${GEOFILES_TAG_FILE:-$STATE_DIR/.geofiles_tag}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { printf '\033[1;34m[setup]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m  %s\n' "$*" >&2; }
err()  { printf '\033[1;31m[err]\033[0m   %s\n' "$*" >&2; }
die()  { err "$*"; exit 1; }

require_root() {
  if [[ $EUID -ne 0 ]]; then
    die "must be run as root (or via sudo)"
  fi
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    die "missing required command: $cmd"
  fi
}

# md5 of file or empty string if file missing — used to gate config writes
# behind an actual change.
file_md5() {
  local f="$1"
  [[ -f "$f" ]] && md5sum "$f" | awk '{print $1}' || echo ""
}

# is_private_ip — returns 0 if the IP belongs to RFC1918 / loopback /
# link-local / IETF CGNAT range (100.64.0.0/10), else 1. Used by the
# print_client_uri NIC-vs-egress heuristic.
is_private_ip() {
  local ip="$1"
  [[ -z "$ip" ]] && return 0
  case "$ip" in
    10.*)             return 0 ;;
    127.*)            return 0 ;;
    169.254.*)        return 0 ;;
    172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;;
    192.168.*)        return 0 ;;
    100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) return 0 ;;
  esac
  return 1
}

# ---------------------------------------------------------------------------
# Step 1: install or upgrade xray-core via the official installer
# ---------------------------------------------------------------------------
install_xray() {
  log "ensuring xray-core is installed and current"
  require_cmd curl
  require_cmd jq || die "install jq first: apt-get install -y jq  (or yum/dnf install -y jq)"

  local latest_tag installed_version
  latest_tag=$(curl -fsSL https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r '.tag_name')
  if [[ -z "$latest_tag" || "$latest_tag" == "null" ]]; then
    die "could not query latest xray release tag from GitHub"
  fi
  log "latest xray release: $latest_tag"

  if command -v xray >/dev/null 2>&1; then
    installed_version=$(xray version | head -n1 | awk '{print $2}' || echo "")
    log "currently installed xray: ${installed_version:-unknown}"
  else
    installed_version=""
  fi

  # The official installer is `install-release.sh` from XTLS/Xray-install.
  # It uses systemd, sets up /usr/local/etc/xray/, /usr/local/bin/xray.
  # Running it without --version pulls the latest; --version=X.Y.Z pins.
  # We only invoke it when our installed_version differs from latest_tag.
  if [[ "v${installed_version#v}" == "${latest_tag}" || "$installed_version" == "${latest_tag#v}" ]]; then
    log "xray is already at latest version, skipping installer"
  else
    log "installing xray $latest_tag via official installer"
    bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" \
      @ install --without-geodata >/dev/null
  fi
}

# ---------------------------------------------------------------------------
# Step 2: provision or reuse REALITY keypair + UUID + shortId
# ---------------------------------------------------------------------------
provision_secrets() {
  log "ensuring REALITY keypair, UUID, and shortId exist"

  if [[ -f "$STATE_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$STATE_FILE"
  fi

  if [[ -z "${REALITY_PRIVATE_KEY:-}" || -z "${REALITY_PUBLIC_KEY:-}" ]]; then
    log "minting fresh REALITY x25519 keypair"
    local kp
    kp=$(xray x25519)
    REALITY_PRIVATE_KEY=$(awk '/Private/ {print $NF}' <<<"$kp")
    REALITY_PUBLIC_KEY=$(awk '/Public/  {print $NF}' <<<"$kp")
  else
    log "reusing existing REALITY keypair (idempotent — does not rotate live clients)"
  fi

  if [[ -z "${CLIENT_UUID:-}" ]]; then
    log "minting fresh client UUID"
    CLIENT_UUID=$(xray uuid)
  else
    log "reusing existing client UUID"
  fi

  if [[ -z "${SHORT_ID:-}" ]]; then
    log "minting fresh shortId (8 hex chars)"
    SHORT_ID=$(head -c 4 /dev/urandom | xxd -p)
  else
    log "reusing existing shortId"
  fi

  install -d -m 700 "$STATE_DIR"
  umask 077
  cat > "$STATE_FILE" <<EOF
# Auto-generated. DO NOT edit by hand unless you know what you're doing —
# changing these breaks every active client.
REALITY_PRIVATE_KEY="$REALITY_PRIVATE_KEY"
REALITY_PUBLIC_KEY="$REALITY_PUBLIC_KEY"
CLIENT_UUID="$CLIENT_UUID"
SHORT_ID="$SHORT_ID"
EOF
  chmod 600 "$STATE_FILE"
}

# ---------------------------------------------------------------------------
# Step 2b: install / refresh geo data files
# ---------------------------------------------------------------------------
install_geofiles() {
  log "ensuring geoip.dat / geosite.dat are current"
  require_cmd curl
  require_cmd jq
  require_cmd sha256sum

  local latest_tag installed_tag=""
  latest_tag=$(curl -fsSL "https://api.github.com/repos/$GEOFILES_REPO/releases/latest" \
    | jq -r '.tag_name')
  if [[ -z "$latest_tag" || "$latest_tag" == "null" ]]; then
    warn "could not query latest $GEOFILES_REPO release tag — skipping geofile refresh"
    return 0
  fi

  if [[ -f "$GEOFILES_TAG_FILE" ]]; then
    installed_tag=$(cat "$GEOFILES_TAG_FILE" 2>/dev/null || true)
  fi

  if [[ "${installed_tag}" == "$latest_tag" \
        && -f "$GEOFILES_DIR/geoip.dat" \
        && -f "$GEOFILES_DIR/geosite.dat" ]]; then
    log "geofiles already at $latest_tag, skipping download"
    return 0
  fi

  log "downloading $GEOFILES_REPO geofiles @ $latest_tag"
  install -d -m 755 "$GEOFILES_DIR"
  local tmpdir
  tmpdir=$(mktemp -d)
  trap "rm -rf '$tmpdir'" RETURN

  local base="https://github.com/$GEOFILES_REPO/releases/download/$latest_tag"
  local f expected actual
  for f in geoip.dat geosite.dat; do
    log "  fetching $f"
    if ! curl -fsSL "$base/$f"            -o "$tmpdir/$f"; then
      warn "failed to download $f — leaving existing files untouched"
      return 0
    fi
    if ! curl -fsSL "$base/$f.sha256sum"  -o "$tmpdir/$f.sha256sum"; then
      warn "no sha256sum for $f, skipping verification"
    else
      # The upstream sums file uses 'release/<file>' as the path
      # (it's relative to the build root, not the asset URL), which
      # would make 'sha256sum -c' look for the wrong file. Extract
      # just the hex digest and compare against what we downloaded.
      expected=$(awk '{print $1}' "$tmpdir/$f.sha256sum")
      actual=$(sha256sum "$tmpdir/$f" | awk '{print $1}')
      if [[ "$expected" != "$actual" ]]; then
        err "sha256 mismatch on $f: expected $expected got $actual — refusing to install"
        return 1
      fi
      log "  verified $f"
    fi
  done

  install -m 644 "$tmpdir/geoip.dat"   "$GEOFILES_DIR/geoip.dat"
  install -m 644 "$tmpdir/geosite.dat" "$GEOFILES_DIR/geosite.dat"
  echo "$latest_tag" > "$GEOFILES_TAG_FILE"
  log "geofiles installed at $GEOFILES_DIR (tag $latest_tag)"
}

# ---------------------------------------------------------------------------
# Step 3: build the desired config JSON, write only if it differs
# ---------------------------------------------------------------------------
write_config() {
  log "preparing $CONFIG_FILE"
  install -d -m 755 "$CONFIG_DIR"

  local tmp tmp_raw
  # xray detects config format from the file extension, so the temp
  # file MUST end in .json — otherwise `xray -test` errors with
  # "Failed to get format of <tmpfile>". `mktemp --suffix=.json`
  # works on GNU coreutils but silently no-ops on some older Ubuntu
  # variants, so we create with bare mktemp then rename. Portable
  # across every distro the script targets.
  tmp_raw=$(mktemp)
  tmp="${tmp_raw}.json"
  mv "$tmp_raw" "$tmp"
  chmod 600 "$tmp"
  cat > "$tmp" <<EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "tag": "in-vless-reality",
      "listen": "0.0.0.0",
      "port": $LISTEN_PORT,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$CLIENT_UUID",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "$REALITY_DEST_HOST:$REALITY_DEST_PORT",
          "xver": 0,
          "serverNames": ["$REALITY_DEST_HOST"],
          "privateKey": "$REALITY_PRIVATE_KEY",
          "shortIds": ["$SHORT_ID"]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls", "quic"]
      }
    }
  ],
  "outbounds": [
    {
      "tag": "out-socks-tunnel",
      "protocol": "socks",
      "settings": {
        "servers": [
          {
            "address": "$SOCKS_HOST",
            "port": $SOCKS_PORT
          }
        ]
      },
      "streamSettings": {
        "sockopt": {
          "tcpKeepAliveIdle": 60,
          "tcpKeepAliveInterval": 15
        }
      }
    },
    {
      "tag": "out-block",
      "protocol": "blackhole"
    }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "ip": ["geoip:private"],
        "outboundTag": "out-block"
      },
      {
        "type": "field",
        "ip": ["geoip:ir"],
        "outboundTag": "out-block"
      },
      {
        "type": "field",
        "domain": ["geosite:category-ir"],
        "outboundTag": "out-block"
      },
      {
        "type": "field",
        "network": "tcp,udp",
        "outboundTag": "out-socks-tunnel"
      }
    ]
  }
}
EOF

  # Validate before applying — a bad config would prevent systemd from
  # starting and locks the user out of his/her own restart.
  if ! xray -test -config "$tmp" >/dev/null 2>&1; then
    err "generated config FAILED xray's own validator. Output:"
    xray -test -config "$tmp" || true
    rm -f "$tmp"
    die "refusing to apply broken config"
  fi

  if [[ "$(file_md5 "$tmp")" == "$(file_md5 "$CONFIG_FILE")" ]]; then
    log "config is already up-to-date, no write needed"
    rm -f "$tmp"
    CONFIG_CHANGED=0
    # Enforce the required mode even when content didn't change —
    # previous runs of this script may have left mode 0600 which
    # blocks xray (runs as 'nobody'). Same for root:root ownership.
    if [[ -f "$CONFIG_FILE" ]]; then
      chmod 644 "$CONFIG_FILE"
      chown root:root "$CONFIG_FILE" 2>/dev/null || true
    fi
  else
    log "applying new config to $CONFIG_FILE"
    # 644 so the xray service user (typically 'nobody' per the
    # official systemd unit) can read it. The REALITY private key
    # lives in this file, so the parent dir /usr/local/etc/xray
    # MUST stay root-only by convention to avoid leaking it.
    install -m 644 "$tmp" "$CONFIG_FILE"
    rm -f "$tmp"
    CONFIG_CHANGED=1
  fi
}

# ---------------------------------------------------------------------------
# Step 4: open the firewall (best-effort; tolerate missing tools)
# ---------------------------------------------------------------------------
open_firewall() {
  log "opening firewall for port $LISTEN_PORT (best-effort)"
  if command -v ufw >/dev/null 2>&1; then
    if ufw status 2>/dev/null | grep -q "^Status: active"; then
      if ! ufw status | grep -qE "^$LISTEN_PORT/tcp.*ALLOW"; then
        ufw allow "$LISTEN_PORT"/tcp || warn "ufw allow failed; open it manually"
      fi
    fi
  fi
  if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
    if ! firewall-cmd --list-ports 2>/dev/null | tr ' ' '\n' | grep -qx "$LISTEN_PORT/tcp"; then
      firewall-cmd --permanent --add-port="$LISTEN_PORT"/tcp || warn "firewall-cmd add-port failed"
      firewall-cmd --reload || true
    fi
  fi
}

# ---------------------------------------------------------------------------
# Step 5: restart xray only when something we manage actually changed
# ---------------------------------------------------------------------------
restart_if_needed() {
  if [[ "${CONFIG_CHANGED:-0}" -eq 1 ]] || ! systemctl is-active --quiet xray; then
    log "restarting xray service"
    systemctl daemon-reload || true
    systemctl enable --now xray
    systemctl restart xray
  else
    log "no config change and xray is already running, skipping restart"
  fi

  sleep 1
  if systemctl is-active --quiet xray; then
    log "xray service is active"
  else
    err "xray service failed to start. journalctl -u xray --since '2 minutes ago' tail:"
    journalctl -u xray --since '2 minutes ago' --no-pager | tail -n 30 || true
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# Step 6: print the client connection URI
# ---------------------------------------------------------------------------
print_client_uri() {
  [[ "$PRINT_CLIENT" == "0" ]] && return 0
  local ip nic_ip egress_ip

  # Discover both possible IPs:
  #   nic_ip    — the source IP of outbound packets per the kernel
  #               routing table (what eth0 actually announces).
  #   egress_ip — the IP that ifconfig.me's HTTPS endpoint observed
  #               us coming from (some providers route outbound HTTPS
  #               through a different egress IP than the listening NIC).
  nic_ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {for (i=1;i<=NF;i++) if ($i=="src") print $(i+1); exit}' || true)
  egress_ip=$(curl -fsSL -4 --max-time 5 https://ifconfig.me 2>/dev/null || true)
  [[ -z "$egress_ip" ]] && egress_ip=$(curl -fsSL -4 --max-time 5 https://api.ipify.org 2>/dev/null || true)

  if [[ -n "${SERVER_PUBLIC_IP:-}" ]]; then
    ip="$SERVER_PUBLIC_IP"
  else
    # Prefer the NIC IP IF it's clearly a public-looking address
    # (some providers report a *different* egress IP via ifconfig.me
    # than the actual ingress IP — using the NIC IP is correct in
    # that case). Fall back to egress IP when the NIC IP is in a
    # private/CGNAT range (real CGNAT setup).
    if [[ -n "$nic_ip" ]] && ! is_private_ip "$nic_ip"; then
      ip="$nic_ip"
    elif [[ -n "$egress_ip" ]]; then
      ip="$egress_ip"
    else
      ip="<your-server-ip>"
    fi
  fi

  # If we have both a NIC IP and an egress IP and they differ, surface
  # the discrepancy so the user can manually pick the one that's
  # actually reachable from the outside.
  if [[ -n "$nic_ip" && -n "$egress_ip" && "$nic_ip" != "$egress_ip" ]]; then
    warn "split-egress detected:  NIC source IP = $nic_ip"
    warn "                        egress IP via ifconfig.me = $egress_ip"
    warn "Using ${ip} in the URI. If clients can't reach it, override with"
    warn "  SERVER_PUBLIC_IP=<the IP that 'nc -z -v <ip> $LISTEN_PORT' actually succeeds against>"
  fi

  local fingerprint="chrome"
  # Use a generic label rather than $(hostname) which would leak the
  # VPS's configured hostname through the vless:// fragment when the
  # URI is pasted into a client or shared.
  local label="XTLS-Reality"
  local enc_label="$label"

  cat <<EOF

================================================================
  Server is up. Connection URI for your client app (v2rayN /
  Hiddify / NekoBox / any modern Xray-aware client):
================================================================

vless://${CLIENT_UUID}@${ip}:${LISTEN_PORT}?security=reality&encryption=none&pbk=${REALITY_PUBLIC_KEY}&sni=${REALITY_DEST_HOST}&sid=${SHORT_ID}&type=tcp&flow=xtls-rprx-vision&fp=${fingerprint}#${enc_label}

================================================================
  Server-side details (keep private):
   - REALITY private key: ${REALITY_PRIVATE_KEY}
   - UUID:                ${CLIENT_UUID}
   - shortId:             ${SHORT_ID}
   - SNI mimic'd:         ${REALITY_DEST_HOST}
   - Outbound SOCKS:      ${SOCKS_HOST}:${SOCKS_PORT}
   - State file (kept across re-runs for idempotency): ${STATE_FILE}
================================================================

EOF
}

# ---------------------------------------------------------------------------
# Sanity: SOCKS upstream reachable (warn, don't fail — the SOCKS could
# be brought up after Xray and we don't want to block startup on it).
# ---------------------------------------------------------------------------
check_socks_upstream() {
  if command -v nc >/dev/null 2>&1; then
    if ! nc -z -w 2 "$SOCKS_HOST" "$SOCKS_PORT" 2>/dev/null; then
      warn "SOCKS upstream $SOCKS_HOST:$SOCKS_PORT is not currently reachable."
      warn "Xray will still start, but no traffic will flow until that proxy is up."
    fi
  fi
}

# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
main() {
  require_root
  install_xray
  provision_secrets
  install_geofiles
  write_config
  open_firewall
  check_socks_upstream
  restart_if_needed
  print_client_uri
}

main "$@"
