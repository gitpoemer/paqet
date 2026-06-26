#!/usr/bin/env bash
#
# ====== ONE-LINERS (curl-from-GitHub direct) =================================
#
#  Install / refresh paqet to the latest release at /opt/paqet/paqet:
#
#    curl -fsSL https://raw.githubusercontent.com/gitpoemer/paqet/optimize/update-paqet.sh | sudo bash
#
#  Pin to a specific release tag (e.g. for version-comparing in testing):
#
#    curl -fsSL https://raw.githubusercontent.com/gitpoemer/paqet/optimize/update-paqet.sh \
#      | sudo PAQET_TAG=v1.0.0-alpha.33-scale bash
#
#  Custom install location:
#
#    curl -fsSL https://raw.githubusercontent.com/gitpoemer/paqet/optimize/update-paqet.sh \
#      | sudo PAQET_PREFIX=/usr/local/paqet bash
#
#  Force re-download even if the desired tag is already installed:
#
#    curl -fsSL https://raw.githubusercontent.com/gitpoemer/paqet/optimize/update-paqet.sh \
#      | sudo PAQET_FORCE=1 bash
#
#  All optional env vars (defaults shown):
#    PAQET_TAG=<latest>         # release tag — empty means query the latest
#    PAQET_PREFIX=/opt/paqet    # binary lands at $PAQET_PREFIX/paqet
#    PAQET_REPO=gitpoemer/paqet # release source
#    PAQET_ARCH=<auto>          # override the arch — useful when uname -m
#                               # disagrees with paqet's release naming
#    PAQET_FORCE=0              # 1 to redownload even when tag matches
#
#  Idempotency: stores the currently installed tag at
#  $PAQET_PREFIX/.version. If the requested tag matches what's already
#  there AND the binary is present, the script exits without touching
#  anything. Set PAQET_FORCE=1 to override.
#
#  NO service handling, NO config writing, NO systemd touch. This script
#  just places the binary. Use it to flip between versions during testing.
#
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Tunables (all overridable via environment)
# ---------------------------------------------------------------------------
PAQET_TAG="${PAQET_TAG:-}"
PAQET_PREFIX="${PAQET_PREFIX:-/opt/paqet}"
PAQET_REPO="${PAQET_REPO:-gitpoemer/paqet}"
PAQET_ARCH="${PAQET_ARCH:-}"
PAQET_FORCE="${PAQET_FORCE:-0}"

VERSION_FILE="$PAQET_PREFIX/.version"
BINARY_PATH="$PAQET_PREFIX/paqet"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { printf '\033[1;34m[update-paqet]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m         %s\n' "$*" >&2; }
err()  { printf '\033[1;31m[err]\033[0m          %s\n' "$*" >&2; }
die()  { err "$*"; exit 1; }

require_root() {
  if [[ $EUID -ne 0 ]]; then
    die "must be run as root (or via sudo) — \$PAQET_PREFIX is system-owned"
  fi
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    die "missing required command: $1 (install via apt/dnf/apk)"
  fi
}

# ---------------------------------------------------------------------------
# Architecture detection — maps uname -m → paqet release's arch filename
# ---------------------------------------------------------------------------
detect_arch() {
  if [[ -n "$PAQET_ARCH" ]]; then
    echo "$PAQET_ARCH"
    return
  fi
  local m
  m=$(uname -m)
  case "$m" in
    x86_64|amd64)             echo "amd64"   ;;
    aarch64|arm64)            echo "arm64"   ;;
    armv7l|armv7|armhf|arm)   echo "arm32"   ;;
    mips)                     echo "mips"    ;;
    mipsel)                   echo "mipsle"  ;;
    mips64)                   echo "mips64"  ;;
    mips64el)                 echo "mips64le";;
    *)                        die "unsupported architecture '$m'; override with PAQET_ARCH=" ;;
  esac
}

# ---------------------------------------------------------------------------
# Resolve target tag — query GitHub for 'latest' if user didn't pin one
# ---------------------------------------------------------------------------
resolve_tag() {
  if [[ -n "$PAQET_TAG" ]]; then
    log "using pinned tag: $PAQET_TAG"
    return
  fi
  require_cmd curl
  require_cmd jq
  log "querying latest release of $PAQET_REPO"
  PAQET_TAG=$(curl -fsSL "https://api.github.com/repos/$PAQET_REPO/releases/latest" \
    | jq -r '.tag_name')
  if [[ -z "$PAQET_TAG" || "$PAQET_TAG" == "null" ]]; then
    die "could not resolve latest release tag from GitHub"
  fi
  log "latest release: $PAQET_TAG"
}

# ---------------------------------------------------------------------------
# Idempotency check — bail if already at the requested tag
# ---------------------------------------------------------------------------
is_already_installed() {
  [[ "$PAQET_FORCE" == "1" ]] && return 1
  [[ -x "$BINARY_PATH" ]] || return 1
  [[ -f "$VERSION_FILE" ]] || return 1
  local current
  current=$(cat "$VERSION_FILE" 2>/dev/null || true)
  [[ "$current" == "$PAQET_TAG" ]]
}

# ---------------------------------------------------------------------------
# Download + extract
# ---------------------------------------------------------------------------
install_paqet() {
  local arch tarball url tmpdir bin_name
  arch=$(detect_arch)
  bin_name="paqet_linux_${arch}"
  tarball="paqet-linux-${arch}-${PAQET_TAG}.tar.gz"
  url="https://github.com/$PAQET_REPO/releases/download/$PAQET_TAG/$tarball"

  log "downloading $tarball"
  tmpdir=$(mktemp -d)
  trap "rm -rf '$tmpdir'" RETURN

  if ! curl -fsSL "$url" -o "$tmpdir/$tarball"; then
    die "failed to download $url — wrong tag or arch? (try PAQET_TAG=…  PAQET_ARCH=…)"
  fi
  log "extracting"
  tar -xzf "$tmpdir/$tarball" -C "$tmpdir"

  if [[ ! -f "$tmpdir/$bin_name" ]]; then
    die "extracted archive did not contain $bin_name — release layout may have changed"
  fi

  install -d -m 755 "$PAQET_PREFIX"
  # Stage the new binary alongside the current one and atomically rename.
  # If paqet is currently running from $BINARY_PATH the rename is safe —
  # Linux keeps the old inode mapped for the running process.
  install -m 755 "$tmpdir/$bin_name" "$BINARY_PATH.new"
  mv -f "$BINARY_PATH.new" "$BINARY_PATH"
  echo "$PAQET_TAG" > "$VERSION_FILE"
  log "installed $PAQET_TAG → $BINARY_PATH"
}

# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
main() {
  require_root
  require_cmd curl
  require_cmd tar
  resolve_tag

  if is_already_installed; then
    log "paqet $PAQET_TAG already installed at $BINARY_PATH (use PAQET_FORCE=1 to re-download)"
    "$BINARY_PATH" version 2>/dev/null || true
    exit 0
  fi

  install_paqet

  log "verifying installed binary version output:"
  "$BINARY_PATH" version 2>/dev/null || warn "  '$BINARY_PATH version' did not produce output — binary may not support the subcommand"
}

main "$@"
