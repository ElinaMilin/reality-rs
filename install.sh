#!/usr/bin/env bash
# Debian one-click installer for reality-rs.
set -Eeuo pipefail
umask 077

APP="reality-rs"
INSTALL_DIR="/etc/${APP}"
BIN_PATH="/usr/local/bin/${APP}"
UNIT_PATH="/etc/systemd/system/${APP}.service"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

LISTEN="0.0.0.0:443"
SNI=""
FALLBACK=""
USER_UUID=""
SHORT_ID=""
BINARY_SOURCE="${REALITY_RS_BINARY:-}"
RELEASE_BASE_URL="${REALITY_RS_RELEASE_BASE_URL:-}"
EXPECTED_SHA256="${REALITY_RS_SHA256:-}"
ASSUME_YES=0
FORCE_CONFIG=0

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
note() { printf '\n==> %s\n' "$*"; }

usage() {
  cat <<'EOF'
Usage: sudo bash install.sh [options]

Options:
  --yes                 Do not prompt; use supplied values or defaults.
  --listen ADDR:PORT     Default: 0.0.0.0:443
  --sni NAME             Required for a new config, e.g. www.example.com.
  --fallback HOST:PORT   Default: SNI:443.
  --uuid UUID            Default: generated UUID.
  --short-id HEX         Default: generated 16-hex-character short ID.
  --binary FILE          Use a local Linux amd64 binary.
  --release-base-url URL Download binary and unit files from URL.
  --force-config         Replace an existing config after backing it up.
  --help                 Show this help.

Environment alternatives: REALITY_RS_BINARY and REALITY_RS_RELEASE_BASE_URL.
EOF
}

while (($#)); do
  case "$1" in
    --yes) ASSUME_YES=1 ;;
    --listen) LISTEN="${2:?missing value}"; shift ;;
    --sni) SNI="${2:?missing value}"; shift ;;
    --fallback) FALLBACK="${2:?missing value}"; shift ;;
    --uuid) USER_UUID="${2:?missing value}"; shift ;;
    --short-id) SHORT_ID="${2:?missing value}"; shift ;;
    --binary) BINARY_SOURCE="${2:?missing value}"; shift ;;
    --release-base-url) RELEASE_BASE_URL="${2:?missing value}"; RELEASE_BASE_URL="${RELEASE_BASE_URL%/}"; shift ;;
    --force-config) FORCE_CONFIG=1 ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
  shift
done

RELEASE_BASE_URL="${RELEASE_BASE_URL%/}"

[[ $EUID -eq 0 ]] || die "run this installer as root (for example: sudo bash install.sh)"
[[ -r /etc/os-release ]] || die "unsupported operating system"
. /etc/os-release
[[ ${ID:-} == "debian" || ${ID_LIKE:-} == *"debian"* ]] || die "this installer supports Debian-family systems only"
[[ $(uname -m) == "x86_64" || $(uname -m) == "amd64" ]] || die "this release supports x86_64 only"
command -v systemctl >/dev/null || die "systemd is required"
command -v python3 >/dev/null || { apt-get update; apt-get install -y python3; }
[[ $LISTEN =~ ^[A-Za-z0-9.:[\]-]+$ ]] || die "invalid listen address"

if [[ -z $BINARY_SOURCE ]]; then
  for candidate in "$SCRIPT_DIR/dist/reality-rs-linux-amd64" "$SCRIPT_DIR/target/x86_64-unknown-linux-gnu/release/reality-rs"; do
    [[ -f $candidate ]] && BINARY_SOURCE="$candidate" && break
  done
fi

TMP_DIR=""
cleanup() {
  if [[ -n $TMP_DIR ]]; then
    rm -rf -- "$TMP_DIR"
  fi
}
trap cleanup EXIT
if [[ -z $BINARY_SOURCE && -n $RELEASE_BASE_URL ]]; then
  command -v curl >/dev/null || { apt-get update; apt-get install -y curl; }
  TMP_DIR="$(mktemp -d)"
  BINARY_SOURCE="$TMP_DIR/reality-rs-linux-amd64"
  curl --fail --location --proto '=https' --tlsv1.2 "$RELEASE_BASE_URL/reality-rs-linux-amd64" -o "$BINARY_SOURCE"
  curl --fail --location --proto '=https' --tlsv1.2 "$RELEASE_BASE_URL/reality-rs-linux-amd64.sha256" -o "$TMP_DIR/reality-rs-linux-amd64.sha256"
  curl --fail --location --proto '=https' --tlsv1.2 "$RELEASE_BASE_URL/reality-rs.service" -o "$TMP_DIR/reality-rs.service"
  curl --fail --location --proto '=https' --tlsv1.2 "$RELEASE_BASE_URL/reality-rsctl" -o "$TMP_DIR/reality-rsctl"
  EXPECTED_SHA256="$(awk 'NR==1 { print $1 }' "$TMP_DIR/reality-rs-linux-amd64.sha256")"
fi
[[ -n $BINARY_SOURCE && -f $BINARY_SOURCE ]] || die "release binary not found; use --binary or --release-base-url"
if [[ -z $EXPECTED_SHA256 && -f "$SCRIPT_DIR/dist/reality-rs-linux-amd64.sha256" && $BINARY_SOURCE == "$SCRIPT_DIR/dist/reality-rs-linux-amd64" ]]; then
  EXPECTED_SHA256="$(awk 'NR==1 { print $1 }' "$SCRIPT_DIR/dist/reality-rs-linux-amd64.sha256")"
fi
if [[ -n $EXPECTED_SHA256 ]]; then
  [[ $EXPECTED_SHA256 =~ ^[A-Fa-f0-9]{64}$ ]] || die "invalid binary SHA-256"
  actual_sha256="$(sha256sum "$BINARY_SOURCE" | awk '{ print $1 }')"
  [[ ${actual_sha256,,} == ${EXPECTED_SHA256,,} ]] || die "binary SHA-256 verification failed"
fi

UNIT_SOURCE="$SCRIPT_DIR/packaging/reality-rs.service"
[[ -f $UNIT_SOURCE ]] || UNIT_SOURCE="${TMP_DIR:-}/reality-rs.service"
[[ -f $UNIT_SOURCE ]] || die "systemd unit file not found"
CTL_SOURCE="$SCRIPT_DIR/packaging/reality-rsctl"
[[ -f $CTL_SOURCE ]] || CTL_SOURCE="${TMP_DIR:-}/reality-rsctl"
[[ -f $CTL_SOURCE ]] || die "management tool not found"

note "Installing ${APP}"
install -d -m 0750 -o root -g root "$INSTALL_DIR"
id -u "$APP" >/dev/null 2>&1 || useradd --system --home /nonexistent --shell /usr/sbin/nologin "$APP"
install -m 0755 -o root -g root "$BINARY_SOURCE" "$BIN_PATH"
install -m 0644 -o root -g root "$UNIT_SOURCE" "$UNIT_PATH"
install -m 0755 -o root -g root "$CTL_SOURCE" /usr/local/bin/reality-rsctl

if [[ ! -f "$INSTALL_DIR/config.json" || $FORCE_CONFIG -eq 1 ]]; then
  if [[ -f "$INSTALL_DIR/config.json" ]]; then
    cp -a "$INSTALL_DIR/config.json" "$INSTALL_DIR/config.json.bak.$(date +%Y%m%d%H%M%S)"
  fi
  if [[ -z $SNI && $ASSUME_YES -eq 0 ]]; then read -r -p "REALITY SNI/domain (e.g. www.example.com): " SNI; fi
  [[ $SNI =~ ^[A-Za-z0-9.-]+$ ]] || die "SNI may contain only letters, numbers, dots, and hyphens"
  [[ -n $FALLBACK ]] || FALLBACK="$SNI:443"
  [[ $FALLBACK =~ ^[A-Za-z0-9.:-]+$ ]] || die "invalid fallback address"
  [[ -n $USER_UUID ]] || USER_UUID="$(cat /proc/sys/kernel/random/uuid)"
  [[ $USER_UUID =~ ^[0-9a-fA-F-]{36}$ ]] || die "invalid UUID"
  [[ -n $SHORT_ID ]] || SHORT_ID="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
  [[ $SHORT_ID =~ ^[0-9a-fA-F]{16}$ ]] || die "short ID must be exactly 16 hex characters"
  mapfile -t KEY_LINES < <("$BIN_PATH" keygen)
  PRIVATE_KEY="${KEY_LINES[0]#private_key=}"
  PUBLIC_KEY="${KEY_LINES[1]#public_key=}"
  [[ -n $PRIVATE_KEY && -n $PUBLIC_KEY ]] || die "could not generate REALITY keys"
  cat > "$INSTALL_DIR/config.json" <<EOF
{
  "listen": "$LISTEN",
  "users": ["$USER_UUID"],
  "reality": {
    "private_key": "$PRIVATE_KEY",
    "server_names": ["$SNI"],
    "short_ids": ["$SHORT_ID"],
    "max_time_diff_secs": 600,
    "fallback": "$FALLBACK"
  }
}
EOF
  chown root:"$APP" "$INSTALL_DIR/config.json"
  chmod 0640 "$INSTALL_DIR/config.json"
  cat > "/root/${APP}-v2rayn.txt" <<EOF
V2rayN fields
Protocol: VLESS
Address: <server IP or domain>
Port: ${LISTEN##*:}
UUID: $USER_UUID
Transport: TCP
Security: REALITY
SNI: $SNI
Fingerprint: chrome
Public key (pbk): $PUBLIC_KEY
Short ID (sid): $SHORT_ID
Flow: leave empty

VLESS URI:
vless://${USER_UUID}@<server-address>:${LISTEN##*:}?encryption=none&security=reality&sni=${SNI}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp#reality-rs
EOF
  chmod 0600 "/root/${APP}-v2rayn.txt"
else
  note "Existing config preserved (use --force-config to replace it)"
fi

systemctl daemon-reload
systemctl enable --now "$APP"
systemctl --no-pager --full status "$APP"

note "Installation complete"
if [[ -f "/root/${APP}-v2rayn.txt" ]]; then
  printf 'V2rayN connection details: /root/%s-v2rayn.txt\n' "$APP"
fi
