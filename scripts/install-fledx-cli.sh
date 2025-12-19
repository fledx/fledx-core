#!/bin/sh
set -eu

# Enable pipefail when the shell supports it.
(set -o pipefail) 2>/dev/null && set -o pipefail

REPO_DEFAULT="fledx/fledx-core"
BIN_NAME="fledx"

die() {
  echo "error: $*" >&2
  exit 1
}

note() {
  echo "note: $*" >&2
}

usage() {
  cat <<'USAGE'
Install the fledx CLI from the latest GitHub Release.

Usage:
  curl -fsSL https://raw.githubusercontent.com/fledx/fledx-core/main/scripts/install-fledx-cli.sh | sh

Options:
  --version <vX.Y.Z|X.Y.Z|nightly|latest>
                                  Install a specific version or tag
                                  (default: latest)
  -b, --bin-dir <DIR>             Install directory (default: /usr/local/bin if root,
                                  otherwise $HOME/.local/bin)
  --repo <OWNER/REPO>             GitHub repo (default: fledx/fledx-core)
  --require-signature             Require Ed25519 signature verification
  --insecure-skip-signature       Skip Ed25519 signature verification
  -h, --help                      Show help

Signature verification:
  By default, the script verifies the downloaded archive against the published
  .sha256 file. If you also want authenticity verification, provide a trusted
  Ed25519 public key allowlist via:

    export FLEDX_RELEASE_SIGNING_ED25519_PUBKEYS="0x<64-hex>,ssh-ed25519 <b64>"

  The release contains a raw 64-byte signature file: *.sha256.sig.

Examples:
  curl -fsSL https://raw.githubusercontent.com/fledx/fledx-core/main/scripts/install-fledx-cli.sh | sh -s -- -b /usr/local/bin
  curl -fsSL https://raw.githubusercontent.com/fledx/fledx-core/main/scripts/install-fledx-cli.sh | sh -s -- --version v0.4.0
  curl -fsSL https://raw.githubusercontent.com/fledx/fledx-core/main/scripts/install-fledx-cli.sh | sh -s -- --version nightly
USAGE
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

hex_to_bin() {
  hex="$1"

  if command -v xxd >/dev/null 2>&1; then
    printf '%s' "$hex" | xxd -r -p
    return 0
  fi

  if command -v python3 >/dev/null 2>&1; then
    python3 - "$hex" <<'PY'
import binascii
import sys

sys.stdout.buffer.write(binascii.unhexlify(sys.argv[1].strip()))
PY
    return 0
  fi

  if command -v perl >/dev/null 2>&1; then
    perl -e 'print pack("H*", $ARGV[0])' "$hex"
    return 0
  fi

  if command -v awk >/dev/null 2>&1; then
    awk -v hex="$hex" '
      function hexval(c) {
        c = tolower(c)
        return index("0123456789abcdef", c) - 1
      }
      function hexbyte(s,    hi, lo) {
        hi = hexval(substr(s, 1, 1))
        lo = hexval(substr(s, 2, 1))
        return (hi * 16) + lo
      }
      BEGIN {
        gsub(/[[:space:]]/, "", hex)
        if (length(hex) % 2 != 0) {
          exit 2
        }
        for (i = 1; i <= length(hex); i += 2) {
          printf "%c", hexbyte(substr(hex, i, 2))
        }
      }
    ' || die "failed to decode hex to binary"
    return 0
  fi

  die "missing tool to decode hex (install xxd, python3, perl, or awk)"
}

curl_get() {
  url="$1"
  out="$2"

  # Prefer strict TLS settings when curl supports them.
  if curl --help 2>/dev/null | grep -q -- '--proto'; then
    curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --retry-delay 1 \
      -H "Accept: application/vnd.github+json" \
      ${GITHUB_TOKEN:+-H "Authorization: Bearer $GITHUB_TOKEN"} \
      -o "$out" "$url"
  else
    curl -fsSL --retry 3 --retry-delay 1 \
      -H "Accept: application/vnd.github+json" \
      ${GITHUB_TOKEN:+-H "Authorization: Bearer $GITHUB_TOKEN"} \
      -o "$out" "$url"
  fi
}

github_latest_tag() {
  repo="$1"
  tmp_json="$2"

  api="https://api.github.com/repos/${repo}/releases/latest"
  curl_get "$api" "$tmp_json"

  # Extract "tag_name": "vX.Y.Z" from GitHub's JSON without jq.
  tag="$(tr -d '\n' < "$tmp_json" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
  [ -n "$tag" ] || die "failed to parse latest tag from GitHub API response"
  echo "$tag"
}

normalize_arch() {
  raw="$(uname -m 2>/dev/null || echo unknown)"
  case "$raw" in
    x86_64|amd64) echo "x86_64" ;;
    aarch64|arm64) echo "aarch64" ;;
    *) die "unsupported architecture: $raw" ;;
  esac
}

normalize_os() {
  raw="$(uname -s 2>/dev/null || echo unknown)"
  case "$raw" in
    Linux) echo "linux" ;;
    *) die "unsupported OS: $raw (supported: Linux)" ;;
  esac
}

sha256_hex_file() {
  file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$file" | awk '{print $NF}'
  else
    die "missing sha256 tool (sha256sum, shasum, or openssl)"
  fi
}

verify_sha256_file() {
  archive="$1"
  sha_file="$2"

  expected="$(sed 's/[[:space:]].*$//' "$sha_file" | tr 'A-F' 'a-f')"
  [ -n "$expected" ] || die "invalid sha256 file (missing hash): $sha_file"

  actual="$(sha256_hex_file "$archive" | tr 'A-F' 'a-f')"
  if [ "$expected" != "$actual" ]; then
    die "sha256 mismatch for $(basename "$archive") (expected $expected, got $actual)"
  fi
}

normalize_pubkey_hex() {
  raw="$1"
  trimmed="$(printf '%s' "$raw" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  case "$trimmed" in
    ssh-ed25519*)
      if ! ssh_ed25519_parser_available; then
        die "ssh-ed25519 public keys require python3, python, or perl to parse; provide 64-hex instead"
      fi
      key="$(ssh_ed25519_to_hex "$trimmed" 2>/dev/null || true)"
      [ -n "$key" ] || return 1
      echo "$key"
      return 0
      ;;
  esac

  key="$(printf '%s' "$trimmed" | tr -d '[:space:]' | tr 'A-F' 'a-f')"
  key="${key#0x}"
  key="${key#0X}"

  echo "$key" | grep -Eq '^[0-9a-f]{64}$' || return 1
  echo "$key"
}

ssh_ed25519_parser_available() {
  command -v python3 >/dev/null 2>&1 && return 0
  command -v python >/dev/null 2>&1 && return 0
  command -v perl >/dev/null 2>&1 && return 0
  return 1
}

ssh_ed25519_to_hex() {
  key="$1"

  if command -v python3 >/dev/null 2>&1; then
    python3 - "$key" <<'PY'
import base64
import sys

key = sys.argv[1].strip()
parts = key.split()
if len(parts) < 2 or parts[0] != "ssh-ed25519":
    sys.exit(1)

try:
    blob = base64.b64decode(parts[1])
except Exception:
    sys.exit(1)

def read_str(buf, off):
    if off + 4 > len(buf):
        raise ValueError
    n = int.from_bytes(buf[off:off+4], "big")
    off += 4
    if off + n > len(buf):
        raise ValueError
    return buf[off:off+n], off + n

try:
    t, off = read_str(blob, 0)
    if t != b"ssh-ed25519":
        raise ValueError
    k, off = read_str(blob, off)
    if len(k) != 32 or off != len(blob):
        raise ValueError
    print(k.hex())
except Exception:
    sys.exit(1)
PY
    return $?
  fi

  if command -v python >/dev/null 2>&1; then
    python - "$key" <<'PY'
import base64
import sys

key = sys.argv[1].strip()
parts = key.split()
if len(parts) < 2 or parts[0] != "ssh-ed25519":
    sys.exit(1)

try:
    blob = base64.b64decode(parts[1])
except Exception:
    sys.exit(1)

def read_str(buf, off):
    if off + 4 > len(buf):
        raise ValueError
    n = int.from_bytes(buf[off:off+4], "big")
    off += 4
    if off + n > len(buf):
        raise ValueError
    return buf[off:off+n], off + n

try:
    t, off = read_str(blob, 0)
    if t != b"ssh-ed25519":
        raise ValueError
    k, off = read_str(blob, off)
    if len(k) != 32 or off != len(blob):
        raise ValueError
    sys.stdout.write(k.hex())
except Exception:
    sys.exit(1)
PY
    return $?
  fi

  if command -v perl >/dev/null 2>&1; then
    perl -MMIME::Base64 -e '
use strict;
use warnings;
my $key = shift // "";
$key =~ s/^\s+|\s+$//g;
my @parts = split /\s+/, $key;
exit 1 if @parts < 2 || $parts[0] ne "ssh-ed25519";
my $blob = MIME::Base64::decode_base64($parts[1]);
my $off = 0;
sub read_str {
  my ($buf, $offref) = @_;
  return undef if $$offref + 4 > length($buf);
  my $len = unpack("N", substr($buf, $$offref, 4));
  $$offref += 4;
  return undef if $$offref + $len > length($buf);
  my $out = substr($buf, $$offref, $len);
  $$offref += $len;
  return $out;
}
my $type = read_str($blob, \$off) // exit 1;
exit 1 if $type ne "ssh-ed25519";
my $key_bytes = read_str($blob, \$off) // exit 1;
exit 1 if length($key_bytes) != 32 || $off != length($blob);
print unpack("H*", $key_bytes);
' "$key"
    return $?
  fi

  return 1
}

verify_ed25519_signature() {
  sha_file="$1"
  sig_file="$2"
  keys_csv="$3"

  [ -f "$sig_file" ] || die "signature file not found: $sig_file"

  need_cmd openssl

  sig_size="$(wc -c < "$sig_file" | tr -d ' ')"
  [ "$sig_size" -eq 64 ] || die "unexpected signature length: $sig_size bytes (expected 64)"

  ok=0
  old_ifs="$IFS"
  IFS=','
  for raw_key in $keys_csv; do
    IFS="$old_ifs"

    key="$(normalize_pubkey_hex "$raw_key" 2>/dev/null || true)"
    if [ -z "$key" ]; then
      IFS=','
      continue
    fi

    der_hex="302a300506032b6570032100${key}"
    der_path="$TMPDIR/pubkey.der"
    pem_path="$TMPDIR/pubkey.pem"

    hex_to_bin "$der_hex" > "$der_path"
    openssl pkey -pubin -inform DER -in "$der_path" -out "$pem_path" >/dev/null 2>&1 || {
      IFS=','
      continue
    }

    if openssl pkeyutl -verify -pubin -inkey "$pem_path" -rawin \
      -in "$sha_file" -sigfile "$sig_file" >/dev/null 2>&1; then
      ok=1
      break
    fi

    IFS=','
  done
  IFS="$old_ifs"

  [ "$ok" -eq 1 ] || die "ed25519 signature verification failed"
}

VERSION="latest"
INSTALL_DIR=""
REPO="$REPO_DEFAULT"
REQUIRE_SIGNATURE="0"
SKIP_SIGNATURE="0"

while [ $# -gt 0 ]; do
  case "$1" in
    --version)
      [ $# -ge 2 ] || die "--version requires a value"
      VERSION="$2"
      shift 2
      ;;
    --version=*)
      VERSION="${1#*=}"
      shift 1
      ;;
    -b|--bin-dir|--install-dir)
      [ $# -ge 2 ] || die "$1 requires a value"
      INSTALL_DIR="$2"
      shift 2
      ;;
    --repo)
      [ $# -ge 2 ] || die "--repo requires a value"
      REPO="$2"
      shift 2
      ;;
    --require-signature)
      REQUIRE_SIGNATURE="1"
      shift 1
      ;;
    --insecure-skip-signature)
      SKIP_SIGNATURE="1"
      shift 1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1 (use --help)"
      ;;
  esac
done

need_cmd curl
need_cmd tar

ARCH="$(normalize_arch)"
OS="$(normalize_os)"

if [ -z "$INSTALL_DIR" ]; then
  if command -v id >/dev/null 2>&1 && [ "$(id -u)" -eq 0 ]; then
    INSTALL_DIR="/usr/local/bin"
  else
    INSTALL_DIR="${HOME}/.local/bin"
  fi
fi

mkdir -p "$INSTALL_DIR"

TMPDIR="$(mktemp -d 2>/dev/null || mktemp -d -t fledx-install)"
trap 'rm -rf "$TMPDIR"' EXIT INT TERM HUP

if [ "$(printf '%s' "$VERSION" | tr 'A-Z' 'a-z')" = "latest" ]; then
  TAG="$(github_latest_tag "$REPO" "$TMPDIR/release.json")"
else
  case "$VERSION" in
    v*) TAG="$VERSION" ;;
    [0-9]*) TAG="v$VERSION" ;;
    *) TAG="$VERSION" ;;
  esac
fi

VER="${TAG#v}"
ASSET="${BIN_NAME}-${VER}-${ARCH}-${OS}.tar.gz"
BASE="https://github.com/${REPO}/releases/download/${TAG}"

ARCHIVE="$TMPDIR/${ASSET}"
SHA_FILE="$TMPDIR/${ASSET}.sha256"
SIG_FILE="$TMPDIR/${ASSET}.sha256.sig"

note "repo: $REPO"
note "tag: $TAG"
note "asset: $ASSET"

curl_get "${BASE}/${ASSET}" "$ARCHIVE"
curl_get "${BASE}/${ASSET}.sha256" "$SHA_FILE"

# Signature is optional by default (can be enforced with --require-signature).
sig_downloaded="0"
if curl_get "${BASE}/${ASSET}.sha256.sig" "$SIG_FILE" 2>/dev/null; then
  sig_downloaded="1"
fi

if [ "$SKIP_SIGNATURE" -ne 1 ]; then
  keys="${FLEDX_RELEASE_SIGNING_ED25519_PUBKEYS:-}"
  if [ -n "$keys" ]; then
    if [ "$sig_downloaded" -ne 1 ]; then
      die "signature verification requested by keys but signature file is missing"
    fi
    verify_ed25519_signature "$SHA_FILE" "$SIG_FILE" "$keys"
  else
    if [ "$sig_downloaded" -eq 1 ]; then
      note "signature file present but no trusted public keys configured"
      note "export FLEDX_RELEASE_SIGNING_ED25519_PUBKEYS=0x<64-hex>[,...] or ssh-ed25519 <b64> to verify authenticity"
    fi
    if [ "$REQUIRE_SIGNATURE" -eq 1 ]; then
      die "missing FLEDX_RELEASE_SIGNING_ED25519_PUBKEYS (required for signature verification)"
    fi
  fi
else
  if [ "$REQUIRE_SIGNATURE" -eq 1 ]; then
    die "--require-signature and --insecure-skip-signature are mutually exclusive"
  fi
  note "skipping signature verification (--insecure-skip-signature)"
fi

verify_sha256_file "$ARCHIVE" "$SHA_FILE"

tar -xzf "$ARCHIVE" -C "$TMPDIR"
[ -f "$TMPDIR/$BIN_NAME" ] || die "archive did not contain expected binary: $BIN_NAME"

target="$INSTALL_DIR/$BIN_NAME"
if command -v install >/dev/null 2>&1; then
  install -m 0755 "$TMPDIR/$BIN_NAME" "$target"
else
  cp "$TMPDIR/$BIN_NAME" "$target"
  chmod 0755 "$target"
fi

echo "Installed $BIN_NAME $VER to $target" >&2

case ":${PATH}:" in
  *":$INSTALL_DIR:"*) : ;;
  *)
    note "add $INSTALL_DIR to your PATH to run '$BIN_NAME' without a full path"
    ;;
esac
