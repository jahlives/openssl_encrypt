#!/usr/bin/env bash
set -euo pipefail

# Generate backward-compatible test files using installed Flatpak versions.
# These files test that the current codebase can decrypt files produced by
# every prior release.
#
# Prerequisites:
#   flatpak install com.opensslencrypt.OpenSSLEncrypt//1.0.0-stable
#   flatpak install com.opensslencrypt.OpenSSLEncrypt//1.0.3-stable
#   flatpak install com.opensslencrypt.OpenSSLEncrypt//1.1.0-stable
#   flatpak install com.opensslencrypt.OpenSSLEncrypt//1.2.1-stable
#   flatpak install com.opensslencrypt.OpenSSLEncrypt//1.3.6-stable
#
# Usage:
#   bash scripts/generate_testfiles_flatpak.sh          # generate missing files
#   bash scripts/generate_testfiles_flatpak.sh --force   # regenerate all files
#   bash scripts/generate_testfiles_flatpak.sh --dryrun  # show commands only

APP_ID="com.opensslencrypt.OpenSSLEncrypt"
PASSWORD="1234"
CONTENT="Hello World"
BASE_DIR="openssl_encrypt/unittests/testfiles"
TMP_INPUT="/tmp/flatpak_testgen_input.txt"

FORCE=false
DRY_RUN=false

# --- Parse options ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --force)  FORCE=true;   shift ;;
        --dryrun) DRY_RUN=true; shift ;;
        -h|--help)
            echo "Usage: $0 [--force] [--dryrun]"
            echo "  --force   Regenerate files even if they already exist"
            echo "  --dryrun  Print commands without executing"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# --- Counters ---
CREATED=0
SKIPPED=0
FAILED=0

# --- Helper: run a single Flatpak encrypt command ---
# Arguments: flatpak_branch  output_dir  filename  encrypt_args...
generate() {
    local branch="$1"; shift
    local outdir="$1"; shift
    local filename="$1"; shift
    local outpath="${outdir}/${filename}"

    if [[ "$FORCE" = false && -f "$outpath" ]]; then
        echo "  SKIP (exists): ${outpath}"
        ((SKIPPED++)) || true
        return 0
    fi

    local cmd="flatpak run ${APP_ID}//${branch} encrypt -i ${TMP_INPUT} -o ${outpath} --password ${PASSWORD} --force-password $*"

    if [[ "$DRY_RUN" = true ]]; then
        echo "  DRY RUN: $cmd"
        return 0
    fi

    echo -n "  Generating: ${outpath} ... "
    if eval "$cmd" > /dev/null 2>&1; then
        if [[ -f "$outpath" ]]; then
            echo "OK"
            ((CREATED++)) || true
        else
            echo "FAIL (file not created)"
            ((FAILED++)) || true
        fi
    else
        echo "FAIL (command error)"
        ((FAILED++)) || true
    fi
}

# --- Preparation ---
echo "=== Flatpak Test File Generator ==="
echo ""

if [[ "$DRY_RUN" = false ]]; then
    echo "${CONTENT}" > "${TMP_INPUT}"
fi

# Create output directories
mkdir -p "${BASE_DIR}/v5"
mkdir -p "${BASE_DIR}/v7"

V5="${BASE_DIR}/v5"
V7="${BASE_DIR}/v7"

# =====================================================================
# v1.0.0 → format_version 5 → v5/   (6 non-PQC + 2 PQC = 8 files)
# =====================================================================
echo ""
echo "--- Flatpak v1.0.0 (format v5) ---"

generate "1.0.0-stable" "$V5" "test1_fp100_aesgcm_default.txt" \
    --algorithm aes-gcm

generate "1.0.0-stable" "$V5" "test1_fp100_chacha_sha512_argon2.txt" \
    --algorithm chacha20-poly1305 --sha512-rounds 2 --enable-argon2

generate "1.0.0-stable" "$V5" "test1_fp100_xchacha_sha256_sha3512_scrypt.txt" \
    --algorithm xchacha20-poly1305 --sha256-rounds 2 --sha3-512-rounds 2 --enable-scrypt

generate "1.0.0-stable" "$V5" "test1_fp100_aessiv_blake2b_balloon.txt" \
    --algorithm aes-siv --blake2b-rounds 2 --enable-balloon

generate "1.0.0-stable" "$V5" "test1_fp100_aesgcmsiv_sha3256_sha512_argon2_scrypt.txt" \
    --algorithm aes-gcm-siv --sha3-256-rounds 2 --sha512-rounds 2 --enable-argon2 --enable-scrypt

generate "1.0.0-stable" "$V5" "test1_fp100_fernet_shake256_argon2.txt" \
    --algorithm fernet --shake256-rounds 2 --enable-argon2

# PQC (v1.0.0): hqc-128-hybrid OK, ml-kem-768-chacha20 OK
generate "1.0.0-stable" "$V5" "test1_fp100_hqc128hybrid_sha512_argon2.txt" \
    --algorithm hqc-128-hybrid --sha512-rounds 2 --enable-argon2 --pqc-store-key

generate "1.0.0-stable" "$V5" "test1_fp100_mlkem768chacha20_sha256_scrypt.txt" \
    --algorithm ml-kem-768-chacha20 --sha256-rounds 2 --enable-scrypt --pqc-store-key

# =====================================================================
# v1.0.3 → format_version 5 → v5/   (6 non-PQC + 2 PQC = 8 files)
# =====================================================================
echo ""
echo "--- Flatpak v1.0.3 (format v5) ---"

generate "1.0.3-stable" "$V5" "test1_fp103_aesgcm_default.txt" \
    --algorithm aes-gcm

generate "1.0.3-stable" "$V5" "test1_fp103_chacha_sha384_blake3_argon2.txt" \
    --algorithm chacha20-poly1305 --sha384-rounds 2 --blake3-rounds 2 --enable-argon2

generate "1.0.3-stable" "$V5" "test1_fp103_aessiv_sha3384_shake128_scrypt.txt" \
    --algorithm aes-siv --sha3-384-rounds 2 --shake128-rounds 2 --enable-scrypt

generate "1.0.3-stable" "$V5" "test1_fp103_xchacha_sha512_blake2b_argon2_scrypt.txt" \
    --algorithm xchacha20-poly1305 --sha512-rounds 2 --blake2b-rounds 2 --enable-argon2 --enable-scrypt

generate "1.0.3-stable" "$V5" "test1_fp103_aesgcmsiv_sha256_sha3512_balloon.txt" \
    --algorithm aes-gcm-siv --sha256-rounds 2 --sha3-512-rounds 2 --enable-balloon

generate "1.0.3-stable" "$V5" "test1_fp103_fernet_sha3256_blake3_argon2_balloon.txt" \
    --algorithm fernet --sha3-256-rounds 2 --blake3-rounds 2 --enable-argon2 --enable-balloon

# PQC (v1.0.3): hqc-128-hybrid OK, ml-kem-512-chacha20 OK
generate "1.0.3-stable" "$V5" "test1_fp103_hqc128hybrid_sha384_argon2_hkdf.txt" \
    --algorithm hqc-128-hybrid --sha384-rounds 2 --enable-argon2 --enable-hkdf --pqc-store-key

generate "1.0.3-stable" "$V5" "test1_fp103_mlkem512chacha20_blake3_sha512_scrypt.txt" \
    --algorithm ml-kem-512-chacha20 --blake3-rounds 2 --sha512-rounds 2 --enable-scrypt --pqc-store-key

# =====================================================================
# v1.1.0 → format_version 5 → v5/   (6 non-PQC + 2 PQC = 8 files)
# =====================================================================
echo ""
echo "--- Flatpak v1.1.0 (format v5) ---"

generate "1.1.0-stable" "$V5" "test1_fp110_chacha_default.txt" \
    --algorithm chacha20-poly1305

generate "1.1.0-stable" "$V5" "test1_fp110_aesgcm_sha512_sha3256_argon2.txt" \
    --algorithm aes-gcm --sha512-rounds 2 --sha3-256-rounds 2 --enable-argon2

generate "1.1.0-stable" "$V5" "test1_fp110_fernet_blake3_shake128_scrypt.txt" \
    --algorithm fernet --blake3-rounds 2 --shake128-rounds 2 --enable-scrypt

generate "1.1.0-stable" "$V5" "test1_fp110_aesgcmsiv_sha384_sha3384_balloon.txt" \
    --algorithm aes-gcm-siv --sha384-rounds 2 --sha3-384-rounds 2 --enable-balloon

generate "1.1.0-stable" "$V5" "test1_fp110_xchacha_blake2b_sha256_argon2_scrypt.txt" \
    --algorithm xchacha20-poly1305 --blake2b-rounds 2 --sha256-rounds 2 --enable-argon2 --enable-scrypt

generate "1.1.0-stable" "$V5" "test1_fp110_aessiv_sha3512_shake256_argon2_balloon.txt" \
    --algorithm aes-siv --sha3-512-rounds 2 --shake256-rounds 2 --enable-argon2 --enable-balloon

# PQC (v1.1.0): hqc-128-hybrid OK, ml-kem-512-chacha20 OK
generate "1.1.0-stable" "$V5" "test1_fp110_hqc128hybrid_sha3384_argon2.txt" \
    --algorithm hqc-128-hybrid --sha3-384-rounds 2 --enable-argon2 --pqc-store-key

generate "1.1.0-stable" "$V5" "test1_fp110_mlkem512chacha20_sha256_hkdf.txt" \
    --algorithm ml-kem-512-chacha20 --sha256-rounds 2 --enable-hkdf --pqc-store-key

# =====================================================================
# v1.2.1 → format_version 5 → v5/   (6 non-PQC + 2 PQC = 8 files)
# =====================================================================
echo ""
echo "--- Flatpak v1.2.1 (format v5) ---"

generate "1.2.1-stable" "$V5" "test1_fp121_fernet_default.txt" \
    --algorithm fernet

generate "1.2.1-stable" "$V5" "test1_fp121_aesgcm_blake3_sha3384_argon2.txt" \
    --algorithm aes-gcm --blake3-rounds 2 --sha3-384-rounds 2 --enable-argon2

generate "1.2.1-stable" "$V5" "test1_fp121_chacha_sha256_shake128_scrypt.txt" \
    --algorithm chacha20-poly1305 --sha256-rounds 2 --shake128-rounds 2 --enable-scrypt

generate "1.2.1-stable" "$V5" "test1_fp121_aessiv_sha512_blake2b_balloon.txt" \
    --algorithm aes-siv --sha512-rounds 2 --blake2b-rounds 2 --enable-balloon

generate "1.2.1-stable" "$V5" "test1_fp121_aesgcmsiv_sha384_sha3256_argon2_balloon.txt" \
    --algorithm aes-gcm-siv --sha384-rounds 2 --sha3-256-rounds 2 --enable-argon2 --enable-balloon

generate "1.2.1-stable" "$V5" "test1_fp121_xchacha_sha3512_shake256_argon2_scrypt.txt" \
    --algorithm xchacha20-poly1305 --sha3-512-rounds 2 --shake256-rounds 2 --enable-argon2 --enable-scrypt

# PQC (v1.2.1): ml-kem-768-hybrid OK, hqc-256-hybrid OK (all PQC works)
generate "1.2.1-stable" "$V5" "test1_fp121_mlkem768hybrid_sha512_argon2.txt" \
    --algorithm ml-kem-768-hybrid --sha512-rounds 2 --enable-argon2 --pqc-store-key

generate "1.2.1-stable" "$V5" "test1_fp121_hqc256hybrid_blake3_scrypt_hkdf.txt" \
    --algorithm hqc-256-hybrid --blake3-rounds 2 --enable-scrypt --enable-hkdf --pqc-store-key

# =====================================================================
# v1.3.6 → format_version 7 → v7/   (6 non-PQC, 0 PQC — PQC broken)
# Argon2+RandomX auto-enabled. --kdf-rounds 1 minimizes RandomX time.
# Hash rounds bypass the interactive security prompt.
# =====================================================================
echo ""
echo "--- Flatpak v1.3.6 (format v7) ---"

generate "1.3.6-stable" "$V7" "test1_fp136_aesgcm_sha512_kdf1.txt" \
    --algorithm aes-gcm --sha512-rounds 2 --kdf-rounds 1

generate "1.3.6-stable" "$V7" "test1_fp136_chacha_sha256_sha3512_kdf1_scrypt.txt" \
    --algorithm chacha20-poly1305 --sha256-rounds 2 --sha3-512-rounds 2 --kdf-rounds 1 --enable-scrypt

generate "1.3.6-stable" "$V7" "test1_fp136_xchacha_blake3_sha384_kdf1.txt" \
    --algorithm xchacha20-poly1305 --blake3-rounds 2 --sha384-rounds 2 --kdf-rounds 1

generate "1.3.6-stable" "$V7" "test1_fp136_aessiv_sha3256_blake2b_kdf1.txt" \
    --algorithm aes-siv --sha3-256-rounds 2 --blake2b-rounds 2 --kdf-rounds 1

generate "1.3.6-stable" "$V7" "test1_fp136_aesgcmsiv_sha256_sha3384_kdf1.txt" \
    --algorithm aes-gcm-siv --sha256-rounds 2 --sha3-384-rounds 2 --kdf-rounds 1

generate "1.3.6-stable" "$V7" "test1_fp136_fernet_sha512_shake256_kdf1.txt" \
    --algorithm fernet --sha512-rounds 2 --shake256-rounds 2 --kdf-rounds 1

# --- Cleanup ---
if [[ "$DRY_RUN" = false ]]; then
    rm -f "${TMP_INPUT}"
fi

# --- Summary ---
echo ""
echo "=== Summary ==="
echo "  Created: ${CREATED}"
echo "  Skipped: ${SKIPPED}"
echo "  Failed:  ${FAILED}"

if [[ ${FAILED} -gt 0 ]]; then
    echo ""
    echo "WARNING: ${FAILED} file(s) failed to generate!"
    exit 1
fi

echo ""
echo "Done."
