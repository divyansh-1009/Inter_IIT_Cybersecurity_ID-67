#!/bin/bash
# Generate genuine Dilithium (ML-DSA-44) certificates for PQC-DTLS 1.3.
#
# Uses OpenSSL's native ML-DSA support (OpenSSL >= 3.5). ML-DSA-44 is the
# FIPS 204 standardisation of CRYSTALS-Dilithium at NIST security level 2
# (commonly "Dilithium2"). No liboqs / OQS provider or wolfSSL certgen tool
# is required, which is why the previous certgen/Falcon/ECC fallback paths
# have been removed -- they silently produced classical ECC certificates.
#
# Outputs a CA plus CA-signed server and client certificates (PEM + DER), and
# regenerates the embedded C header boot/wolfssl/certs_dilithium_data.h that
# the RISC-V firmware compiles in.

set -euo pipefail

# Run from the repository root regardless of where the script is invoked.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

CERT_DIR="host/certs_dilithium"
HEADER_OUT="boot/wolfssl/certs_dilithium_data.h"
PQC_ALG="ML-DSA-44"          # FIPS 204, NIST level 2 (Dilithium2)
CA_DAYS=3650
LEAF_DAYS=1825

echo "=== Generating $PQC_ALG (Dilithium2) certificates ==="

# --- Preconditions -----------------------------------------------------------
if ! command -v openssl >/dev/null 2>&1; then
    echo "ERROR: openssl not found in PATH." >&2
    exit 1
fi
if ! openssl list -signature-algorithms 2>/dev/null | grep -qi "ML-DSA-44"; then
    echo "ERROR: this OpenSSL build has no native ML-DSA-44 support." >&2
    echo "       Need OpenSSL >= 3.5 (check: 'openssl list -signature-algorithms')." >&2
    exit 1
fi

# By default OpenSSL 3.5+ writes ML-DSA private keys in the "seed+expanded"
# (a.k.a. "both") PKCS#8 form. wolfSSL's decoder, when it sees a seed, ALWAYS
# regenerates the key from that seed via make_key_from_seed() -- which returns
# NOT_COMPILED_IN on a liboqs-backed build (the server's documented build path
# in install_pqc_wolfssl.sh). We therefore emit "priv-only" (expanded-only)
# keys, which decode straight into wolfSSL's import_private() path and work on
# both the wolfCrypt (firmware) and liboqs (server) builds. It also avoids a
# runtime key-expansion step on the 1 MHz client.
GENPKEY_FMT=""
if openssl genpkey -algorithm "$PQC_ALG" \
        -provparam ml-dsa.output_formats=priv-only \
        -out /dev/null >/dev/null 2>&1; then
    GENPKEY_FMT="-provparam ml-dsa.output_formats=priv-only"
    echo "Using expanded-only (priv-only) ML-DSA private-key encoding."
else
    echo "WARNING: this OpenSSL cannot emit priv-only ML-DSA keys; falling back" >&2
    echo "         to the default seed+expanded form. This will FAIL to load on" >&2
    echo "         a liboqs-backed wolfSSL build (upgrade to OpenSSL >= 3.5)." >&2
fi

mkdir -p "$CERT_DIR"
( cd "$CERT_DIR"
  # Clean old artefacts so a stale ECC fallback can never survive a re-run.
  rm -f ./*.pem ./*.der ./*.csr ./*.srl

  echo "[1/4] Generating Dilithium root CA..."
  openssl genpkey -algorithm "$PQC_ALG" $GENPKEY_FMT -out ca-key.pem
  openssl req -x509 -new -key ca-key.pem -out ca-cert.pem -days "$CA_DAYS" \
      -subj "/C=US/ST=State/L=City/O=LiteX-PQC/OU=CA/CN=LiteX Dilithium CA"

  echo "[2/4] Generating Dilithium server certificate..."
  openssl genpkey -algorithm "$PQC_ALG" $GENPKEY_FMT -out server-key.pem
  openssl req -new -key server-key.pem -out server.csr \
      -subj "/C=US/ST=State/L=City/O=LiteX-PQC/OU=Server/CN=LiteX PQC Server"
  openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem \
      -CAcreateserial -out server-cert.pem -days "$LEAF_DAYS"

  echo "[3/4] Generating Dilithium client certificate..."
  openssl genpkey -algorithm "$PQC_ALG" $GENPKEY_FMT -out client-key.pem
  openssl req -new -key client-key.pem -out client.csr \
      -subj "/C=US/ST=State/L=City/O=LiteX-PQC/OU=Client/CN=LiteX PQC Client"
  openssl x509 -req -in client.csr -CA ca-cert.pem -CAkey ca-key.pem \
      -CAcreateserial -out client-cert.pem -days "$LEAF_DAYS"

  echo "[4/4] Converting to DER and verifying chain..."
  for name in ca server client; do
      openssl x509 -in "${name}-cert.pem" -outform DER -out "${name}-cert.der"
      # Private keys as PKCS#8 DER (what wolfSSL_CTX_use_PrivateKey_buffer wants).
      openssl pkey -in "${name}-key.pem" -outform DER -out "${name}-key.der"
  done
  openssl verify -CAfile ca-cert.pem server-cert.pem
  openssl verify -CAfile ca-cert.pem client-cert.pem
)

# --- Embed CA cert, client cert and client key into the firmware header ------
echo "Regenerating embedded header $HEADER_OUT ..."
python3 - "$CERT_DIR" "$HEADER_OUT" <<'PY'
import sys
from pathlib import Path

cert_dir, out = Path(sys.argv[1]), Path(sys.argv[2])
arrays = [
    ("ca_cert_dilithium_der",     "ca-cert.der"),
    ("client_cert_dilithium_der", "client-cert.der"),
    ("client_key_dilithium_der",  "client-key.der"),
]

def emit(name, data):
    lines = [f"static const unsigned char {name}[] = {{"]
    for i in range(0, len(data), 12):
        body = ", ".join(f"0x{b:02x}" for b in data[i:i + 12])
        lines.append(f"    {body},")
    if len(lines) > 1:
        lines[-1] = lines[-1].rstrip(",")
    lines += ["};", f"static const unsigned int {name}_len = {len(data)};"]
    return "\n".join(lines)

blocks = [
    "/* Auto-generated Dilithium (ML-DSA-44 / FIPS 204) certificate data. */",
    "/* Post-Quantum Cryptography certificates for the DTLS 1.3 client.   */",
    "/* Regenerate with host/generate_dilithium_certs.sh.                 */",
    "#ifndef CERTS_DILITHIUM_DATA_H",
    "#define CERTS_DILITHIUM_DATA_H",
    "",
]
for name, der in arrays:
    blocks.append(emit(name, (cert_dir / der).read_bytes()))
    blocks.append("")
blocks.append("#endif /* CERTS_DILITHIUM_DATA_H */")
out.write_text("\n".join(blocks) + "\n")
print(f"  wrote {out}")
PY

echo ""
echo "=== Done. All certificates use $PQC_ALG (Dilithium2). ==="
ls -l "$CERT_DIR"/*.pem "$CERT_DIR"/*.der
