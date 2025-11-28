#!/bin/bash
# Install wolfSSL with Post-Quantum Cryptography (Dilithium/ML-DSA) support

set -euo pipefail

WORK_DIR="$HOME/pqc_build"
LIBOQS_DIR="$WORK_DIR/liboqs"
WOLFSSL_DIR="$WORK_DIR/wolfssl"

echo "=== Installing wolfSSL with Dilithium (PQC) Support ==="
echo "This will take several minutes..."

# Create work directory
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

# 1. Install liboqs (Open Quantum Safe library)
echo "[1/3] Building liboqs..."
if [ ! -d "$LIBOQS_DIR" ]; then
    git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs.git
fi

cd "$LIBOQS_DIR"
mkdir -p build
cd build

cmake -DCMAKE_INSTALL_PREFIX=/usr/local \
      -DOQS_USE_OPENSSL=ON \
      -DBUILD_SHARED_LIBS=ON \
      ..
      
make -j"$(nproc)"
sudo make install
sudo ldconfig

echo "[1/3] ✓ liboqs installed successfully"

# 2. Build wolfSSL with PQC support
echo "[2/3] Building wolfSSL with PQC support..."
cd "$WORK_DIR"

if [ ! -d "$WOLFSSL_DIR" ]; then
    git clone --depth 1 https://github.com/wolfSSL/wolfssl.git
fi

cd "$WOLFSSL_DIR"
./autogen.sh

# Compatibility shim: newer liboqs dropped the *_ipd_* ML-DSA constants.
# Add fallbacks so wolfSSL builds against current liboqs headers.
DILITHIUM_HEADER="$WOLFSSL_DIR/wolfssl/wolfcrypt/dilithium.h"
if [ -f "$DILITHIUM_HEADER" ] && ! grep -q "liboqs >=0.10 compatibility" "$DILITHIUM_HEADER"; then
    python3 - "$DILITHIUM_HEADER" <<'PY'
import sys
from pathlib import Path

hdr = Path(sys.argv[1])
text = hdr.read_text()
needle = "#elif defined(HAVE_LIBOQS)\n"
shim = """#elif defined(HAVE_LIBOQS)

/* liboqs >=0.10 compatibility: ML-DSA constants dropped the _ipd_ infix */
#ifndef OQS_SIG_ml_dsa_44_ipd_length_public_key
#define OQS_SIG_ml_dsa_44_ipd_length_public_key OQS_SIG_ml_dsa_44_length_public_key
#define OQS_SIG_ml_dsa_44_ipd_length_secret_key OQS_SIG_ml_dsa_44_length_secret_key
#define OQS_SIG_ml_dsa_44_ipd_length_signature  OQS_SIG_ml_dsa_44_length_signature
#endif
#ifndef OQS_SIG_ml_dsa_65_ipd_length_public_key
#define OQS_SIG_ml_dsa_65_ipd_length_public_key OQS_SIG_ml_dsa_65_length_public_key
#define OQS_SIG_ml_dsa_65_ipd_length_secret_key OQS_SIG_ml_dsa_65_length_secret_key
#define OQS_SIG_ml_dsa_65_ipd_length_signature  OQS_SIG_ml_dsa_65_length_signature
#endif
#ifndef OQS_SIG_ml_dsa_87_ipd_length_public_key
#define OQS_SIG_ml_dsa_87_ipd_length_public_key OQS_SIG_ml_dsa_87_length_public_key
#define OQS_SIG_ml_dsa_87_ipd_length_secret_key OQS_SIG_ml_dsa_87_length_secret_key
#define OQS_SIG_ml_dsa_87_ipd_length_signature  OQS_SIG_ml_dsa_87_length_signature
#endif

"""
if needle in text:
    text = text.replace(needle, shim, 1)
    hdr.write_text(text)
PY
fi

# Configure with PQC, DTLS 1.3, channel frag (avoids DTLS+PQC warning), and OpenSSL compat
./configure \
    --enable-experimental \
    --enable-dtls \
    --enable-dtls13 \
    --enable-dtls-frag-ch \
    --enable-psk \
    --enable-debug \
    --enable-opensslextra \
    --with-liboqs \
    CFLAGS="-DHAVE_LIBOQS -DHAVE_PQC"

make -j"$(nproc)"
sudo make install
sudo ldconfig

echo "[2/3] ✓ wolfSSL with PQC installed successfully"

# 3. Verify installation
echo "[3/3] Verifying installation..."
if grep -q "HAVE_LIBOQS" /usr/local/include/wolfssl/options.h; then
    echo "✓ PQC support confirmed in wolfSSL"
else
    echo "⚠ Warning: PQC support may not be fully enabled"
fi

echo ""
echo "=== Installation Complete ==="
echo "wolfSSL with Dilithium support is now installed"
echo "You can now generate Dilithium certificates"
