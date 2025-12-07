# RISC-V + LiteX + ML-KEM-512 + Dilithium (ML-DSA) PQC

This guide provides a systematic, step-by-step procedure to set up a complete RISC-V embedded development environment with Post-Quantum Cryptography (ML-KEM-512 and Dilithium/ML-DSA-44) support.

**Our specific objective and core implementation** for this project was to architect, integrate, and establish a **quantum-secure DTLS 1.3 handshake** on this constrained embedded system. To achieve this Post-Quantum Cryptography (PQC) security layer, we implemented:
* **ML-KEM-512** (FIPS 203, NIST level 1 — the standardised CRYSTALS-Kyber KEM) for secure, quantum-resistant key exchange. The client explicitly forces this group via `wolfSSL_CTX_set_groups()`, so the handshake never silently falls back to classical ECDHE.
* **Dilithium / ML-DSA-44** (FIPS 204, NIST level 2) for quantum-resistant digital signatures and mutual certificate authentication. The CA, server, and client certificates are all genuine ML-DSA certificates.

## Prerequisites

Ensure your system has the following installed:
- **Python 3.8+**
- **Git**
- **Build tools**: `build-essential`, `cmake`, `autoconf`, `automake`, `libtool`
- **Linux environment** (Ubuntu 20.04 or newer recommended)

---

## Repository Structure

This repository contains a complete RISC-V embedded system with Post-Quantum Cryptography support, organized into the following directories:

### Core Directories

#### `boot/`
Bare-metal firmware for the RISC-V embedded client:
- **`main.c`** - Main client firmware implementing DTLS 1.3 handshake with Dilithium PQC certificates
- **`crt0.d`** / **`linker.ld`** - RISC-V bootloader and memory layout configuration
- **`Makefile`** - Build system for compiling the firmware
- **`wolfssl/`** - WolfSSL/WolfCrypt headers and certificate data
  - **`certs_dilithium_data.h`** - Auto-generated C arrays containing embedded Dilithium certificates (CA, client cert, client key)
- **`src/`** - Additional firmware source files
- **`wolfcrypt/`** - WolfCrypt cryptographic library headers

#### `host/`
Host-side server implementations and certificate generation tools:
- **`dtls13_dilithium_server.c`** - DTLS 1.3 server with Dilithium PQC support
- **`server`** - Compiled server binary
- **`generate_dilithium_certs.sh`** - Script for generating Dilithium certificates
- **`generate_dilithium_certs.c`** - C implementation for certificate generation
- **`install_pqc_wolfssl.sh`** - WolfSSL PQC installation automation script
- **`certs_dilithium/`** - Generated Dilithium PQC certificates (ca-cert.pem, server-cert.pem, client-cert.pem, keys)

#### `build/`
Build artifacts and intermediate files:
- **`sim/`** - LiteX simulation build output (CSR definitions, Verilog, memory maps)

### LiteX Framework Modules

These directories contain the LiteX SoC framework and peripherals:

#### `litex/`
Main LiteX SoC framework - provides FPGA/simulation infrastructure for RISC-V CPU and peripherals

#### `litex-boards/`
Board support packages and hardware platform definitions

#### `litedram/`
LiteDRAM controller - DRAM memory controller core

#### `liteeth/`
LiteEth - Ethernet MAC and PHY implementation (used for network communication in this project)

#### `litescope/`
Logic analyzer for debugging FPGA designs

#### `litesdcard/`
SD card controller module

#### `litespi/`
SPI flash controller

#### `litesata/`
SATA controller implementation

#### `litepcie/`
PCIe controller core

#### `liteiclink/`
Inter-chip communication links (SerDes)

#### `litejesd204b/`
JESD204B high-speed serial interface

#### `litei2c/`
I2C controller implementation

### CPU Cores

RISC-V and other CPU implementations in Python HDL format:

#### `pythondata-cpu-vexriscv/`
**VexRiscv** - Primary RISC-V CPU core used in this project (32-bit, customizable pipeline)

#### `pythondata-cpu-vexriscv-smp/`
VexRiscv SMP - Multi-core variant

#### `pythondata-cpu-vexiiriscv/`
VexiiRiscv - Next-generation VexRiscv implementation

#### Other CPU Cores:
- **`pythondata-cpu-lm32/`** - LatticeMico32 soft processor
- **`pythondata-cpu-minerva/`** - Minerva RISC-V core
- **`pythondata-cpu-mor1kx/`** - OpenRISC processor
- **`pythondata-cpu-naxriscv/`** - NaxRiscv RISC-V core
- **`pythondata-cpu-sentinel/`** - Sentinel RISC-V core
- **`pythondata-cpu-serv/`** - SERV bit-serial RISC-V core

### Supporting Libraries

#### `migen/`
Migen - Python-based HDL (Hardware Description Language) toolbox, foundation for LiteX

#### `pythondata-software-compiler_rt/`
Compiler runtime support libraries

#### `pythondata-software-picolibc/`
Picolibc - Embedded C library for bare-metal systems

#### `pythondata-misc-tapcfg/`
TAP network interface configuration utilities

#### `pythondata-misc-usb_ohci/`
USB OHCI controller implementation

#### `valentyusb/`
USB device controller core

#### `wolfssl/`
WolfSSL library source code with PQC support (Dilithium, ML-KEM, Kyber)

### Configuration and Environment

#### `litex-env/`
Python virtual environment containing all LiteX dependencies and tools

#### `litex_setup.py`
Master setup script for initializing LiteX environment and installing toolchains

### Root Files

- **`csr.json`** - Control/Status Register definitions for the simulated SoC
- **`README.md`** - This comprehensive setup guide

### Data Flow

```
┌─────────────────────────────────────────────────────────────┐
│  Certificate Generation                                     │
│  host/generate_dilithium_certs.sh                           │
│         ↓                                                   │
│  host/certs_dilithium/*.pem                                 │
│         ↓                                                   │
│  boot/wolfssl/certs_dilithium_data.h                        │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  Firmware Build                                             │
│  boot/main.c + boot/wolfssl/certs_dilithium_data.h          │
│         ↓                                                   │
│  litex_bare_metal_demo                                      │
│         ↓                                                   │
│  boot.bin (RISC-V firmware with embedded PQC certs)         │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  Runtime Execution                                          │
│  Server: host/server (192.168.1.100:6000)                   │
│         ↕ DTLS 1.3 + Dilithium (ML-DSA) + ML-KEM-512        │
│  Client: litex_sim + boot.bin (192.168.1.50:60000)          │
│         ↑                                                   │
│  VexRiscv CPU @ 1MHz with LiteEth network                   │
└─────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Initial Setup and Environment Configuration

### Step 1: Clone the Repository

Clone the project repository containing the LiteX configuration and simulation modules:

```bash
git clone https://github.com/divyansh-1009/Inter_IIT_Cybersecurity_ID-67.git
cd Inter_IIT_Cybersecurity_ID-67
```

### Step 2: Create and Activate Python Virtual Environment

Isolate LiteX and Python dependencies using a virtual environment:

```bash
python3 -m venv litex-env
source litex-env/bin/activate
```


### Step 3: Install System Dependencies

Install required system packages:

```bash
sudo apt update
sudo apt install -y libevent-dev libjson-c-dev verilator meson ninja-build autoconf automake libtool
```

### Step 4: Initialize LiteX Environment

Make the setup script executable and initialize:

```bash
chmod +x litex_setup.py
./litex_setup.py --init --install
```

Install additional Python dependencies:

```bash
pip3 install meson ninja
```

### Step 5: Install RISC-V Toolchain

Install the RISC-V GCC toolchain using the LiteX setup utility:

```bash
sudo ./litex_setup.py --gcc=riscv
```


---

## Phase 2: WolfSSL Configuration with Post-Quantum Support

### Step 6: Clone and Build WolfSSL with PQC Support

Clone the WolfSSL repository:

```bash
git clone https://github.com/wolfSSL/wolfssl.git
cd wolfssl
```

Run the autoconf setup:

```bash
./autogen.sh
```

Configure with comprehensive PQC and DTLS support:

```bash
./configure \
    --enable-opensslcoexist \
    --enable-opensslextra \
    --enable-opensslall \
    --enable-dilithium \
    --enable-mlkem \
    --enable-kyber \
    --enable-sp \
    --enable-debug \
    --enable-certgen \
    --enable-pkcs7 \
    --enable-pkcs12 \
    --enable-tlsx \
    --enable-dtls \
    --enable-dtls13 \
    --enable-dtls-frag-ch \
    CFLAGS="-DWC_ENABLE_DILITHIUM -DWC_ENABLE_MLKEM -DWOLFSSL_STATIC_RSA -DWOLFSSL_STATIC_DH"
```

Build and install:

```bash
make -j$(nproc)
sudo make install
sudo ldconfig
```

Return to the project directory:

```bash
cd ..
```

---

## Phase 3: Generate Dilithium Post-Quantum Certificates

### Step 7: Generate Dilithium Certificates

Generate the Dilithium (ML-DSA-44) CA, server, and client certificates:

```bash
./host/generate_dilithium_certs.sh
```

The script uses OpenSSL's **native ML-DSA-44** support (requires OpenSSL >= 3.5;
verify with `openssl list -signature-algorithms | grep ML-DSA`). No liboqs / OQS
provider is needed. It aborts with an error rather than silently falling back to
classical ECC if ML-DSA is unavailable.

This creates the following in `host/certs_dilithium/` (PEM + DER, all ML-DSA-44):
- **ca-cert.pem / ca-cert.der** - Dilithium Root CA certificate
- **server-cert.pem / server-key.pem** - Dilithium server certificate + private key
- **client-cert.pem / client-key.pem** - Dilithium client certificate + private key

It also regenerates **boot/wolfssl/certs_dilithium_data.h**, the embedded C
arrays (CA cert, client cert, client key) that the firmware compiles in.

> Verify the algorithm at any time with:
> `openssl x509 -in host/certs_dilithium/ca-cert.pem -noout -text | grep "Signature Algorithm"`
> — this must report `ML-DSA-44`, not `ecdsa-with-SHA256`.

---

## Phase 4: Embedded Certificate Header

### Step 8: Use the Embedded Certificate Header

The embedded header is tracked in the repo:
- **boot/wolfssl/certs_dilithium_data.h** - C header containing embedded certificate arrays for the firmware

---

## Phase 5: Configure Network Interface for Client-Server Communication

### Step 9: Setup tap0 Network Interface

Configure the tap0 virtual network interface for RISC-V simulation to communicate with the host server:

**If tap0 already exists and is busy, remove it first:**

```bash
sudo ip link set tap0 down
sudo ip link del tap0
```

**Create and configure tap0:**

```bash
sudo ip tuntap add dev tap0 mode tap
sudo ip addr flush dev tap0
sudo ip addr add 192.168.1.100/24 dev tap0
sudo ip link set tap0 up
```

**Verify the interface:**

```bash
ip addr show tap0
```

You should see output similar to:
```
3: tap0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel master br0 state UP group default qlen 1000
    link/ether 12:34:56:78:9a:bc brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.100/24 scope global tap0
```

---

## Phase 6: Build and Run the Server

### Step 10: Compile the Dilithium PQC DTLS Server

Compile the server binary with WolfSSL support:

```bash
gcc host/dtls13_dilithium_server.c -o host/server \
    -I/usr/local/include \
    -L/usr/local/lib \
    -Wl,-rpath=/usr/local/lib \
    -lwolfssl
```

Verify the server binary was created:

```bash
ls -la host/server
```

### Step 11: Run the Server

**Terminal 1 - Start the DTLS Server:**

```bash
./host/server
```

The server will:
- Listen on `192.168.1.100:6000`
- Load the Dilithium CA certificate to verify client authenticity
- Load the Dilithium server certificate and private key
- Require mutual TLS authentication with PQC certificates
- Use DTLS 1.3 with AES-128-GCM-SHA256 cipher suite
- Advertise ML-KEM-512 (plus ML-KEM hybrids) for post-quantum key exchange

Expected output:
```
Starting Dilithium PQC DTLS Server...
Listening on 192.168.1.100:6000
Waiting for client connections...
```

---

## Phase 7: Build and Run the Embedded Client

### Step 12: Rebuild the Bare-Metal Demo Client Firmware

**Terminal 2 - In a new terminal, ensure virtual environment is active:**

```bash
source litex-env/bin/activate
```

Regenerate the bare-metal demo firmware (now with embedded Dilithium certificates):

```bash
litex_bare_metal_demo --build-path=build/sim
```

This creates:
- **boot.bin** - Compiled RISC-V firmware with embedded Dilithium certificates

### Step 13: Run the LiteX Simulation with Ethernet

**Terminal 2 - Launch the RISC-V simulation client:**

```bash
litex_sim --csr-json csr.json \
    --cpu-type=vexriscv \
    --cpu-variant=full \
    --integrated-main-ram-size=0x06400000 \
    --ram-init=boot.bin \
    --with-ethernet
```

The simulation will:
- Start a RISC-V VexRiscv CPU running at 1MHz
- Load the compiled firmware (`boot.bin`) into simulated RAM
- Initialize network interface at `192.168.1.50:60000`
- Perform DTLS 1.3 handshake with server using Dilithium certificates
- Validate server's certificate against Dilithium CA
- Present client certificate for mutual authentication
- Establish encrypted channel with post-quantum cryptography

---

## Expected Behavior and Flow

### Client-Server Handshake Timeline

1. **Server Ready** - Waiting for client connection on `192.168.1.100:6000`
2. **Client Boot** - RISC-V loads firmware from boot.bin
3. **Network Initialize** - Embedded system obtains IP `192.168.1.50` (simulated)
4. **DTLS Initiation** - Client initiates handshake with server
5. **Certificate Exchange** - Both parties exchange and validate Dilithium certificates
6. **Handshake Completion** - Mutual authentication established (takes 30-60 seconds due to 1MHz CPU)
7. **Encrypted Communication** - Application data exchanged over secured channel

### Client Details (192.168.1.50:60000) - Embedded RISC-V @ 1MHz:
- Loads Dilithium (ML-DSA-44) CA certificate (~4.1 KB) from embedded arrays
- Loads Dilithium client certificate (~4.1 KB) and private key (~2.6 KB)
- Forces the ML-KEM-512 key-exchange group via `wolfSSL_CTX_set_groups()`
- Initiates DTLS 1.3 handshake with server
- Validates server's Dilithium certificate against CA
- Presents client Dilithium certificate for mutual authentication
- Uses TLS13-AES128-GCM-SHA256 cipher
- Performs Post-Quantum Key Exchange (ML-KEM-512)
- Sends encrypted application data

### Server Details (192.168.1.100:6000) - Host System:
- Loads Dilithium CA certificate to verify client
- Loads server certificate and private key
- Validates client Dilithium certificate against CA
- Completes DTLS 1.3 handshake with PQC support
- Receives and processes encrypted data
- Demonstrates quantum-resistant mutual authentication

---

## Monitoring and Debugging

### Monitor Network Traffic

In a third terminal, capture traffic on the tap0 interface:

```bash
sudo tcpdump -i tap0 -nn udp and port 6000
```

### View Communication Details

Monitor client output in Terminal 2 (simulation) and server output in Terminal 1 to observe the handshake progress.

### Check Interface Status

Verify tap0 is active during the simulation:

```bash
ip addr show tap0
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| **"No such file or directory"** (certificates) | Ensure Dilithium certificates are generated: `./host/generate_dilithium_certs.sh` |
| **"Device or resource busy"** (tap0) | Remove and recreate tap0: `sudo ip link del tap0` then repeat Step 9 |
| **"Command not found"** (litex_sim) | Activate virtual environment: `source litex-env/bin/activate` |
| **Server compilation fails** | Verify wolfSSL installed: `ldconfig -p \| grep wolfssl` |
| **Handshake timeout** | Normal behavior with 1MHz simulated CPU - wait 30-60 seconds |
| **Client won't connect** | Ensure tap0 is up and server is running on correct IP (192.168.1.100:6000) |
| **Handshake picks classical ECDHE** | Confirm the client's `wolfSSL_CTX_set_groups(ctx, {WOLFSSL_ML_KEM_512}, 1)` call succeeded and the server advertises ML-KEM (both require `WOLFSSL_HAVE_MLKEM`) |
| **Certificates decode as ECDSA** | Regenerate with `./host/generate_dilithium_certs.sh`; the CA cert must report `Signature Algorithm: ML-DSA-44` |
| **Server fails to load its ML-DSA key** (`NOT_COMPILED_IN` / `make_key_from_seed`) | The key was written in seed+expanded form. Regenerate with `./host/generate_dilithium_certs.sh` — it emits `priv-only` (expanded) keys via OpenSSL's `-provparam ml-dsa.output_formats=priv-only`, which load on both wolfCrypt and liboqs builds. Requires OpenSSL >= 3.5. |

---

## Performance Notes and Optimizations

The following choices target the evaluation metrics (latency, throughput, CPU
cycles, memory) on the 1 MHz simulated RISC-V core:

- **PQC KEM = ML-KEM-512 (pure).** The lowest-cost standardised KEM (FIPS 203,
  NIST level 1), minimising key-exchange cycles and handshake bytes versus
  higher levels or hybrid groups. Forced explicitly with `wolfSSL_CTX_set_groups()`.
- **Speed-tuned wolfCrypt build.** The SoC has ~100 MiB of RAM, so the
  `WOLFSSL_*_SMALL_MEM`, `WOLFSSL_DILITHIUM_SMALL`, `WOLFSSL_DILITHIUM_NO_LARGE_CODE`
  and `WOLFSSL_SHA3_SMALL` paths are **not** enabled — they trade speed for a RAM
  saving this platform does not need. This is the single largest handshake-latency
  lever. (Expect a higher heap/ROM figure in exchange.)
- **No verbose TLS trace on the hot path.** `wolfSSL_Debugging_ON()` is not
  called and `DEBUG_WOLFSSL*` are off; the internal trace was emitted over the
  blocking UART *inside* the timed handshake at 1 MHz.
- **Expanded (`priv-only`) ML-DSA keys.** Avoids a runtime seed→key expansion on
  the client and is the format wolfSSL loads directly (see troubleshooting above).
- **Fuller RNG utilisation.** The custom PRNG emits all four bytes of each 32-bit
  xorshift word (previously one), cutting RNG work on the ML-KEM keygen path ~4x.

> These are reproducible knobs, not measured results. Regenerate `evidence/`
> on the Linux build host (see `evidence/README.md`) to capture the actual
> latency/throughput/footprint after building with this configuration.

---

## File Structure and Modifications

### Key Files Modified for Dilithium PQC:

- `host/generate_dilithium_certs.sh` - Certificate generation script with Dilithium naming
- `host/dtls13_dilithium_server.c` - Server implementation with Dilithium PQC support
- `boot/main.c` - Client firmware with embedded Dilithium certificates
- `boot/wolfssl/certs_dilithium_data.h` - Embedded Dilithium certificate arrays (auto-generated)

---

## Quick Reference Commands

### Activate Environment
```bash
source litex-env/bin/activate
```

### Setup (One-Time)
```bash
cd Constraint_Env_Sim
source litex-env/bin/activate
./host/generate_dilithium_certs.sh
sudo ip tuntap add dev tap0 mode tap
sudo ip addr add 192.168.1.100/24 dev tap0
sudo ip link set tap0 up
```

### Run Demo
```bash
# Terminal 1: Start server
./host/server

# Terminal 2: Build and run client
source litex-env/bin/activate
litex_bare_metal_demo --build-path=build/sim
litex_sim --csr-json csr.json --cpu-type=vexriscv --cpu-variant=full \
    --integrated-main-ram-size=0x06400000 --ram-init=boot.bin --with-ethernet

# Terminal 3: Monitor traffic (optional)
sudo tcpdump -i tap0 -nn udp and port 6000
```

---

## Implementation Status

✅ **Repository cloning and environment setup**  
✅ **WolfSSL with comprehensive PQC support (Dilithium, ML-KEM, Kyber)**  
✅ **Dilithium certificate generation and conversion**  
✅ **tap0 network interface configuration**  
✅ **DTLS 1.3 server with PQC authentication**  
✅ **Embedded client firmware with quantum-resistant certificates**  
✅ **Mutual TLS authentication with CA validation**  
✅ **Post-quantum key exchange (ML-KEM-512)**  

---

## Support and Additional Resources

- **WolfSSL Documentation**: https://github.com/wolfSSL/wolfssl
- **LiteX Documentation**: https://github.com/enjoy-digital/litex
- **Post-Quantum Cryptography**: https://en.wikipedia.org/wiki/Post-quantum_cryptography
- **DTLS 1.3 RFC**: https://tools.ietf.org/html/rfc9147

---

**Last Updated**: December 2025  
**Version**: 1.1  
**Status**: Demonstration / proof-of-concept (simulation on LiteX + Verilator)