// DTLS 1.3 PQC client on LiteX + LiteEth.
// Uses wolfSSL (vendored in boot/wolfssl) with custom UDP I/O over LiteEth.
// Implements Post-Quantum Cryptography using Kyber (ML-KEM) and Dilithium.

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <irq.h>
#include <libbase/uart.h>
#include <generated/csr.h>

#ifdef CSR_ETHMAC_BASE
#include <libliteeth/udp.h>
#endif

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif

// ------------------------ Network configuration ------------------------

#ifdef CSR_ETHMAC_BASE

// Locally-administered MAC for the LiteX SoC
#define LOCAL_MAC0  0x02
#define LOCAL_MAC1  0x11
#define LOCAL_MAC2  0x22
#define LOCAL_MAC3  0x33
#define LOCAL_MAC4  0x44
#define LOCAL_MAC5  0x55

// LiteX IP (simulated SoC)
#define LOCAL_IP0   192
#define LOCAL_IP1   168
#define LOCAL_IP2   1
#define LOCAL_IP3   50

// Host IP on tap0 (DTLS server)
#define REMOTE_IP0  192
#define REMOTE_IP1  168
#define REMOTE_IP2  1
#define REMOTE_IP3  100

// UDP ports for DTLS
#define DTLS_CLIENT_PORT 60000
#define DTLS_SERVER_PORT 6000

// Busy-loop wait caps
#define RX_TIMEOUT_LOOPS   4000000U
#define DTLS_IO_TIMEOUT_LOOPS 8000000U

// DTLS settings
#define DTLS_MTU           1200
#define DTLS_MAX_RX        1600
#define DTLS_APP_MSG       "Hello from LiteX PQC-DTLS 1.3 client"

static const uint8_t kLocalMac[6] = {
    LOCAL_MAC0, LOCAL_MAC1, LOCAL_MAC2,
    LOCAL_MAC3, LOCAL_MAC4, LOCAL_MAC5,
};

static const uint32_t kLocalIp  =
    IPTOINT(LOCAL_IP0, LOCAL_IP1, LOCAL_IP2, LOCAL_IP3);
static const uint32_t kRemoteIp =
    IPTOINT(REMOTE_IP0, REMOTE_IP1, REMOTE_IP2, REMOTE_IP3);

#endif // CSR_ETHMAC_BASE

// ------------------------ Helpers ------------------------

static void print_ipv4(const char *label, uint32_t ip)
{
    uint8_t a = (ip >> 24) & 0xff;
    uint8_t b = (ip >> 16) & 0xff;
    uint8_t c = (ip >> 8)  & 0xff;
    uint8_t d = ip & 0xff;
    printf("%s %d.%d.%d.%d\n", label, a, b, c, d);
}

static void dump_bytes(const char *label, const uint8_t *data, unsigned length)
{
    unsigned i;
    printf("%s (%u bytes):\n", label, length);
    for (i = 0; i < length; i++) {
        printf("%02X ", data[i]);
        if ((i + 1u) % 16u == 0u)
            printf("\n");
    }
    if (length % 16u != 0u)
        printf("\n");
}

// ------------------------ Custom RNG for wolfSSL ------------------------
// NOTE: This is a simple xorshift PRNG seeded from the cycle counter.
// It is sufficient for simulation/demo, not production-grade entropy.
static uint32_t prng_state = 0xA5A5A5A5u;

static uint32_t prng_next(void)
{
    uint32_t x = prng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    prng_state = x;
    return x;
}

static void prng_seed(void)
{
#if defined(__riscv)
    uint64_t cycles = 0;
    asm volatile("rdcycle %0" : "=r"(cycles));
    prng_state ^= (uint32_t)cycles ^ (uint32_t)(cycles >> 32);
#endif
    prng_state ^= 0x3C6EF35Fu; // LCG-style mix-in
    // Never allow state to stay zero
    if (prng_state == 0)
        prng_state = 0x1u;
}

int CustomRngGenerateBlock(unsigned char *output, unsigned int sz)
{
    if (prng_state == 0xA5A5A5A5u)
        prng_seed();

    // Emit all four bytes of each 32-bit xorshift word instead of just one.
    // ML-KEM key generation and encapsulation pull a large amount of random
    // data through SHAKE seeding, so consuming the full word (rather than one
    // byte per draw) cuts the RNG work on the handshake hot path by ~4x.
    unsigned int i = 0;
    while (i < sz) {
        uint32_t v = prng_next();
        unsigned int chunk = (sz - i < 4u) ? (sz - i) : 4u;
        for (unsigned int b = 0; b < chunk; ++b) {
            output[i++] = (unsigned char)(v & 0xFFu);
            v >>= 8;
        }
    }
    return 0;
}

// ------------------------ UDP RX state ------------------------

#ifdef CSR_ETHMAC_BASE

typedef struct {
    volatile int ready;
    uint32_t src_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t length;
    uint8_t  data[DTLS_MAX_RX];
} udp_rx_state_t;

static udp_rx_state_t g_rx;

static void udp_rx_cb(uint32_t src_ip, uint16_t src_port,
                      uint16_t dst_port, void *data, uint32_t length)
{
    if (dst_port != DTLS_CLIENT_PORT) {
        // Ignore traffic not meant for the DTLS client port
        return;
    }

    uint32_t capped = length;
    if (capped > sizeof(g_rx.data))
        capped = sizeof(g_rx.data);

    g_rx.ready    = 1;
    g_rx.src_ip   = src_ip;
    g_rx.src_port = src_port;
    g_rx.dst_port = dst_port;
    g_rx.length   = capped;

    memcpy(g_rx.data, data, capped);

    printf("[UDP] RX %lu bytes from %u -> %u\n",
           (unsigned long)length, src_port, dst_port);
}

static void udp_rx_reset(void)
{
    g_rx.ready = 0;
    g_rx.length = 0;
}

#endif // CSR_ETHMAC_BASE

// ------------------------ wolfSSL I/O callbacks ------------------------

#ifdef CSR_ETHMAC_BASE

typedef struct {
    uint32_t peer_ip;
    uint16_t peer_port;
} dtls_net_ctx_t;

static int dtls_io_recv(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    (void)ssl;
    (void)ctx;

    for (uint32_t i = 0; i < DTLS_IO_TIMEOUT_LOOPS; ++i) {
        udp_service();
        if (g_rx.ready)
            break;
    }

    if (!g_rx.ready) {
        // Let wolfSSL know we timed out so it can retransmit DTLS flights
        (void)wolfSSL_dtls_got_timeout(ssl);
        printf("[UDP] recv timeout\n");
        return WOLFSSL_CBIO_ERR_WANT_READ;
    }

    int copy_len = (g_rx.length > (uint32_t)sz) ? sz : (int)g_rx.length;
    memcpy(buf, g_rx.data, (unsigned)copy_len);
    udp_rx_reset();
    printf("[UDP] RX handed %d bytes to wolfSSL\n", copy_len);
    return copy_len;
}

static int dtls_io_send(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    (void)ssl;
    dtls_net_ctx_t* net = (dtls_net_ctx_t*)ctx;
    if (net == NULL)
        return WOLFSSL_CBIO_ERR_GENERAL;

    printf("[IO_SEND] requested sz=%d, peer_port=%u\n", sz, net->peer_port);

    if (sz <= 0 || sz > DTLS_MAX_RX) {
        printf("[IO_SEND] bad size, returning error\n");
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    uint8_t* tx_buf = (uint8_t*)udp_get_tx_buffer();
    printf("[IO_SEND] got tx buffer %p\n", (void*)tx_buf);

    memcpy(tx_buf, buf, (unsigned)sz);

    if (!udp_send(DTLS_CLIENT_PORT, net->peer_port, (uint32_t)sz)) {
        printf("[IO_SEND] udp_send failed\n");
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    printf("[UDP] TX %d bytes to port %u\n", sz, net->peer_port);
    return sz;
}

// ------------------------ Dilithium PQC Certificates & Keys ------------------------
// Auto-generated Post-Quantum Cryptography certificates for DTLS 1.3
#include "wolfssl/certs_dilithium_data.h"

#endif // CSR_ETHMAC_BASE

// Accept certs even if device clock is wrong (ignore time validity errors).
static int verify_allow_badtime(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    int err = wolfSSL_X509_STORE_CTX_get_error(store);
    if (err == ASN_BEFORE_DATE_E || err == ASN_AFTER_DATE_E)
        return 1;
    return preverify;
}

// ------------------------ DTLS demo ------------------------

static int run_dtls13_demo(void)
{
    printf("DEBUG: Entered run_dtls13_demo\n");
    fflush(stdout);
#ifndef CSR_ETHMAC_BASE
    printf("Ethernet MAC not present in this build; rebuild with --with-ethernet.\n");
    return -1;
#else
    printf("\n=== DTLS 1.3 Client (Dilithium PQC) ===\n");
    printf("Using Post-Quantum Cryptography Certificates\n");
    fflush(stdout);
    print_ipv4("Local IP: ",  kLocalIp);
    print_ipv4("Remote IP:",  kRemoteIp);
    printf("Local port: %u, server port: %u\n", DTLS_CLIENT_PORT, DTLS_SERVER_PORT);

    // Initialize Ethernet and UDP
    eth_init();
#ifdef CSR_ETHPHY_MODE_DETECTION_MODE_ADDR
    eth_mode();
#endif
    udp_start(kLocalMac, kLocalIp);
    udp_set_callback(udp_rx_cb);
    udp_rx_reset();

    // Resolve ARP
    printf("Resolving ARP for remote...");
    if (!udp_arp_resolve(kRemoteIp)) {
        printf(" failed.\n");
        udp_set_callback(NULL);
        return -1;
    }
    printf(" done.\n");

    // wolfSSL setup
    wolfSSL_Init();
    // NOTE: wolfSSL_Debugging_ON() is intentionally not called. The verbose
    // internal trace it enables is emitted over the blocking UART during the
    // handshake, and at 1 MHz that logging dominated the measured handshake
    // latency. Application-level progress prints below are kept for the demo.

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfDTLSv1_3_client_method());
    if (ctx == NULL) {
        printf("wolfSSL_CTX_new failed\n");
        udp_set_callback(NULL);
        wolfSSL_Cleanup();
        return -1;
    }

    // 1. Load CA Certificate to verify Server (Dilithium)
    printf("Loading Dilithium CA certificate (%u bytes)...\n", ca_cert_dilithium_der_len);
    if (wolfSSL_CTX_load_verify_buffer(ctx, ca_cert_dilithium_der, ca_cert_dilithium_der_len, WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        printf("Failed to load CA certificate\n");
        wolfSSL_CTX_free(ctx);
        udp_set_callback(NULL);
        wolfSSL_Cleanup();
        return -1;
    }
    printf("Dilithium CA certificate loaded successfully.\n");

    // 2. Load Client Certificate & Private Key for Mutual Auth (Dilithium)
    printf("Loading Dilithium client certificate (%u bytes)...\n", client_cert_dilithium_der_len);
    if (wolfSSL_CTX_use_certificate_buffer(ctx, client_cert_dilithium_der, client_cert_dilithium_der_len, WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        printf("Failed to load Client certificate\n");
        wolfSSL_CTX_free(ctx);
        udp_set_callback(NULL);
        wolfSSL_Cleanup();
        return -1;
    }
    printf("Dilithium client certificate loaded successfully.\n");
    
    printf("Loading Dilithium client private key (%u bytes)...\n", client_key_dilithium_der_len);
    if (wolfSSL_CTX_use_PrivateKey_buffer(ctx, client_key_dilithium_der, client_key_dilithium_der_len, WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        printf("Failed to load Client private key\n");
        wolfSSL_CTX_free(ctx);
        udp_set_callback(NULL);
        wolfSSL_Cleanup();
        return -1;
    }
    printf("Dilithium client private key loaded successfully.\n");

    // 3. Enable Mutual Authentication (ignore bad time since no RTC on target)
    wolfSSL_CTX_set_verify(ctx,
        WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT,
        verify_allow_badtime);
    printf("Mutual authentication enabled with PQC (time validity ignored).\n");

    // 4. Set Cipher Suite (TLS 1.3)
    wolfSSL_CTX_set_cipher_list(ctx, "TLS13-AES128-GCM-SHA256");
    printf("Cipher suite set to TLS13-AES128-GCM-SHA256.\n");

#ifdef HAVE_PQC
    // Force a Post-Quantum KEM for key exchange. Without this the client only
    // advertises classical curves and the handshake silently falls back to
    // ECDHE, so this call is what actually makes the channel quantum-safe.
    // ML-KEM-512 (FIPS 203, NIST level 1) is the smallest/fastest KEM, chosen
    // to minimise latency and memory on the 1 MHz RISC-V core.
    {
        int kem_groups[] = { WOLFSSL_ML_KEM_512 };
        if (wolfSSL_CTX_set_groups(ctx, kem_groups,
                                   (int)(sizeof(kem_groups) / sizeof(kem_groups[0])))
                != WOLFSSL_SUCCESS) {
            printf("Failed to set PQC key-exchange group (ML-KEM-512)\n");
            wolfSSL_CTX_free(ctx);
            udp_set_callback(NULL);
            wolfSSL_Cleanup();
            return -1;
        }
        printf("Post-Quantum Key Exchange enabled (ML-KEM-512).\n");
    }
#endif

    wolfSSL_SetIORecv(ctx, dtls_io_recv);
    wolfSSL_SetIOSend(ctx, dtls_io_send);

    WOLFSSL* ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        printf("wolfSSL_new failed\n");
        wolfSSL_CTX_free(ctx);
        udp_set_callback(NULL);
        wolfSSL_Cleanup();
        return -1;
    }

    // Configure MTU settings
    wolfSSL_CTX_set_options(ctx, WOLFSSL_OP_NO_QUERY_MTU);

    dtls_net_ctx_t net = {.peer_ip = kRemoteIp, .peer_port = DTLS_SERVER_PORT};
    wolfSSL_SetIOReadCtx(ssl, &net);
    wolfSSL_SetIOWriteCtx(ssl, &net);
    
    printf("Starting DTLS 1.3 handshake with Dilithium PQC certificates...\n");
    int ret;
    int attempts = 0;
    const int kMaxAttempts = 300;
    for (;;) {
        ret = wolfSSL_connect(ssl);
        if (ret == WOLFSSL_SUCCESS)
            break;

        int err = wolfSSL_get_error(ssl, ret);
        if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
            if (++attempts >= kMaxAttempts) {
                printf("Handshake stuck after %d attempts (want read/write)\n", attempts);
                wolfSSL_free(ssl);
                wolfSSL_CTX_free(ctx);
                udp_set_callback(NULL);
                wolfSSL_Cleanup();
                return -1;
            }
            continue; // keep driving the state machine
        }
        printf("Handshake failed: %d\n", err);
        char error_buf[80];
        wolfSSL_ERR_error_string(err, error_buf);
        printf("Error string: %s\n", error_buf);
        
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        udp_set_callback(NULL);
        wolfSSL_Cleanup();
        return -1;
    }
    printf("Handshake complete.\n");
    printf("Negotiated Cipher: %s\n", wolfSSL_get_cipher(ssl));
    printf("Negotiated Version: %s\n", wolfSSL_get_version(ssl));

    // Send application data
    const char app_msg[] = DTLS_APP_MSG;
    ret = wolfSSL_write(ssl, app_msg, (int)sizeof(app_msg));
    if (ret != (int)sizeof(app_msg)) {
        int err = wolfSSL_get_error(ssl, ret);
        printf("wolfSSL_write failed: %d\n", err);
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        udp_set_callback(NULL);
        wolfSSL_Cleanup();
        return -1;
    }
    printf("Sent %d bytes of application data.\n", ret);

    // Wait for echo from server
    uint8_t rx_buf[DTLS_MAX_RX];
    ret = wolfSSL_read(ssl, rx_buf, sizeof(rx_buf));
    if (ret < 0) {
        int err = wolfSSL_get_error(ssl, ret);
        printf("wolfSSL_read failed: %d\n", err);
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        udp_set_callback(NULL);
        wolfSSL_Cleanup();
        return -1;
    }

    printf("Received %d bytes over DTLS.\n", ret);
    dump_bytes("[RX] decrypted payload", rx_buf, (unsigned)ret);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    udp_set_callback(NULL);
    return 0;
#endif
}

// ------------------------ main() ------------------------

int main(void)
{
#ifdef CONFIG_CPU_HAS_INTERRUPT
    irq_setmask(0);
    irq_setie(1);
#endif
    uart_init();

    printf("\nLiteX DTLS 1.3 Dilithium PQC client (wolfSSL)\n");
    printf("Post-Quantum Cryptography with Dilithium certificates\n");
    printf("DEBUG: About to call run_dtls13_demo\n");
    fflush(stdout);

    int status = run_dtls13_demo();
    printf("DEBUG: run_dtls13_demo returned with status: %d\n", status);
    printf("Demo %s.\n", (status == 0) ? "PASSED" : "FAILED");

    return 0;
}
