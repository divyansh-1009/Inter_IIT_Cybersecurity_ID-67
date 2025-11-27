#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H
#define WOLFSSL_USE_ALIGN

// #define WOLFCRYPT_ONLY // only use the crypto backend

#define WOLFSSL_SP_MATH // maths backend for crypto

#define NO_TIME_H
#define WOLFSSL_NO_CLOCK
#define NO_ASN_TIME

/* user_settings.h */
#define WOLFSSL_NO_SOCK
#define NO_WRITEV
#define WOLFSSL_USER_IO
#define WOLFSSL_SMALL_STACK         // Optimize for small stack usage
#define WOLFSSL_SMALL_CERT_VERIFY   // Lower memory certificate verification
#define NO_FILESYSTEM               // Don't use file system
#define NO_WOLFSSL_DIR              // Don't use directory access
// #define NO_WOLFSSL_SERVER           // Client only, no server support
#define SINGLE_THREADED             // No threading support needed
#define NO_ERROR_STRINGS            // Save space by removing error strings
#define WOLFSSL_SMALL_SESSION_CACHE // Smaller session cache
// #define NO_OLD_TLS                  // Only support TLS 1.2+
#define WOLFSSL_TLS13
#define HAVE_TLS_EXTENSIONS
#define WC_RSA_PSS
#define NO_DH                       // Disable DH to save space

#define HAVE_X25519
#define HAVE_CURVE25519
#define WOLFSSL_SHA256
#define WOLFSSL_SHA512
#define HAVE_ECC             // Enable ECC
#define HAVE_ED25519         // Enable ED25519
#define HAVE_RSA             // Enable RSA
#define HAVE_AESGCM          // Enable AES-GCM
#define WC_RSA_BLINDING      // Enable RSA blinding
#define ECC_TIMING_RESISTANT // Make ECC resistant to timing attacks

#define WOLFSSL_WC_MLKEM
#define WOLFSSL_HAVE_MLKEM
#define WOLFSSL_HAVE_KYBER // enable ML-KEM in wolfSSL
#define WOLFSSL_SHA3       // ML-KEM uses SHA3/SHAKE
#define WOLFSSL_SHAKE256
#define WOLFSSL_SHAKE128
#define WOLFSSL_DTLS
#define WOLFSSL_DTLS13
#define WOLFSSL_DTLS_CH_FRAG
#define WOLFSSL_SEND_HRR_COOKIE
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_HKDF
#define WOLFSSL_KEY_GEN
#define WOLFSSL_HAVE_SP_RSA

#define WOLFSSL_HAVE_SP_ECC
#define HAVE_ECC256 // specifically enable secp256r1

/* --- Post-Quantum Cryptography (PQC) --- */
#define WOLFSSL_HAVE_MLKEM
#define WOLFSSL_WC_MLKEM
#define HAVE_DILITHIUM
#define WOLFSSL_WC_DILITHIUM

/* --- Performance note ---
 * The LiteX SoC provides ~100 MiB of main RAM, so the wolfCrypt "small memory"
 * PQC paths (WOLFSSL_MLKEM_*_SMALL_MEM, WOLFSSL_DILITHIUM_SMALL,
 * WOLFSSL_DILITHIUM_VERIFY_SMALL_MEM, WOLFSSL_DILITHIUM_NO_LARGE_CODE,
 * WOLFSSL_SHA3_SMALL) are deliberately NOT enabled: they trade speed for a RAM
 * saving this platform does not need, and they were the dominant cost in the
 * 1 MHz handshake. Using the faster (larger) code paths cuts handshake latency
 * and PQC key-exchange cycles at the expense of a higher heap/ROM figure.
 */

/* --- Dependencies --- */
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256

/* --- System & Alignment --- */
#define WOLFSSL_TRUST_PEER_CERT
#define WOLFSSL_GENERAL_ALIGNMENT 4

extern int CustomRngGenerateBlock(unsigned char *, unsigned int);
#define CUSTOM_RAND_GENERATE_SEED CustomRngGenerateBlock

#endif // USER_SETTINGS_H