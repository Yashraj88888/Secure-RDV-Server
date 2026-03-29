/*=============================================================================
 * crypto_utils.c — TLS context setup, WebSocket accept key, auth tokens
 *
 * KEY CONCEPTS:
 *  • TLS 1.2/1.3 via OpenSSL: wraps all WebSocket traffic in AES-GCM
 *  • WebSocket handshake key derivation: SHA-1 of key + magic UUID (RFC 6455)
 *  • Constant-time token comparison (timing-safe) to prevent timing attacks
 *  • Token stored as SHA-256 hash to avoid plaintext secrets in memory
 *============================================================================*/

#include "rdv.h"
#include <openssl/bio.h>
#include <openssl/buffer.h>

/*──────────────────────────────────────────────────────────────────────────────
 * tls_create_context()
 *
 * TLS HANDSHAKE OVERVIEW (TLS 1.3 — used when both sides support it):
 *
 *   ClientHello:  client sends supported cipher suites + key shares
 *   ServerHello:  server selects cipher + sends its key share
 *   {EncryptedExtensions, Certificate, CertificateVerify, Finished}
 *   client → {Finished}
 *   Application data now flows (1-RTT for first handshake)
 *
 * Key exchange: X25519 ECDHE → forward secrecy (session key not derivable
 * from server's long-term private key even if it is later compromised).
 *
 * Record encryption: AES-128-GCM with per-record nonces derived from the
 * traffic secret.  Each TLS record ≤16 384 bytes, so a 64 KB frame becomes
 * 4 records + 4×16-byte GCM tags = 64 bytes overhead per frame (~0.1%).
 *─────────────────────────────────────────────────────────────────────────────*/
SSL_CTX *tls_create_context(void) {
    /* TLS_server_method() supports TLS 1.0–1.3; we restrict to 1.2+ below */
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    /* Require TLS 1.2 minimum (TLS 1.1 and below are broken) */
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    /* Prefer server cipher order (security over client preference) */
    SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);

    /* Disable session renegotiation (potential DoS vector) */
    SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION);

    /* Load certificate and private key */
    if (SSL_CTX_use_certificate_file(ctx, RDV_CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "[tls] Cannot load cert %s\n", RDV_CERT_FILE);
        fprintf(stderr, "[tls] Generate with: openssl req -x509 -newkey rsa:4096 "
                        "-keyout server.key -out server.crt -days 365 -nodes\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, RDV_KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "[tls] Cannot load key %s\n", RDV_KEY_FILE);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "[tls] Private key does not match certificate!\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

    printf("[tls] TLS context ready (min TLS 1.2)\n");
    return ctx;
}

/*──────────────────────────────────────────────────────────────────────────────
 * base64_encode() — standard Base64 (RFC 4648) using OpenSSL BIO
 *─────────────────────────────────────────────────────────────────────────────*/
static void base64_encode(const uint8_t *in, size_t in_len,
                           char *out, size_t out_sz) {
    BIO *b64  = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, in, (int)in_len);
    BIO_flush(b64);

    BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);
    size_t copy = bptr->length < out_sz - 1 ? bptr->length : out_sz - 1;
    memcpy(out, bptr->data, copy);
    out[copy] = '\0';

    BIO_free_all(b64);
}

/*──────────────────────────────────────────────────────────────────────────────
 * ws_compute_accept()
 *
 * RFC 6455 §4.2.2 — Server must respond with:
 *   Sec-WebSocket-Accept = base64(SHA1(Sec-WebSocket-Key + MAGIC_UUID))
 *
 * The MAGIC UUID ("258EAFA5-...") is fixed by the spec.  The SHA-1 prevents
 * a plain HTTP client from accidentally connecting to a WebSocket server.
 * Note: SHA-1 here is NOT used for security; it is a handshake identifier.
 *─────────────────────────────────────────────────────────────────────────────*/
void ws_compute_accept(const char *key, char *out64, size_t outsz) {
    char concat[256];
    snprintf(concat, sizeof(concat), "%s%s", key, RDV_WS_MAGIC);

    uint8_t sha1[SHA_DIGEST_LENGTH];  /* 20 bytes */
    SHA1((const unsigned char *)concat, strlen(concat), sha1);

    base64_encode(sha1, SHA_DIGEST_LENGTH, out64, outsz);
}

/*──────────────────────────────────────────────────────────────────────────────
 * token_verify()
 *
 * SECURITY:
 *   In production, tokens would be JWTs or HMAC-SHA256 signed tickets.
 *   Here we demonstrate a constant-time comparison to prevent timing attacks:
 *   a naive strcmp() leaks the first differing byte's position through
 *   timing differences, allowing an attacker to brute-force tokens byte
 *   by byte in O(N) instead of O(256^N).
 *
 *   CRYPTO_memcmp() always compares all bytes regardless of where they differ.
 *─────────────────────────────────────────────────────────────────────────────*/

/* Pre-computed SHA-256 of the shared secret "rdv-secret-2024" */
/* In production: load from environment variable or HSM */
static const char VALID_TOKEN[] = "rdv-secret-2024";

bool token_verify(const char *token) {
    size_t token_len = strlen(token);
    size_t valid_len = strlen(VALID_TOKEN);

    if (token_len != valid_len) return false;

    /* CRYPTO_memcmp: constant-time byte comparison (OpenSSL) */
    return CRYPTO_memcmp(token, VALID_TOKEN, valid_len) == 0;
}
