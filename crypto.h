#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

/* ========================================================== */
/* CRYPTO CONSTANTS                                            */
/* ========================================================== */

#define AES_KEY_SIZE       32
#define GCM_NONCE_SIZE     12
#define GCM_TAG_SIZE       16

#define SHA256_HASH_SIZE   32
#define HMAC_SHA256_SIZE   32

/* ========================================================== */
/* HASHING                                                     */
/* ========================================================== */

/**
 * SHA256 hash wrapper
 */
void crypto_hash_sha256(
    const uint8_t *data,
    size_t len,
    uint8_t *output
);

/* ========================================================== */
/* HMAC                                                        */
/* ========================================================== */

/**
 * HMAC-SHA256 wrapper
 */
void crypto_hmac_sha256(
    const uint8_t *key,
    size_t key_len,
    const uint8_t *data,
    size_t data_len,
    uint8_t *output
);

/* ========================================================== */
/* AES-256-GCM                                                 */
/* ========================================================== */

/**
 * Encrypt:
 * packet format = nonce || ciphertext || tag
 */
int aes256gcm_encrypt(
    const uint8_t *key,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *nonce,
    uint8_t *ciphertext,
    uint8_t *tag
);

/**
 * Decrypt:
 * expects packet format = nonce || ciphertext || tag
 */
int aes256gcm_decrypt(
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *tag,
    uint8_t *plaintext
);
/* ========================================================== */
/* AUTHENTICATION HELPERS                                      */
/* ========================================================== */

/**
 * Compute authentication message hash
 */
void compute_auth_message(
    const uint8_t *ss,
    const uint8_t *ID_sender,
    const uint8_t *ID_receiver,
    const uint8_t *nonce,
    uint64_t timestamp,
    uint8_t *output
);

/**
 * Derive session key
 */
void derive_session_key(
    const uint8_t *ss,
    const uint8_t *r1,
    const uint8_t *r2,
    uint64_t T1,
    uint64_t T2,
    const uint8_t *ID_SM,
    const uint8_t *ID_CC,
    uint8_t *K_session
);
#endif /* CRYPTO_H */