#include "crypto.h"
#include "utils.h"
#include "kyber512.h"
#include <string.h>
#include <stdio.h>

/* ========================================================== */
/* SHA256                                                      */
/* ========================================================== */

void crypto_hash_sha256(
    const uint8_t *data,
    size_t len,
    uint8_t *output
)
{
    SHA256(data, len, output);
}

/* ========================================================== */
/* HMAC-SHA256                                                 */
/* ========================================================== */

void crypto_hmac_sha256(
    const uint8_t *key,
    size_t key_len,
    const uint8_t *data,
    size_t data_len,
    uint8_t *output
)
{
    unsigned int out_len = HMAC_SHA256_SIZE;

    HMAC(
        EVP_sha256(),
        key,
        (int)key_len,
        data,
        data_len,
        output,
        &out_len
    );
}

/* ========================================================== */
/* AES-256-GCM ENCRYPTION                                     */
/* ========================================================== */

int aes256gcm_encrypt(
    const uint8_t *key,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *nonce,
    uint8_t *ciphertext,
    uint8_t *tag
)
{
    EVP_CIPHER_CTX *ctx = NULL;

    int len = 0;
    int ciphertext_len = 0;

    /*
       Generate secure random nonce
    */

    if (RAND_bytes(nonce, GCM_NONCE_SIZE) != 1) {
        return -1;
    }

    ctx = EVP_CIPHER_CTX_new();

    if (!ctx) {
        return -1;
    }

    /*
       Initialize AES-256-GCM
    */

    if (EVP_EncryptInit_ex(
            ctx,
            EVP_aes_256_gcm(),
            NULL,
            NULL,
            NULL) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /*
       Set nonce length
    */

    if (EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_SET_IVLEN,
            GCM_NONCE_SIZE,
            NULL) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /*
       Set key and nonce
    */

    if (EVP_EncryptInit_ex(
            ctx,
            NULL,
            NULL,
            key,
            nonce) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /*
       Encrypt plaintext
    */

    if (EVP_EncryptUpdate(
            ctx,
            ciphertext,
            &len,
            plaintext,
            (int)plaintext_len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    ciphertext_len = len;

    /*
       Finalize encryption
    */

    if (EVP_EncryptFinal_ex(
            ctx,
            ciphertext + len,
            &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    ciphertext_len += len;

    /*
       Extract authentication tag
    */

    if (EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_GET_TAG,
            GCM_TAG_SIZE,
            tag) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

/* ========================================================== */
/* AES-256-GCM DECRYPTION                                     */
/* ========================================================== */

int aes256gcm_decrypt(
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *tag,
    uint8_t *plaintext
)
{
    EVP_CIPHER_CTX *ctx = NULL;

    int len = 0;
    int plaintext_len = 0;
    int ret;

    ctx = EVP_CIPHER_CTX_new();

    if (!ctx) {
        return -1;
    }

    /*
       Initialize AES-256-GCM
    */

    if (EVP_DecryptInit_ex(
            ctx,
            EVP_aes_256_gcm(),
            NULL,
            NULL,
            NULL) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /*
       Set nonce length
    */

    if (EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_SET_IVLEN,
            GCM_NONCE_SIZE,
            NULL) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /*
       Set key and nonce
    */

    if (EVP_DecryptInit_ex(
            ctx,
            NULL,
            NULL,
            key,
            nonce) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /*
       Decrypt ciphertext
    */

    if (EVP_DecryptUpdate(
            ctx,
            plaintext,
            &len,
            ciphertext,
            (int)ciphertext_len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    plaintext_len = len;

    /*
       Set expected authentication tag
    */

    if (EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_SET_TAG,
            GCM_TAG_SIZE,
            (void *)tag) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /*
       Verify tag and finalize
    */

    ret = EVP_DecryptFinal_ex(
        ctx,
        plaintext + len,
        &len
    );

    EVP_CIPHER_CTX_free(ctx);

    /*
       Authentication success
    */

    if (ret > 0)
    {
        plaintext_len += len;
        return plaintext_len;
    }

    /*
       Authentication failed
    */

    return -1;
}
/* ========================================================== */
/* AUTHENTICATION HELPERS                                      */
/* ========================================================== */

void compute_auth_message(
    const uint8_t *ss,
    const uint8_t *ID_sender,
    const uint8_t *ID_receiver,
    const uint8_t *nonce,
    uint64_t timestamp,
    uint8_t *output
)
{
    uint8_t buffer[256];

    size_t offset = 0;

    memcpy(buffer + offset, ss, KYBER_SSBYTES);
    offset += KYBER_SSBYTES;

    memcpy(buffer + offset, ID_sender, ID_LENGTH);
    offset += ID_LENGTH;

    memcpy(buffer + offset, ID_receiver, ID_LENGTH);
    offset += ID_LENGTH;

    memcpy(buffer + offset, nonce, NONCE_LENGTH);
    offset += NONCE_LENGTH;

    memcpy(buffer + offset, &timestamp, sizeof(uint64_t));
    offset += sizeof(uint64_t);

    crypto_hash_sha256(
        buffer,
        offset,
        output
    );
}

void derive_session_key(
    const uint8_t *ss,
    const uint8_t *r1,
    const uint8_t *r2,
    uint64_t T1,
    uint64_t T2,
    const uint8_t *ID_SM,
    const uint8_t *ID_CC,
    uint8_t *K_session
)
{
    uint8_t buffer[512];

    size_t offset = 0;

    memcpy(buffer + offset, ss, KYBER_SSBYTES);
    offset += KYBER_SSBYTES;

    memcpy(buffer + offset, r1, NONCE_LENGTH);
    offset += NONCE_LENGTH;

    memcpy(buffer + offset, r2, NONCE_LENGTH);
    offset += NONCE_LENGTH;

    memcpy(buffer + offset, &T1, sizeof(uint64_t));
    offset += sizeof(uint64_t);

    memcpy(buffer + offset, &T2, sizeof(uint64_t));
    offset += sizeof(uint64_t);

    memcpy(buffer + offset, ID_SM, ID_LENGTH);
    offset += ID_LENGTH;

    memcpy(buffer + offset, ID_CC, ID_LENGTH);
    offset += ID_LENGTH;

    crypto_hash_sha256(
        buffer,
        offset,
        K_session
    );
}