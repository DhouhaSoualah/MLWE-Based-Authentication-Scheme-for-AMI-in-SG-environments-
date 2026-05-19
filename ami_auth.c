/**
 * ami_auth.c - Smart Meter authentication implementation
 */

#include "ami_auth.h"
#include "crypto.h"
#include "kyber512.h"

#include <stdio.h>
#include <string.h>

/* ========================================================== */
/* SMART METER IMPLEMENTATION                                  */
/* ========================================================== */

int sm_init(
    SmartMeter *sm,
    const char *sm_id,
    const uint8_t *pk_CC,
    const uint8_t *ID_CC
)
{
    memset(sm, 0, sizeof(SmartMeter));

    /*
       Derive Smart Meter identity
    */

    uint8_t hash[SHA256_HASH_SIZE];

    crypto_hash_sha256(
        (const uint8_t *)sm_id,
        strlen(sm_id),
        hash
    );

    memcpy(
        sm->ID_SM,
        hash,
        ID_LENGTH
    );

    /*
       Store Control Center credentials
    */

    memcpy(
        sm->pk_CC,
        pk_CC,
        KYBER_PUBLICKEYBYTES
    );

    memcpy(
        sm->ID_CC,
        ID_CC,
        ID_LENGTH
    );

    sm->state = SM_STATE_IDLE;

    return 0;
}

int sm_initiate_authentication(
    SmartMeter *sm,
    AuthMessage1 *msg1_out
)
{
    if (sm->state != SM_STATE_IDLE) {
        return -1;
    }

    printf("\n[SM] === Generating Message 1 ===\n");

    /*
       Generate nonce r1
    */

    generate_random_bytes(
        sm->r1,
        NONCE_LENGTH
    );

    print_hex(
        "[SM] Generated r1",
        sm->r1,
        NONCE_LENGTH
    );

    /*
       Generate timestamp T1
    */

    sm->T1 = get_timestamp();

    printf(
        "[SM] Timestamp T1: %llu\n",
        (unsigned long long)sm->T1
    );

    /*
       Kyber512 encapsulation
    */

    printf("[SM] Performing Kyber512 encapsulation...\n");

    if (kyber512_enc(
            msg1_out->ct,
            sm->current_ss,
            sm->pk_CC) != 0)
    {
        return -1;
    }

    print_hex(
        "[SM] Shared secret ss",
        sm->current_ss,
        KYBER_SSBYTES
    );

    /*
       Compute:
       M1 = H(ss || ID_SM || ID_CC || r1 || T1)
    */

    compute_auth_message(
        sm->current_ss,
        sm->ID_SM,
        sm->ID_CC,
        sm->r1,
        sm->T1,
        msg1_out->M1
    );

    print_hex(
        "[SM] M1",
        msg1_out->M1,
        SHA256_HASH_SIZE
    );

    /*
       Fill Message 1
    */

    msg1_out->version = PROTOCOL_VERSION;

    memcpy(
        msg1_out->r1,
        sm->r1,
        NONCE_LENGTH
    );

    msg1_out->T1 = sm->T1;

    memcpy(
        msg1_out->ID_SM,
        sm->ID_SM,
        ID_LENGTH
    );

    sm->state = SM_STATE_WAITING_M2;

    printf("[SM] [OK] Message 1 ready\n");

    return 0;
}

int sm_process_message2(
    SmartMeter *sm,
    const AuthMessage2 *msg2,
    AuthMessage3 *msg3_out
)
{
    if (sm->state != SM_STATE_WAITING_M2) {
        return -1;
    }

    printf("\n[SM] === Processing Message 2 ===\n");

    /*
       Verify protocol version
    */

    if (msg2->version != PROTOCOL_VERSION) {

        printf("[SM] [ERROR] Version mismatch\n");

        sm->state = SM_STATE_ERROR;

        return -1;
    }

    /*
       Verify timestamp freshness
    */

    if (!verify_timestamp(msg2->T2)) {

        printf("[SM] [ERROR] Timestamp T2 expired\n");

        sm->state = SM_STATE_ERROR;

        return -1;
    }

    printf("[SM] [OK] Timestamp T2 verified\n");

    /*
       Verify Control Center identity
    */

    if (!secure_compare(
            msg2->ID_CC,
            sm->ID_CC,
            ID_LENGTH))
    {
        printf("[SM] [ERROR] ID_CC mismatch\n");

        sm->state = SM_STATE_ERROR;

        return -1;
    }

    printf("[SM] [OK] ID_CC verified\n");

    /*
       Verify:
       M2 = H(ss || ID_CC || ID_SM || r2 || T2)
    */

    uint8_t expected_M2[SHA256_HASH_SIZE];

    compute_auth_message(
        sm->current_ss,
        msg2->ID_CC,
        sm->ID_SM,
        msg2->r2,
        msg2->T2,
        expected_M2
    );

    if (!secure_compare(
            expected_M2,
            msg2->M2,
            SHA256_HASH_SIZE))
    {
        printf("[SM] [ERROR] M2 verification failed\n");

        sm->state = SM_STATE_ERROR;

        return -1;
    }

    printf("[SM] [OK] M2 verified - CC authenticated\n");

    /*
       Compute:
       M3 = H(ss || r1 || r2)
    */

    uint8_t m3_input[
        KYBER_SSBYTES +
        NONCE_LENGTH +
        NONCE_LENGTH
    ];

    memcpy(
        m3_input,
        sm->current_ss,
        KYBER_SSBYTES
    );

    memcpy(
        m3_input + KYBER_SSBYTES,
        sm->r1,
        NONCE_LENGTH
    );

    memcpy(
        m3_input + KYBER_SSBYTES + NONCE_LENGTH,
        msg2->r2,
        NONCE_LENGTH
    );

    crypto_hash_sha256(
        m3_input,
        sizeof(m3_input),
        msg3_out->M3
    );

    print_hex(
        "[SM] M3",
        msg3_out->M3,
        SHA256_HASH_SIZE
    );

    /*
       Derive session key
    */

    derive_session_key(
        sm->current_ss,
        sm->r1,
        msg2->r2,
        sm->T1,
        msg2->T2,
        sm->ID_SM,
        msg2->ID_CC,
        sm->K_session
    );

    print_hex(
        "[SM] Session key K_session",
        sm->K_session,
        SESSION_KEY_LENGTH
    );

    printf("[DEBUG] Session Key: ");

    for (int i = 0; i < SESSION_KEY_LENGTH; i++) {
        printf("%02X", sm->K_session[i]);
    }

    printf("\n");

    sm->session_started = get_timestamp();

    sm->state = SM_STATE_AUTHENTICATED;

    /*
       Fill Message 3
    */

    msg3_out->version = PROTOCOL_VERSION;

    memcpy(
        msg3_out->ID_SM,
        sm->ID_SM,
        ID_LENGTH
    );

    printf("[SM] [OK] Message 3 ready\n");

    return 0;
}

int sm_encrypt_data(
    SmartMeter *sm,
    const uint8_t *plaintext,
    size_t pt_len,
    uint8_t *output,
    size_t *output_len
)
{
    if (sm->state != SM_STATE_AUTHENTICATED) {
        return -1;
    }

    /*
       Check session timeout
    */

    uint64_t now = get_timestamp();

    if (now - sm->session_started > SESSION_TIMEOUT) {

        sm->state = SM_STATE_IDLE;

        return -1;
    }

    uint8_t ciphertext[256];

    uint8_t nonce[GCM_NONCE_SIZE];

    uint8_t tag[GCM_TAG_SIZE];

    /*
       AES-256-GCM encryption
    */

    int ciphertext_len = aes256gcm_encrypt(
        sm->K_session,
        plaintext,
        pt_len,
        nonce,
        ciphertext,
        tag
    );

    if (ciphertext_len < 0) {

        printf("[SM] [ERROR] AES-256-GCM encryption failed\n");

        return -1;
    }

    /*
       Packet format:
       nonce || ciphertext || tag
    */

    memcpy(
        output,
        nonce,
        GCM_NONCE_SIZE
    );

    memcpy(
        output + GCM_NONCE_SIZE,
        ciphertext,
        ciphertext_len
    );

    memcpy(
        output + GCM_NONCE_SIZE + ciphertext_len,
        tag,
        GCM_TAG_SIZE
    );

    *output_len =
        GCM_NONCE_SIZE +
        ciphertext_len +
        GCM_TAG_SIZE;

    printf("[SM] [OK] AES-256-GCM encryption successful\n");

    return 0;
}

int sm_get_session_key(
    SmartMeter *sm,
    uint8_t *key_out
)
{
    if (sm->state != SM_STATE_AUTHENTICATED) {
        return -1;
    }

    /*
       Check session timeout
    */

    uint64_t now = get_timestamp();

    if (now - sm->session_started > SESSION_TIMEOUT) {

        sm->state = SM_STATE_IDLE;

        return -1;
    }

    memcpy(
        key_out,
        sm->K_session,
        SESSION_KEY_LENGTH
    );

    return 0;
}