/**
 * control_center.c - Control Center implementation
 */

#include "control_center.h"
#include "crypto.h"
#include "kyber512.h"

#include <stdio.h>
#include <string.h>

/* ========================================================== */
/* CONTROL CENTER IMPLEMENTATION                               */
/* ========================================================== */

int cc_init(
    ControlCenter *cc,
    const char *cc_id
)
{
    memset(cc, 0, sizeof(ControlCenter));

    printf("\n[CC] === Initializing Control Center ===\n");

    /*
       Derive Control Center identity
    */

    uint8_t hash[SHA256_HASH_SIZE];

    crypto_hash_sha256(
        (const uint8_t *)cc_id,
        strlen(cc_id),
        hash
    );

    memcpy(
        cc->ID_CC,
        hash,
        ID_LENGTH
    );

    print_hex(
        "[CC] ID_CC",
        cc->ID_CC,
        ID_LENGTH
    );

    /*
       Generate Kyber512 keypair
    */

    printf("[CC] Generating Kyber512 keypair...\n");

    if (kyber512_keypair(
            cc->pk_CC,
            cc->sk_CC) != 0)
    {
        return -1;
    }

    printf("[CC] [OK] Keypair generated\n");

    cc->session_active = false;

    return 0;
}

void cc_get_public_key(
    ControlCenter *cc,
    uint8_t *pk_out
)
{
    memcpy(
        pk_out,
        cc->pk_CC,
        KYBER_PUBLICKEYBYTES
    );
}

void cc_get_identity(
    ControlCenter *cc,
    uint8_t *ID_out
)
{
    memcpy(
        ID_out,
        cc->ID_CC,
        ID_LENGTH
    );
}

int cc_process_message1(
    ControlCenter *cc,
    const AuthMessage1 *msg1,
    AuthMessage2 *msg2_out
)
{
    printf("\n[CC] === Processing Message 1 ===\n");

    /*
       Verify protocol version
    */

    if (msg1->version != PROTOCOL_VERSION) {

        printf("[CC] [ERROR] Version mismatch\n");

        return -1;
    }

    /*
       Verify timestamp freshness
    */

    if (!verify_timestamp(msg1->T1)) {

        printf("[CC] [ERROR] Timestamp T1 expired\n");

        return -1;
    }

    printf("[CC] [OK] Timestamp T1 verified\n");

    /*
       Kyber512 decapsulation
    */

    printf("[CC] Performing Kyber512 decapsulation...\n");

    if (kyber512_dec(
            cc->session_ss,
            msg1->ct,
            cc->sk_CC) != 0)
    {
        return -1;
    }

    print_hex(
        "[CC] Shared secret ss",
        cc->session_ss,
        KYBER_SSBYTES
    );

    /*
       Verify:
       M1 = H(ss || ID_SM || ID_CC || r1 || T1)
    */

    uint8_t expected_M1[SHA256_HASH_SIZE];

    compute_auth_message(
        cc->session_ss,
        msg1->ID_SM,
        cc->ID_CC,
        msg1->r1,
        msg1->T1,
        expected_M1
    );

    if (!secure_compare(
            expected_M1,
            msg1->M1,
            SHA256_HASH_SIZE))
    {
        printf("[CC] [ERROR] M1 verification failed\n");

        return -1;
    }

    printf("[CC] [OK] M1 verified - Smart Meter authenticated\n");

    /*
       Store session data
    */

    memcpy(
        cc->session_ID_SM,
        msg1->ID_SM,
        ID_LENGTH
    );

    memcpy(
        cc->session_r1,
        msg1->r1,
        NONCE_LENGTH
    );

    cc->session_T1 = msg1->T1;

    /*
       Generate r2 and T2
    */

    generate_random_bytes(
        cc->session_r2,
        NONCE_LENGTH
    );

    cc->session_T2 = get_timestamp();

    print_hex(
        "[CC] Generated r2",
        cc->session_r2,
        NONCE_LENGTH
    );

    printf(
        "[CC] Generated T2: %llu\n",
        (unsigned long long)cc->session_T2
    );

    /*
       Compute:
       M2 = H(ss || ID_CC || ID_SM || r2 || T2)
    */

    compute_auth_message(
        cc->session_ss,
        cc->ID_CC,
        msg1->ID_SM,
        cc->session_r2,
        cc->session_T2,
        msg2_out->M2
    );

    print_hex(
        "[CC] M2",
        msg2_out->M2,
        SHA256_HASH_SIZE
    );

    /*
       Fill Message 2
    */

    msg2_out->version = PROTOCOL_VERSION;

    memcpy(
        msg2_out->r2,
        cc->session_r2,
        NONCE_LENGTH
    );

    msg2_out->T2 = cc->session_T2;

    memcpy(
        msg2_out->ID_CC,
        cc->ID_CC,
        ID_LENGTH
    );

    printf("[CC] [OK] Message 2 ready\n");

    return 0;
}

int cc_process_message3(
    ControlCenter *cc,
    const AuthMessage3 *msg3
)
{
    printf("\n[CC] === Processing Message 3 ===\n");

    /*
       Verify ID_SM
    */

    if (!secure_compare(
            msg3->ID_SM,
            cc->session_ID_SM,
            ID_LENGTH))
    {
        printf("[CC] [ERROR] ID_SM mismatch\n");

        return -1;
    }

    /*
       Verify:
       M3 = H(ss || r1 || r2)
    */

    uint8_t expected_M3[SHA256_HASH_SIZE];

    uint8_t m3_input[
        KYBER_SSBYTES +
        NONCE_LENGTH +
        NONCE_LENGTH
    ];

    memcpy(
        m3_input,
        cc->session_ss,
        KYBER_SSBYTES
    );

    memcpy(
        m3_input + KYBER_SSBYTES,
        cc->session_r1,
        NONCE_LENGTH
    );

    memcpy(
        m3_input + KYBER_SSBYTES + NONCE_LENGTH,
        cc->session_r2,
        NONCE_LENGTH
    );

    crypto_hash_sha256(
        m3_input,
        sizeof(m3_input),
        expected_M3
    );

    if (!secure_compare(
            expected_M3,
            msg3->M3,
            SHA256_HASH_SIZE))
    {
        printf("[CC] [ERROR] M3 verification failed\n");

        return -1;
    }

    printf("[CC] [OK] M3 verified - Mutual authentication complete\n");

    /*
       Derive session key
    */

    derive_session_key(
        cc->session_ss,
        cc->session_r1,
        cc->session_r2,
        cc->session_T1,
        cc->session_T2,
        cc->session_ID_SM,
        cc->ID_CC,
        cc->session_K
    );

    print_hex(
        "[CC] Session key K_session",
        cc->session_K,
        SESSION_KEY_LENGTH
    );

    printf("[DEBUG] Session Key: ");

    for (int i = 0; i < SESSION_KEY_LENGTH; i++) {
        printf("%02X", cc->session_K[i]);
    }

    printf("\n");

    cc->session_active = true;

    printf("[CC] [OK] Authenticated session established\n");

    return 0;
}

int cc_decrypt_data(
    ControlCenter *cc,
    const uint8_t *encrypted,
    size_t enc_len,
    uint8_t *plaintext,
    size_t *pt_len
)
{
    if (!cc->session_active) {
        return -1;
    }

    /*
       Minimum packet size:
       nonce + tag
    */

    if (enc_len < (GCM_NONCE_SIZE + GCM_TAG_SIZE)) {
        return -1;
    }

    uint8_t nonce[GCM_NONCE_SIZE];
    uint8_t tag[GCM_TAG_SIZE];
    uint8_t ciphertext[512];

    /*
       Packet format:
       nonce || ciphertext || tag
    */

    memcpy(
        nonce,
        encrypted,
        GCM_NONCE_SIZE
    );

    int ciphertext_len =
        (int)enc_len
        - GCM_NONCE_SIZE
        - GCM_TAG_SIZE;

    memcpy(
        ciphertext,
        encrypted + GCM_NONCE_SIZE,
        ciphertext_len
    );

    memcpy(
        tag,
        encrypted + GCM_NONCE_SIZE + ciphertext_len,
        GCM_TAG_SIZE
    );

    /*
       AES-256-GCM decryption
    */

    int decrypted_len = aes256gcm_decrypt(
        cc->session_K,
        nonce,
        ciphertext,
        ciphertext_len,
        tag,
        plaintext
    );

    if (decrypted_len < 0) {

        printf("[CC] [ERROR] AES-256-GCM authentication failed\n");

        return -1;
    }

    *pt_len = decrypted_len;

    printf("[CC] [OK] AES-256-GCM decryption successful\n");

    return 0;
}