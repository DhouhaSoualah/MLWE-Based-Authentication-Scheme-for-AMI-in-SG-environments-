/**
 * control_center.h - Control Center module
 */

#ifndef CONTROL_CENTER_H
#define CONTROL_CENTER_H
#include <stdint.h>
#include <stdbool.h>

#include "utils.h"
#include "kyber512.h"
#include "ami_auth.h"
/* ========================================================== */
/* CONTROL CENTER STATE                                        */
/* ========================================================== */

typedef struct
{
    /*
       Control Center identity
    */

    uint8_t ID_CC[ID_LENGTH];

    /*
       Kyber512 keypair
    */

    uint8_t pk_CC[KYBER_PUBLICKEYBYTES];
    uint8_t sk_CC[KYBER_SECRETKEYBYTES];

    /*
       Session tracking
    */

    bool session_active;

    uint8_t session_ID_SM[ID_LENGTH];

    uint8_t session_ss[KYBER_SSBYTES];

    uint8_t session_r1[NONCE_LENGTH];
    uint8_t session_r2[NONCE_LENGTH];

    uint64_t session_T1;
    uint64_t session_T2;

    uint8_t session_K[SESSION_KEY_LENGTH];

} ControlCenter;

/* ========================================================== */
/* CONTROL CENTER FUNCTIONS                                    */
/* ========================================================== */

/**
 * @brief Initialize Control Center
 */
int cc_init(
    ControlCenter *cc,
    const char *cc_id
);

/**
 * @brief Get public key
 */
void cc_get_public_key(
    ControlCenter *cc,
    uint8_t *pk_out
);

/**
 * @brief Get identity
 */
void cc_get_identity(
    ControlCenter *cc,
    uint8_t *ID_out
);

/**
 * @brief Process M1 and generate M2
 */
int cc_process_message1(
    ControlCenter *cc,
    const AuthMessage1 *msg1,
    AuthMessage2 *msg2_out
);

/**
 * @brief Process M3 (final verification)
 */
int cc_process_message3(
    ControlCenter *cc,
    const AuthMessage3 *msg3
);

/**
 * @brief Decrypt secure payload
 *
 * Packet format:
 * nonce || ciphertext || tag
 */
int cc_decrypt_data(
    ControlCenter *cc,
    const uint8_t *encrypted,
    size_t enc_len,
    uint8_t *plaintext,
    size_t *pt_len
);

#endif /* CONTROL_CENTER_H */