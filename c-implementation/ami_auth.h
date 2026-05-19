/**
 * ami_auth.h - Smart Meter authentication module
 */

#ifndef AMI_AUTH_H
#define AMI_AUTH_H

#include <stdint.h>
#include <stdbool.h>

#include "utils.h"
#include "kyber512.h"
#include "crypto.h"
#include "sha256.h"
/* ========================================================== */
/* MESSAGE STRUCTURES                                          */
/* ========================================================== */

/**
 * Message 1:
 * SM -> CC
 */

typedef struct
{
    uint16_t version;

    /*
       Kyber512 ciphertext
    */

    uint8_t ct[KYBER_CIPHERTEXTBYTES];

    /*
       Authentication hash
    */

    uint8_t M1[SHA256_HASH_SIZE];

    /*
       Nonce and timestamp
    */

    uint8_t r1[NONCE_LENGTH];

    uint64_t T1;

    /*
       Smart Meter identity
    */

    uint8_t ID_SM[ID_LENGTH];

} AuthMessage1;

/**
 * Message 2:
 * CC -> SM
 */

typedef struct
{
    uint16_t version;

    uint8_t M2[SHA256_HASH_SIZE];

    uint8_t r2[NONCE_LENGTH];

    uint64_t T2;

    uint8_t ID_CC[ID_LENGTH];

} AuthMessage2;

/**
 * Message 3:
 * SM -> CC
 */

typedef struct
{
    uint16_t version;

    uint8_t M3[SHA256_HASH_SIZE];

    uint8_t ID_SM[ID_LENGTH];

} AuthMessage3;

/* ========================================================== */
/* SMART METER STATE                                           */
/* ========================================================== */

typedef enum
{
    SM_STATE_IDLE,

    SM_STATE_WAITING_M2,

    SM_STATE_AUTHENTICATED,

    SM_STATE_ERROR

} SmartMeterState;

/* ========================================================== */
/* SMART METER STRUCTURE                                       */
/* ========================================================== */

typedef struct
{
    /*
       Identities
    */

    uint8_t ID_SM[ID_LENGTH];

    uint8_t ID_CC[ID_LENGTH];

    /*
       Control Center public key
    */

    uint8_t pk_CC[KYBER_PUBLICKEYBYTES];

    /*
       Authentication state
    */

    SmartMeterState state;

    /*
       Session data
    */

    uint8_t current_ss[KYBER_SSBYTES];

    uint8_t r1[NONCE_LENGTH];

    uint64_t T1;

    uint8_t K_session[SESSION_KEY_LENGTH];

    uint64_t session_started;

} SmartMeter;

/* ========================================================== */
/* SMART METER FUNCTIONS                                       */
/* ========================================================== */

/**
 * @brief Initialize Smart Meter
 */
int sm_init(
    SmartMeter *sm,
    const char *sm_id,
    const uint8_t *pk_CC,
    const uint8_t *ID_CC
);

/**
 * @brief Initiate authentication (Generate M1)
 */
int sm_initiate_authentication(
    SmartMeter *sm,
    AuthMessage1 *msg1_out
);

/**
 * @brief Process M2 and generate M3
 */
int sm_process_message2(
    SmartMeter *sm,
    const AuthMessage2 *msg2,
    AuthMessage3 *msg3_out
);

/**
 * @brief Encrypt secure payload
 *
 * Packet format:
 * nonce || ciphertext || tag
 */
int sm_encrypt_data(
    SmartMeter *sm,
    const uint8_t *plaintext,
    size_t pt_len,
    uint8_t *output,
    size_t *output_len
);

/**
 * @brief Export session key
 */
int sm_get_session_key(
    SmartMeter *sm,
    uint8_t *key_out
);

#endif /* AMI_AUTH_H */