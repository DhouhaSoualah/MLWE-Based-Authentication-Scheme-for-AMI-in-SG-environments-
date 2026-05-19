#ifndef KYBER512_H
#define KYBER512_H

#include <stdint.h>
#include <stddef.h>

#include <oqs/oqs.h>

/*
    ML-KEM-512 (Kyber512)
*/

#define KYBER_PUBLICKEYBYTES  OQS_KEM_ml_kem_512_length_public_key
#define KYBER_SECRETKEYBYTES  OQS_KEM_ml_kem_512_length_secret_key
#define KYBER_CIPHERTEXTBYTES OQS_KEM_ml_kem_512_length_ciphertext
#define KYBER_SSBYTES         OQS_KEM_ml_kem_512_length_shared_secret

/*
    REAL ML-KEM FUNCTIONS
*/

int kyber512_keypair(
    uint8_t *pk,
    uint8_t *sk
);

int kyber512_enc(
    uint8_t *ct,
    uint8_t *ss,
    const uint8_t *pk
);

int kyber512_dec(
    uint8_t *ss,
    const uint8_t *ct,
    const uint8_t *sk
);

#endif