#include "kyber512.h"

#include <oqs/oqs.h>

int kyber512_keypair(
    uint8_t *pk,
    uint8_t *sk
)
{
    OQS_KEM *kem =
        OQS_KEM_new(OQS_KEM_alg_ml_kem_512);

    if (!kem)
        return -1;

    if (OQS_KEM_keypair(
            kem,
            pk,
            sk) != OQS_SUCCESS)
    {
        OQS_KEM_free(kem);

        return -1;
    }

    OQS_KEM_free(kem);

    return 0;
}

int kyber512_enc(
    uint8_t *ct,
    uint8_t *ss,
    const uint8_t *pk
)
{
    OQS_KEM *kem =
        OQS_KEM_new(OQS_KEM_alg_ml_kem_512);

    if (!kem)
        return -1;

    if (OQS_KEM_encaps(
            kem,
            ct,
            ss,
            pk) != OQS_SUCCESS)
    {
        OQS_KEM_free(kem);

        return -1;
    }

    OQS_KEM_free(kem);

    return 0;
}

int kyber512_dec(
    uint8_t *ss,
    const uint8_t *ct,
    const uint8_t *sk
)
{
    OQS_KEM *kem =
        OQS_KEM_new(OQS_KEM_alg_ml_kem_512);

    if (!kem)
        return -1;

    if (OQS_KEM_decaps(
            kem,
            ss,
            ct,
            sk) != OQS_SUCCESS)
    {
        OQS_KEM_free(kem);

        return -1;
    }

    OQS_KEM_free(kem);

    return 0;
}