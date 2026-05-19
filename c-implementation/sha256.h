/**
 * sha256.h - Legacy SHA-256 implementation
 * Retained for compatibility only.
 *
 * OpenSSL SHA256 is now the primary hash implementation.
 */

#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

typedef struct
{
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[64];

} sha256_ctx;

/* Legacy SHA-256 API */

void sha256_init(
    sha256_ctx *ctx
);

void sha256_update(
    sha256_ctx *ctx,
    const uint8_t *data,
    size_t len
);

void sha256_final(
    sha256_ctx *ctx,
    uint8_t *hash
);

/* Convenience function */

void sha256(
    const uint8_t *data,
    size_t len,
    uint8_t *hash
);

#endif /* SHA256_H */