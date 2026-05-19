/**
 * utils.h - Utility functions for MLWE-AMI protocol
 */

#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ========================================================== */
/* CONSTANTS                                                   */
/* ========================================================== */

#define PROTOCOL_VERSION   0x0100

#define DELTA_T            300
#define SESSION_TIMEOUT    3600

#define NONCE_LENGTH       16
#define SESSION_KEY_LENGTH 32
#define ID_LENGTH          16

#define AES_KEY_SIZE       32
#define GCM_NONCE_SIZE     12
#define GCM_TAG_SIZE       16

/* ========================================================== */
/* UTILITY FUNCTIONS                                           */
/* ========================================================== */

/**
 * @brief Get current Unix timestamp
 */
uint64_t get_timestamp(void);

/**
 * @brief Verify timestamp freshness
 */
bool verify_timestamp(uint64_t T_received);

/**
 * @brief Generate cryptographically secure random bytes
 */
void generate_random_bytes(
    uint8_t *buffer,
    size_t length
);

/**
 * @brief Print hex dump
 */
void print_hex(
    const char *label,
    const uint8_t *data,
    size_t len
);

/**
 * @brief Constant-time memory comparison
 */
bool secure_compare(
    const uint8_t *a,
    const uint8_t *b,
    size_t len
);

#endif /* UTILS_H */