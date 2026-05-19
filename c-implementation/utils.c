/**
 * utils.c - Utility functions implementation
 */

#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/rand.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/time.h>
#endif

/* ========================================================== */
/* TIMESTAMP FUNCTIONS                                         */
/* ========================================================== */

uint64_t get_timestamp(void)
{
    return (uint64_t)time(NULL);
}

bool verify_timestamp(uint64_t T_received)
{
    uint64_t T_now = get_timestamp();

    int64_t diff = (int64_t)(T_now - T_received);

    if (diff < 0) {
        diff = -diff;
    }

    return (diff <= DELTA_T);
}

/* ========================================================== */
/* CRYPTOGRAPHIC RANDOM NUMBER GENERATION                      */
/* ========================================================== */

void generate_random_bytes(
    uint8_t *buffer,
    size_t length
)
{
    if (RAND_bytes(buffer, (int)length) != 1) {

        printf("[ERROR] OpenSSL RAND_bytes failed\n");

        exit(EXIT_FAILURE);
    }
}

/* ========================================================== */
/* DEBUGGING UTILITIES                                         */
/* ========================================================== */

void print_hex(
    const char *label,
    const uint8_t *data,
    size_t len
)
{
    printf("%s: ", label);

    size_t max_print = (len > 16) ? 16 : len;

    for (size_t i = 0; i < max_print; i++) {
        printf("%02X", data[i]);
    }

    if (len > 16) {
        printf("... (%zu bytes total)", len);
    }

    printf("\n");
}

/* ========================================================== */
/* SECURITY UTILITIES                                          */
/* ========================================================== */

bool secure_compare(
    const uint8_t *a,
    const uint8_t *b,
    size_t len
)
{
    uint8_t diff = 0;

    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }

    return (diff == 0);
}