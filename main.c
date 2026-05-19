/**
 * main.c - MLWE-AMI Desktop Prototype
 *
 * Complete simulation of the authentication protocol
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ami_auth.h"
#include "control_center.h"
#include "crypto.h"
#include "utils.h"

/* ========================================================== */
/* SIMULATION HELPERS                                          */
/* ========================================================== */

void print_banner(const char *title)
{
    printf("\n");

    printf("+====================================================================+\n");
    printf("| %-66s |\n", title);
    printf("+====================================================================+\n");
}

void print_section(const char *title)
{
    printf("\n");

    printf("======================================================================\n");
    printf("  %s\n", title);
    printf("======================================================================\n");
}

/* ========================================================== */
/* MAIN DEMONSTRATION                                          */
/* ========================================================== */

int main(void)
{
    int ret;

    print_banner(
        "MLWE-AMI AUTHENTICATION PROTOCOL - DESKTOP PROTOTYPE"
    );

    printf("\n");
    printf("Target Platform : Desktop (Windows/GCC)\n");
    printf("Future Platform : STM32L475VG Cortex-M4\n");

    printf("\n");
    printf("This is a desktop prototype implementation.\n");
    printf("Kyber512 is currently simulated.\n");

    /* ====================================================== */
    /* SETUP PHASE                                             */
    /* ====================================================== */

    print_section("SETUP PHASE");

    ControlCenter cc;

    ret = cc_init(
        &cc,
        "CC_MAIN"
    );

    if (ret != 0) {

        printf("[ERROR] Control Center initialization failed\n");

        return 1;
    }

    uint8_t pk_CC[KYBER_PUBLICKEYBYTES];

    uint8_t ID_CC[ID_LENGTH];

    cc_get_public_key(
        &cc,
        pk_CC
    );

    cc_get_identity(
        &cc,
        ID_CC
    );

    printf("\n[OK] Setup Phase complete\n");

    /* ====================================================== */
    /* SMART METER INITIALIZATION                              */
    /* ====================================================== */

    print_section("SMART METER INITIALIZATION");

    SmartMeter sm;

    ret = sm_init(
        &sm,
        "SM_001",
        pk_CC,
        ID_CC
    );

    if (ret != 0) {

        printf("[ERROR] Smart Meter initialization failed\n");

        return 1;
    }

    print_hex(
        "[SM] ID_SM",
        sm.ID_SM,
        ID_LENGTH
    );

    printf("\n[OK] Smart Meter ready\n");

    /* ====================================================== */
    /* AUTHENTICATION PHASE                                    */
    /* ====================================================== */

    print_section("AUTHENTICATION PHASE");

    /*
       Message 1:
       SM -> CC
    */

    AuthMessage1 msg1;

    ret = sm_initiate_authentication(
        &sm,
        &msg1
    );

    if (ret != 0) {

        printf("[ERROR] M1 generation failed\n");

        return 1;
    }

    printf("\n");
    printf("[NETWORK] Simulating M1 transmission (SM -> CC)\n");

    printf(
        "[NETWORK] Message size: %zu bytes\n",
        sizeof(AuthMessage1)
    );

    /*
       Message 2:
       CC -> SM
    */

    AuthMessage2 msg2;

    ret = cc_process_message1(
        &cc,
        &msg1,
        &msg2
    );

    if (ret != 0) {

        printf("[ERROR] M1 processing failed\n");

        return 1;
    }

    printf("\n");
    printf("[NETWORK] Simulating M2 transmission (CC -> SM)\n");

    printf(
        "[NETWORK] Message size: %zu bytes\n",
        sizeof(AuthMessage2)
    );

    /*
       Message 3:
       SM -> CC
    */

    AuthMessage3 msg3;

    ret = sm_process_message2(
        &sm,
        &msg2,
        &msg3
    );

    if (ret != 0) {

        printf("[ERROR] M2 processing failed\n");

        return 1;
    }

    printf("\n");
    printf("[NETWORK] Simulating M3 transmission (SM -> CC)\n");

    printf(
        "[NETWORK] Message size: %zu bytes\n",
        sizeof(AuthMessage3)
    );

    /*
       Final verification
    */

    ret = cc_process_message3(
        &cc,
        &msg3
    );

    if (ret != 0) {

        printf("[ERROR] M3 verification failed\n");

        return 1;
    }

    printf("\n[OK] Mutual authentication successful\n");

    /* ====================================================== */
    /* SESSION KEY VERIFICATION                                */
    /* ====================================================== */

    print_section("SESSION KEY VERIFICATION");

    uint8_t sm_key[SESSION_KEY_LENGTH];

    if (sm_get_session_key(
            &sm,
            sm_key) != 0)
    {
        printf("[ERROR] Failed to export SM session key\n");

        return 1;
    }

    if (secure_compare(
            sm_key,
            cc.session_K,
            SESSION_KEY_LENGTH))
    {
        printf("[OK] Session keys match\n");
    }
    else {

        printf("[ERROR] Session key mismatch\n");

        return 1;
    }

    /* ====================================================== */
    /* SECURE DATA TRANSMISSION                                */
    /* ====================================================== */

    print_section("SECURE DATA TRANSMISSION");

    const char *sensor_data =
        "Smart Meter Reading: 12.45 kWh";

    printf(
        "\n[SM] Plaintext Data: %s\n",
        sensor_data
    );

    uint8_t encrypted_packet[512];

    size_t encrypted_len = 0;

    ret = sm_encrypt_data(
        &sm,
        (const uint8_t *)sensor_data,
        strlen(sensor_data),
        encrypted_packet,
        &encrypted_len
    );

    if (ret != 0) {

        printf("[ERROR] Data encryption failed\n");

        return 1;
    }

    printf(
        "[NETWORK] Encrypted packet size: %zu bytes\n",
        encrypted_len
    );

    uint8_t decrypted[512];

    size_t decrypted_len = 0;

    ret = cc_decrypt_data(
        &cc,
        encrypted_packet,
        encrypted_len,
        decrypted,
        &decrypted_len
    );

    if (ret != 0) {

        printf("[ERROR] Data decryption failed\n");

        return 1;
    }

    decrypted[decrypted_len] = '\0';

    printf(
        "[CC] Decrypted Data: %s\n",
        decrypted
    );

    /*
       Verify integrity
    */

    if (strcmp(
            sensor_data,
            (char *)decrypted) == 0)
    {
        printf("[OK] Integrity verification successful\n");
    }
    else {

        printf("[ERROR] Integrity verification failed\n");

        return 1;
    }

    /* ====================================================== */
    /* FINAL STATUS                                            */
    /* ====================================================== */

    print_section("FINAL STATUS");

    printf("[OK] MLWE authentication successful\n");

    printf("[OK] Session key established\n");

    printf("[OK] AES-256-GCM encryption operational\n");

    printf("[OK] AES-256-GCM decryption operational\n");

    printf("[OK] Protocol execution completed successfully\n");

    return 0;
}