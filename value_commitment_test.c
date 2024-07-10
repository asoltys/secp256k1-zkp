#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <secp256k1.h>
#include "./include/secp256k1_generator.h"
#include "./include/secp256k1_rangeproof.h"

// Function to convert a hexadecimal string to a byte array
void hex_to_bytes(const char *hex, unsigned char *bytes, size_t bytes_len) {
    for (size_t i = 0; i < bytes_len; i++) {
        sscanf(&hex[i * 2], "%2hhx", &bytes[i]);
    }
}

// Function to convert a byte array to a hexadecimal string
void bytes_to_hex(const unsigned char *bytes, size_t bytes_len, char *hex) {
    for (size_t i = 0; i < bytes_len; i++) {
        sprintf(&hex[i * 2], "%02x", bytes[i]);
    }
}

// Function to print a point
void print_point(const secp256k1_context *ctx, const secp256k1_pubkey *pubkey, const char *label) {
    unsigned char pubkey_bytes[33];
    size_t output_length = 33;
    secp256k1_ec_pubkey_serialize(ctx, pubkey_bytes, &output_length, pubkey, SECP256K1_EC_COMPRESSED);
    char pubkey_hex[67];
    bytes_to_hex(pubkey_bytes, 33, pubkey_hex);
    printf("%s (hex): %s\n", label, pubkey_hex);
}


// Function to print a scalar
void print_scalar(const unsigned char *scalar, const char *label) {
    char scalar_hex[65];
    bytes_to_hex(scalar, 32, scalar_hex);
    printf("%s: %s\n", label, scalar_hex);
}

int main() {
    // Initialize the secp256k1 context
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    // Test data
    const char *generator_hex = "0ba4fd25e0e2108e55aec683810a8652f9b067242419a1f7cc0f01f92b4b078252";
    const char *blinder_hex = "8b5d87d94b9f54dc5dd9f31df5dffedc974fc4d5bf0d2ee1297e5aba504ccc26";
    const char *expected_hex = "08a9de5e391458abf4eb6ff0cc346fa0a8b5b0806b2ee9261dde54d436423c1982";

    // Convert hex strings to byte arrays
    unsigned char generator_bytes[33];
    unsigned char blinder[32];
    unsigned char expected_commitment[33];
    hex_to_bytes(generator_hex, generator_bytes, 33);
    hex_to_bytes(blinder_hex, blinder, 32);
    hex_to_bytes(expected_hex, expected_commitment, 33);

    // Deserialize generator
    secp256k1_generator generator;
    if (!secp256k1_generator_parse(ctx, &generator, generator_bytes)) {
        printf("Failed to parse generator.\n");
        return 1;
    }

    // Log the generator point using print_point function
    print_point(ctx, (secp256k1_pubkey *)&generator, "Generator Point G2");

    // Serialize the generator point and print the Y coordinate (the function has been modified to print Y)
    unsigned char output[33];
    secp256k1_generator_serialize(ctx, output, &generator);

    const char *value_str = "10000";
    uint64_t value = strtoull(value_str, NULL, 10);

    // Create the commitment
    secp256k1_pedersen_commitment commitment;
    if (!secp256k1_pedersen_commit(ctx, &commitment, blinder, value, &generator)) {
        printf("Failed to create value commitment.\n");
        return 1;
    }

    // Serialize and log the commitment
    unsigned char commitment_bytes[33];
    secp256k1_pedersen_commitment_serialize(ctx, commitment_bytes, &commitment);

    char commitment_hex[67];
    bytes_to_hex(commitment_bytes, 33, commitment_hex);
    printf("%s (hex): %s\n", "Commitment hex", commitment_hex);

    // Compare the created commitment with the expected commitment
    if (memcmp(commitment_bytes, expected_commitment, 33) == 0) {
        printf("Value commitment matches expected result.\n");
    } else {
        printf("Value commitment does not match expected result.\n");
    }

    // Destroy the secp256k1 context
    secp256k1_context_destroy(ctx);

    return 0;
}
