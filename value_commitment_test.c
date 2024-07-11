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

void print_point(const secp256k1_context *ctx, const secp256k1_pubkey *pubkey, const char *label) {
    unsigned char pubkey_bytes[33];
    size_t output_length = 33;
    secp256k1_ec_pubkey_serialize(ctx, pubkey_bytes, &output_length, pubkey, SECP256K1_EC_COMPRESSED);
    char pubkey_hex[67];
    bytes_to_hex(pubkey_bytes, 33, pubkey_hex);
    printf("%s (hex): %s\n", label, pubkey_hex);
}

int main() {
    const char *generator_hex = "02a4fd25e0e2108e55aec683810a8652f9b067242419a1f7cc0f01f92b4b078252";
    const char *scalar_hex = "8b5d87d94b9f54dc5dd9f31df5dffedc974fc4d5bf0d2ee1297e5aba504ccc26";
    unsigned char generator_bytes[33];
    unsigned char scalar_bytes[32];

    hex_to_bytes(generator_hex, generator_bytes, 33);
    hex_to_bytes(scalar_hex, scalar_bytes, 32);

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    // Parse the generator point as a public key
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, generator_bytes, 33)) {
        printf("Failed to parse generator as pubkey.\n");
        return 1;
    }

    // Multiply the public key by the scalar
    secp256k1_pubkey result_pubkey = pubkey;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, (unsigned char *)&result_pubkey, scalar_bytes)) {
        printf("Failed to multiply scalar by generator.\n");
        return 1;
    }

    // Print the resulting point
    print_point(ctx, &result_pubkey, "Resulting Point");

    secp256k1_context_destroy(ctx);
    return 0;
}
