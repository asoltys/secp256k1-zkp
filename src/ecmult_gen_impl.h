/***********************************************************************
 * Copyright (c) 2013, 2014, 2015 Pieter Wuille, Gregory Maxwell       *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_ECMULT_GEN_IMPL_H
#define SECP256K1_ECMULT_GEN_IMPL_H

#include "util.h"
#include "scalar.h"
#include "group.h"
#include "ecmult_gen.h"
#include "hash_impl.h"
#include "precomputed_ecmult_gen.h"

static void secp256k1_ecmult_gen_context_build(secp256k1_ecmult_gen_context *ctx) {
    secp256k1_ecmult_gen_blind(ctx, NULL);
    ctx->built = 1;
}

static int secp256k1_ecmult_gen_context_is_built(const secp256k1_ecmult_gen_context* ctx) {
    return ctx->built;
}


static void secp256k1_ecmult_gen_context_clear(secp256k1_ecmult_gen_context *ctx) {
    ctx->built = 0;
    secp256k1_scalar_clear(&ctx->blind);
    secp256k1_gej_clear(&ctx->initial);
}

/* Utility functions for converting to hex strings */
static void secp256k1_fe_to_hex(const secp256k1_fe *fe, char *buf) {

    unsigned char bin[32];
    int i;
    secp256k1_fe_get_b32(bin, fe);
    for (i = 0; i < 32; i++) {
        snprintf(buf + (i * 2), 3, "%02x", bin[i]);
    }
    buf[64] = '\0';
}

static const char* secp256k1_scalar_to_string(const secp256k1_scalar *s) {
    static char buf[65];
    unsigned char bin[32];
    int i;
    secp256k1_scalar_get_b32(bin, s);
    for (i = 0; i < 32; i++) {
        snprintf(buf + (i * 2), 3, "%02x", bin[i]);
    }
    buf[64] = '\0';
    return buf;
}

static const char* secp256k1_gej_to_string(const secp256k1_gej *r) {
    static char buf[390];
    char x_buf[65], y_buf[65], z_buf[65];
    secp256k1_fe_to_hex(&r->x, x_buf);
    secp256k1_fe_to_hex(&r->y, y_buf);
    secp256k1_fe_to_hex(&r->z, z_buf);
    snprintf(buf, sizeof(buf), "\n x: %s\n y: %s\n z: %s\n", x_buf, y_buf, z_buf);
    return buf;
}

static void secp256k1_ecmult_gen(const secp256k1_ecmult_gen_context *ctx, secp256k1_gej *r, const secp256k1_scalar *gn) {
    int bits = ECMULT_GEN_PREC_BITS;
    int g = ECMULT_GEN_PREC_G(bits);
    int n = ECMULT_GEN_PREC_N(bits);

    secp256k1_ge add;
    secp256k1_ge_storage adds;
    secp256k1_scalar gnb;
    int i, j, n_i;
    memset(&adds, 0, sizeof(adds));
    *r = ctx->initial;

    /* Blind scalar/point multiplication by computing (n-b)G + bG instead of nG. */
    secp256k1_scalar_add(&gnb, gn, &ctx->blind);
    
    add.infinity = 0;
    for (i = 0; i < n; i++) {
        n_i = secp256k1_scalar_get_bits(&gnb, i * bits, bits);
        for (j = 0; j < g; j++) {
            secp256k1_ge_storage_cmov(&adds, &secp256k1_ecmult_gen_prec_table[i][j], j == n_i);
        }
        secp256k1_ge_from_storage(&add, &adds);
        secp256k1_gej_add_ge(r, r, &add);
    }
    n_i = 0;

    secp256k1_ge_clear(&add);
    secp256k1_scalar_clear(&gnb);
}

/* Setup blinding values for secp256k1_ecmult_gen. */
static void secp256k1_ecmult_gen_blind(secp256k1_ecmult_gen_context *ctx, const unsigned char *seed32) {
    secp256k1_scalar b;
    secp256k1_gej gb;
    secp256k1_fe s;
    unsigned char nonce32[32];
    secp256k1_rfc6979_hmac_sha256 rng;
    unsigned char keydata[64];
    if (seed32 == NULL) {
        /* When seed is NULL, reset the initial point and blinding value. */
        secp256k1_gej_set_ge(&ctx->initial, &secp256k1_ge_const_g);
        secp256k1_gej_neg(&ctx->initial, &ctx->initial);
        secp256k1_scalar_set_int(&ctx->blind, 1);
        return;
    }
    /* The prior blinding value (if not reset) is chained forward by including it in the hash. */
    secp256k1_scalar_get_b32(keydata, &ctx->blind);
    /** Using a CSPRNG allows a failure free interface, avoids needing large amounts of random data,
     *   and guards against weak or adversarial seeds.  This is a simpler and safer interface than
     *   asking the caller for blinding values directly and expecting them to retry on failure.
     */
    VERIFY_CHECK(seed32 != NULL);
    memcpy(keydata + 32, seed32, 32);
    secp256k1_rfc6979_hmac_sha256_initialize(&rng, keydata, 64);
    memset(keydata, 0, sizeof(keydata));
    secp256k1_rfc6979_hmac_sha256_generate(&rng, nonce32, 32);
    secp256k1_fe_set_b32_mod(&s, nonce32);
    secp256k1_fe_cmov(&s, &secp256k1_fe_one, secp256k1_fe_normalizes_to_zero(&s));
    /* Randomize the projection to defend against multiplier sidechannels.
       Do this before our own call to secp256k1_ecmult_gen below. */
    secp256k1_gej_rescale(&ctx->initial, &s);
    secp256k1_fe_clear(&s);
    secp256k1_rfc6979_hmac_sha256_generate(&rng, nonce32, 32);
    secp256k1_scalar_set_b32(&b, nonce32, NULL);
    /* A blinding value of 0 works, but would undermine the projection hardening. */
    secp256k1_scalar_cmov(&b, &secp256k1_scalar_one, secp256k1_scalar_is_zero(&b));
    secp256k1_rfc6979_hmac_sha256_finalize(&rng);
    memset(nonce32, 0, 32);
    /* The random projection in ctx->initial ensures that gb will have a random projection. */
    secp256k1_ecmult_gen(ctx, &gb, &b);
    secp256k1_scalar_negate(&b, &b);
    ctx->blind = b;
    ctx->initial = gb;
    secp256k1_scalar_clear(&b);
    secp256k1_gej_clear(&gb);
}

#endif /* SECP256K1_ECMULT_GEN_IMPL_H */
