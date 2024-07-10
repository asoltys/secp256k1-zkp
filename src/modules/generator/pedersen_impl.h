/***********************************************************************
 * Copyright (c) 2015 Gregory Maxwell                                  *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. *
 ***********************************************************************/

#ifndef SECP256K1_PEDERSEN_IMPL_H
#define SECP256K1_PEDERSEN_IMPL_H

#include <string.h>

#include "../../eckey.h"
#include "../../ecmult_const.h"
#include "../../ecmult_gen.h"
#include "../../group.h"
#include "../../field.h"
#include "../../scalar.h"
#include "../../util.h"

static void secp256k1_pedersen_scalar_set_u64(secp256k1_scalar *sec, uint64_t value) {
    unsigned char data[32];
    int i;
    for (i = 0; i < 24; i++) {
        data[i] = 0;
    }
    for (; i < 32; i++) {
        data[i] = value >> 56;
        value <<= 8;
    }
    secp256k1_scalar_set_b32(sec, data, NULL);
    memset(data, 0, 32);
}

static void secp256k1_pedersen_ecmult_small(secp256k1_gej *r, uint64_t gn, const secp256k1_ge* genp) {
    secp256k1_scalar s;
    secp256k1_pedersen_scalar_set_u64(&s, gn);
    secp256k1_ecmult_const(r, genp, &s);
    secp256k1_scalar_clear(&s);
}


static void print_secp256k1_scalar(const secp256k1_scalar* scalar) {
    int i;
    unsigned char data[32];
    secp256k1_scalar_get_b32(data, scalar);
    for (i = 0; i < 32; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static void print_secp256k1_fe(const secp256k1_fe* fe) {
    int i;
    unsigned char data[32];
    secp256k1_fe normalized_fe = *fe;
    secp256k1_fe_normalize_var(&normalized_fe);
    secp256k1_fe_get_b32(data, &normalized_fe);
    for (i = 0; i < 32; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static void print_secp256k1_ge(const secp256k1_ge* ge) {
    printf("x = "); print_secp256k1_fe(&ge->x);
    printf("y = "); print_secp256k1_fe(&ge->y);
}

/* sec * G + value * G2. */
SECP256K1_INLINE static void secp256k1_pedersen_ecmult(const secp256k1_ecmult_gen_context *ecmult_gen_ctx, secp256k1_gej *rj, const secp256k1_scalar *sec, uint64_t value, const secp256k1_ge* genp) {
    secp256k1_gej vj;
    secp256k1_ecmult_gen(ecmult_gen_ctx, rj, sec);
    secp256k1_ge base_ge;
    secp256k1_gej base_gej;

    base_gej = ecmult_gen_ctx->initial;
    secp256k1_ge_set_gej(&base_ge, &base_gej);

    printf("Base Point (G):\n");
    if (secp256k1_fe_is_odd(&base_ge.y)) {
        secp256k1_fe_negate(&base_ge.y, &base_ge.y, 1);
    }
    print_secp256k1_ge(&base_ge);

    printf("sec blinding factor:\n");
    print_secp256k1_scalar(sec);

    printf("rj after ecmult_gen:\n");
    printf("rj.x = "); print_secp256k1_fe(&rj->x);
    printf("rj.y = "); print_secp256k1_fe(&rj->y);
    printf("rj.z = "); print_secp256k1_fe(&rj->z);

    secp256k1_pedersen_ecmult_small(&vj, value, genp);

    printf("vj after pedersen_ecmult_small:\n");
    printf("vj.x = "); print_secp256k1_fe(&vj.x);
    printf("vj.y = "); print_secp256k1_fe(&vj.y);
    printf("vj.z = "); print_secp256k1_fe(&vj.z);

    /* FIXME: constant time. */
    secp256k1_gej_add_var(rj, rj, &vj, NULL);

    printf("rj after gej_add_var:\n");
    printf("rj.x = "); print_secp256k1_fe(&rj->x);
    printf("rj.y = "); print_secp256k1_fe(&rj->y);
    printf("rj.z = "); print_secp256k1_fe(&rj->z);

    secp256k1_gej_clear(&vj);
}

#endif
