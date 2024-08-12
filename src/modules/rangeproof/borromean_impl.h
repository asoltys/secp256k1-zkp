/**********************************************************************
 * Copyright (c) 2014, 2015 Gregory Maxwell                          *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/


#ifndef SECP256K1_BORROMEAN_IMPL_H
#define SECP256K1_BORROMEAN_IMPL_H

#include "../../scalar.h"
#include "../../field.h"
#include "../../group.h"
#include "../../hash.h"
#include "../../eckey.h"
#include "../../ecmult.h"
#include "../../ecmult_gen.h"
#include "borromean.h"

#include <limits.h>
#include <string.h>

SECP256K1_INLINE static void secp256k1_borromean_hash(unsigned char *hash, const unsigned char *m, size_t mlen, const unsigned char *e, size_t elen,
 size_t ridx, size_t eidx) {
    unsigned char ring[4];
    unsigned char epos[4];
    secp256k1_sha256 sha256_en;

    secp256k1_write_be32(ring, (uint32_t)ridx);
    secp256k1_write_be32(epos, (uint32_t)eidx);

    secp256k1_sha256_initialize(&sha256_en);
    secp256k1_sha256_write(&sha256_en, e, elen);
    secp256k1_sha256_write(&sha256_en, m, mlen);
    secp256k1_sha256_write(&sha256_en, ring, 4);
    secp256k1_sha256_write(&sha256_en, epos, 4);
    secp256k1_sha256_finalize(&sha256_en, hash);
}

/**  "Borromean" ring signature.
 *   Verifies nrings concurrent ring signatures all sharing a challenge value.
 *   Signature is one s value per pubkey and a hash.
 *   Verification equation:
 *   | m = H(P_{0..}||message) (Message must contain pubkeys or a pubkey commitment)
 *   | For each ring i:
 *   | | en = to_scalar(H(e0||m||i||0))
 *   | | For each pubkey j:
 *   | | | r = s_i_j G + en * P_i_j
 *   | | | e = H(r||m||i||j)
 *   | | | en = to_scalar(e)
 *   | | r_i = r
 *   | return e_0 ==== H(r_{0..i}||m)
 */
int secp256k1_borromean_verify(secp256k1_scalar *evalues, const unsigned char *e0,
 const secp256k1_scalar *s, const secp256k1_gej *pubs, const size_t *rsizes, size_t nrings, const unsigned char *m, size_t mlen) {
    secp256k1_gej rgej;
    secp256k1_ge rge;
    secp256k1_scalar ens;
    secp256k1_sha256 sha256_e0;
    unsigned char tmp[33];
    size_t i;
    size_t j;
    size_t count;
    size_t size;
    int overflow;
    VERIFY_CHECK(e0 != NULL);
    VERIFY_CHECK(s != NULL);
    VERIFY_CHECK(pubs != NULL);
    VERIFY_CHECK(rsizes != NULL);
    VERIFY_CHECK(nrings > 0);
    VERIFY_CHECK(m != NULL);
    count = 0;
    secp256k1_sha256_initialize(&sha256_e0);
    for (i = 0; i < nrings; i++) {
        VERIFY_CHECK(INT_MAX - count > rsizes[i]);
        secp256k1_borromean_hash(tmp, m, mlen, e0, 32, i, 0);
        secp256k1_scalar_set_b32(&ens, tmp, &overflow);
        for (j = 0; j < rsizes[i]; j++) {
            if (overflow || secp256k1_scalar_is_zero(&s[count]) || secp256k1_scalar_is_zero(&ens) || secp256k1_gej_is_infinity(&pubs[count])) {
                return 0;
            }
            if (evalues) {
                /*If requested, save the challenges for proof rewind.*/
                evalues[count] = ens;
            }
            secp256k1_ecmult(&rgej, &pubs[count], &ens, &s[count]);
            if (secp256k1_gej_is_infinity(&rgej)) {
                return 0;
            }
            /* OPT: loop can be hoisted and split to use batch inversion across all the rings; this would make it much faster. */
            secp256k1_ge_set_gej_var(&rge, &rgej);
            secp256k1_eckey_pubkey_serialize(&rge, tmp, &size, 1);
            if (j != rsizes[i] - 1) {
                secp256k1_borromean_hash(tmp, m, mlen, tmp, 33, i, j + 1);
                secp256k1_scalar_set_b32(&ens, tmp, &overflow);
            } else {
                secp256k1_sha256_write(&sha256_e0, tmp, size);
            }
            count++;
        }
    }
    secp256k1_sha256_write(&sha256_e0, m, mlen);
    secp256k1_sha256_finalize(&sha256_e0, tmp);
    return secp256k1_memcmp_var(e0, tmp, 32) == 0;
}

void bytes_to_hex(const unsigned char *bytes, size_t bytes_len, char *hex) {
    size_t i;
    for (i = 0; i < bytes_len; i++) {
        sprintf(&hex[i * 2], "%02x", bytes[i]);
    }
}

void print_scalarb(const unsigned char *scalar, const char *label) {
    char scalar_hex[65];
    bytes_to_hex(scalar, 32, scalar_hex);
    printf("%s: %s\n", label, scalar_hex);
}

void print_scalar(const char* label, const secp256k1_scalar *scalar) {
    int i;
    unsigned char buf[32];
    secp256k1_scalar_get_b32(buf, scalar);
    printf("%s: ", label);
    for (i = 0; i < 32; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

void print_gej(const char* label, const secp256k1_gej *gej) {
    secp256k1_ge ge;
    unsigned char buf[65];
    size_t size;
    size_t i;

    secp256k1_ge_set_gej(&ge, gej);

    size = 33;
    if (secp256k1_eckey_pubkey_serialize(&ge, buf, &size, 1)) {
        printf("%s: ", label);
        for (i = 0; i < size; i++) {
            printf("%02x", buf[i]);
        }
        printf("\n");
    } else {
        printf("%s: failed to serialize\n", label);
    }
}

void print_array(const char* label, const unsigned char *arr, size_t len) {
  size_t i;
    printf("%s: ", label);
    for (i = 0; i < len; i++) {
        printf("%02x", arr[i]);
    }
    printf("\n");
}

void print_size_t_array(const char* label, const size_t *arr, size_t len) {
  size_t i;
    printf("%s: ", label);
    for (i = 0; i < len; i++) {
        printf("%zu ", arr[i]);
    }
    printf("\n");
}

int secp256k1_borromean_sign(const secp256k1_ecmult_gen_context *ecmult_gen_ctx,
 unsigned char *e0, secp256k1_scalar *s, const secp256k1_gej *pubs, const secp256k1_scalar *k, const secp256k1_scalar *sec,
 const size_t *rsizes, const size_t *secidx, size_t nrings, const unsigned char *m, size_t mlen) {

    secp256k1_gej rgej;
    secp256k1_ge rge;
    secp256k1_scalar ens;
    secp256k1_sha256 sha256_e0;
    unsigned char tmp[33];
    size_t i;
    size_t j;
    size_t count;
    size_t size;
    int overflow;
    VERIFY_CHECK(ecmult_gen_ctx != NULL);
    VERIFY_CHECK(e0 != NULL);
    VERIFY_CHECK(s != NULL);
    VERIFY_CHECK(pubs != NULL);
    VERIFY_CHECK(k != NULL);
    VERIFY_CHECK(sec != NULL);
    VERIFY_CHECK(rsizes != NULL);
    VERIFY_CHECK(secidx != NULL);
    VERIFY_CHECK(nrings > 0);
    VERIFY_CHECK(m != NULL);
    secp256k1_sha256_initialize(&sha256_e0);
    count = 0;

    /*
    printf("e0 initial: ");
    for (i = 0; i < 32; i++) {
        printf("%02x", e0[i]);
    }
    printf("\n");

    printf("Parameters:\n");
    for (i = 0; i < 72; i++) {
        print_scalar("s", &s[i]);
    }
    print_size_t_array("rsizes", rsizes, nrings);
    print_size_t_array("secidx", secidx, nrings);
    printf("nrings: %zu\n", nrings);
    print_array("m", m, mlen);
    printf("mlen: %zu\n", mlen);
    */

    for (i = 0; i < nrings; i++) {
        VERIFY_CHECK(INT_MAX - count > rsizes[i]);
        secp256k1_ecmult_gen(ecmult_gen_ctx, &rgej, &k[i]);
        secp256k1_ge_set_gej(&rge, &rgej);
        if (secp256k1_gej_is_infinity(&rgej)) {
            return 0;
        }
        secp256k1_eckey_pubkey_serialize(&rge, tmp, &size, 1);
        for (j = secidx[i] + 1; j < rsizes[i]; j++) {
            secp256k1_borromean_hash(tmp, m, mlen, tmp, 33, i, j);
            secp256k1_scalar_set_b32(&ens, tmp, &overflow);
            if (overflow || secp256k1_scalar_is_zero(&ens)) {
                return 0;
            }
            /** The signing algorithm as a whole is not memory uniform so there is likely a cache sidechannel that
             *  leaks which members are non-forgeries. That the forgeries themselves are variable time may leave
             *  an additional privacy impacting timing side-channel, but not a key loss one.
             */
            secp256k1_ecmult(&rgej, &pubs[count + j], &ens, &s[count + j]);
            if (secp256k1_gej_is_infinity(&rgej)) {
                return 0;
            }
            secp256k1_ge_set_gej(&rge, &rgej);
            secp256k1_eckey_pubkey_serialize(&rge, tmp, &size, 1);
        }
        secp256k1_sha256_write(&sha256_e0, tmp, size);
        count += rsizes[i];
    }

    secp256k1_sha256_write(&sha256_e0, m, mlen);
    secp256k1_sha256_finalize(&sha256_e0, e0);

    count = 0;
    for (i = 0; i < nrings; i++) {
        VERIFY_CHECK(INT_MAX - count > rsizes[i]);
        print_array("e0", e0, 32);
        print_array("m", m, mlen);
        printf("SKOO\n");
        secp256k1_borromean_hash(tmp, m, mlen, e0, 32, i, 0);
        print_array("tmp", tmp, 32);
        secp256k1_scalar_set_b32(&ens, tmp, &overflow);
        print_array("ens", &ens, 32);
        if (overflow || secp256k1_scalar_is_zero(&ens)) {
            return 0;
        }
        for (j = 0; j < secidx[i]; j++) {
            print_gej("pub", &pubs[count+j]);
            print_array("ens", &ens, 32);
            print_array("s", &s[count+j], 32);
            secp256k1_ecmult(&rgej, &pubs[count + j], &ens, &s[count + j]);
            if (secp256k1_gej_is_infinity(&rgej)) {
                return 0;
            }
            secp256k1_ge_set_gej(&rge, &rgej);
            secp256k1_eckey_pubkey_serialize(&rge, tmp, &size, 1);
            print_array("rgej", tmp, 33);
            printf("WOWIE\n");
            secp256k1_borromean_hash(tmp, m, mlen, tmp, 33, i, j + 1);
            print_array("tmp", tmp, 32);
            secp256k1_scalar_set_b32(&ens, tmp, &overflow);
            print_array("ensB", &ens, 32);
            if (overflow || secp256k1_scalar_is_zero(&ens)) {
                return 0;
            }
        }

        print_array("ens", &ens, 32);
        print_array("sec", &sec[i], 32);
        print_array("k", &k[i], 32);
        secp256k1_scalar_mul(&s[count + j], &ens, &sec[i]);
        print_array("mul", &s[count + j], 32);
        secp256k1_scalar_negate(&s[count + j], &s[count + j]);
        print_array("neg", &s[count + j], 32);
        secp256k1_scalar_add(&s[count + j], &s[count + j], &k[i]);
        print_array("add", &s[count + j], 32);

        printf("===== setting %zu ====", count+j);
        print_array("", &s[count+j], 32);
        if (secp256k1_scalar_is_zero(&s[count + j])) {
            return 0;
        }
        count += rsizes[i];
    }


    /*
    printf("Final s values:\n");
    for (i = 0; i < count; i++) {
        print_scalar("s", &s[i]);
    }
    */

    secp256k1_scalar_clear(&ens);
    secp256k1_ge_clear(&rge);
    secp256k1_gej_clear(&rgej);
    memset(tmp, 0, 33);
    return 1;
}

#endif
