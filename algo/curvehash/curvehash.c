/*
 * Copyright 2011 ArtForz
 * Copyright 2011-2013 pooler
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "miner.h"

#include <string.h>
#include <inttypes.h>
#include <secp256k1.h>
#include <openssl/sha.h>

static void sha256_hash(unsigned char *hash, const unsigned char *data, int len) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, len);
    SHA256_Final(hash, &ctx);
}

int scanhash_curvehash(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_pubkey pubkey;
    unsigned char pub[65];
    size_t publen = 65;

    uint32_t _ALIGN(128) hash[8];
    uint32_t _ALIGN(128) hash_le[8];
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    uint32_t _ALIGN(128) pdata_be[20];
    for (int i = 0; i < 20; i++) {
        be32enc(pdata_be + i, pdata[i]);
    }
    uint32_t first_nonce = pdata[19];
    uint32_t nonce = first_nonce;
    const uint32_t Htarg = ptarget[7];
    do {
        pdata[19] = nonce;
        pdata_be[19] = swab32(pdata[19]);
        sha256_hash((unsigned char *) hash, (unsigned char *) pdata_be, 80);
        for (int round = 0; round < 8; round++) {
            secp256k1_ec_pubkey_create(ctx, &pubkey, (unsigned char *) hash);
            secp256k1_ec_pubkey_serialize(ctx, pub, &publen, &pubkey, SECP256K1_EC_UNCOMPRESSED);
            sha256_hash((unsigned char *) hash, pub, 65);
        }
        if (hash[7] <= Htarg) {
            if (fulltest(hash, ptarget)) {
                work_set_target_ratio(work, hash);
                pdata[19] = nonce;
                *hashes_done = pdata[19] - first_nonce;
                return 1;
            }
        }
        nonce++;
    } while (nonce < max_nonce && !work_restart[thr_id].restart);
    *hashes_done = pdata[19] - first_nonce;
    return 0;
}
