/*
 * Smoke test of the C ABI from plain C.
 *
 * The crate has no hash implementation of its own; the caller supplies
 * SHA3-256, SHA3-512, SHAKE256 and secure memory through hqc_callbacks_t.
 * Plain C has no SHA3 at hand, so this program only exercises the structural
 * checks of the ABI: sizes, parameter-set validation, callback validation and
 * null pointers.
 * The full round trip through real callbacks is exercised by `cargo test`
 * (with sha3-crate callbacks) and by Botan's test suite (with Botan's hashes).
 *
 *   gcc -O2 -Iinclude botan_abi_smoketest.c -o smoketest \
 *       -L target/release -lrust_hqc -lpthread -ldl -lm
 */
#include "hqc_c_api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int32_t fail_sha3(void* ctx, const hqc_buffer_t* parts, size_t n, uint8_t* out) {
   (void)ctx; (void)parts; (void)n; (void)out;
   return -1;
}
static int32_t fail_init(void* ctx, const hqc_buffer_t* parts, size_t n, hqc_xof_t** out) {
   (void)ctx; (void)parts; (void)n; (void)out;
   return -1;
}
static int32_t fail_squeeze(void* ctx, hqc_xof_t* xof, uint8_t* out, size_t len) {
   (void)ctx; (void)xof; (void)out; (void)len;
   return -1;
}
static void noop_free(void* ctx, hqc_xof_t* xof) { (void)ctx; (void)xof; }
static void* stub_alloc(void* ctx, size_t len) { (void)ctx; return calloc(len, 1); }
static void stub_free(void* ctx, void* ptr, size_t len) { (void)ctx; memset(ptr, 0, len); free(ptr); }

int main(void) {
   for(uint8_t ps = 1; ps <= 5; ps += 2) {
      size_t ekl, dkl, ctl, ssl, kprl, encrl;
      if(hqc_sizes(ps, &ekl, &dkl, &ctl, &ssl)) { printf("sizes failed\n"); return 1; }
      if(hqc_randomness_lengths(ps, &kprl, &encrl)) { printf("randomness lengths failed\n"); return 1; }
      printf("HQC-%u  ek=%zu dk=%zu ct=%zu ss=%zu  randomness: keypair=%zu encaps=%zu\n",
             ps, ekl, dkl, ctl, ssl, kprl, encrl);
   }

   hqc_callbacks_t cb;
   memset(&cb, 0, sizeof cb);
   cb.version = HQC_CALLBACKS_VERSION;
   cb.hash.sha3_256 = fail_sha3;
   cb.hash.sha3_512 = fail_sha3;
   cb.hash.shake256_init = fail_init;
   cb.hash.shake256_squeeze = fail_squeeze;
   cb.hash.shake256_free = noop_free;
   cb.alloc.secure_alloc = stub_alloc;
   cb.alloc.secure_free = stub_free;

   uint8_t ek[2241], dk[32], seed[32] = {0};
   printf("error paths:\n");
   printf("  bad param set      -> %d (expect %d)\n", hqc_sizes(2, NULL, NULL, NULL, NULL), HQC_ERR_BAD_PARAMETER_SET);
   printf("  null callbacks     -> %d (expect %d)\n",
          hqc_keypair(1, NULL, ek, sizeof ek, dk, sizeof dk, seed, sizeof seed), HQC_ERR_BAD_CALLBACKS);
   cb.version = 99;
   printf("  wrong version      -> %d (expect %d)\n",
          hqc_keypair(1, &cb, ek, sizeof ek, dk, sizeof dk, seed, sizeof seed), HQC_ERR_BAD_CALLBACKS);
   cb.version = HQC_CALLBACKS_VERSION;
   printf("  null ek            -> %d (expect %d)\n",
          hqc_keypair(1, &cb, NULL, 0, dk, sizeof dk, seed, sizeof seed), HQC_ERR_NULL_POINTER);
   printf("  failing callback   -> %d (expect %d)\n",
          hqc_keypair(1, &cb, ek, sizeof ek, dk, sizeof dk, seed, sizeof seed), HQC_ERR_HASH_CALLBACK);
   printf("  48-byte seed       -> %d (expect %d)\n",
          hqc_keypair(1, &cb, ek, sizeof ek, dk, sizeof dk, seed, 48), HQC_ERR_BUFFER_LENGTH);
   printf("  short dk           -> %d (expect %d)\n",
          hqc_public_key(1, &cb, ek, sizeof ek, dk, 31), HQC_ERR_INVALID_KEY);
   cb.alloc.secure_free = NULL;
   printf("  null alloc member  -> %d (expect %d)\n",
          hqc_keypair(1, &cb, ek, sizeof ek, dk, sizeof dk, seed, sizeof seed), HQC_ERR_BAD_CALLBACKS);
   return 0;
}
