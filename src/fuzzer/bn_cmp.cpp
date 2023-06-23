/*
* (C) 2021 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "fuzzers.h"

#include <botan/bigint.h>

void fuzz(const uint8_t in[], size_t len) {
   const size_t max_bits = 512;

   if(len < 3 || len > 1 + 2 * (max_bits / 8)) {
      return;
   }

   const uint8_t signs = in[0];
   const size_t x_len = (len - 1) / 2;

   Botan::BigInt x = Botan::BigInt::decode(in + 1, x_len);
   Botan::BigInt y = Botan::BigInt::decode(in + 1 + x_len, len - x_len - 1);

   if(signs & 1) {
      x.flip_sign();
   }
   if(signs & 2) {
      y.flip_sign();
   }

   const Botan::BigInt d1 = x - y;
   const Botan::BigInt d2 = y - x;

   FUZZER_ASSERT_TRUE(d1.cmp(d2, false) == 0);

   const bool is_eq = (x == y);
   const bool is_lt = (x < y);
   const bool is_gt = (x > y);
   const bool is_lte = (x <= y);
   const bool is_gte = (x >= y);

   if(is_eq) {
      FUZZER_ASSERT_TRUE(d1.is_zero());
      FUZZER_ASSERT_TRUE(d2.is_zero());
   }

   if(is_lte) {
      FUZZER_ASSERT_TRUE(is_lt || is_eq);
   }

   if(is_gte) {
      FUZZER_ASSERT_TRUE(is_gt || is_eq);
   }

   if(is_lt) {
      FUZZER_ASSERT_TRUE(!is_gt);
      FUZZER_ASSERT_TRUE(d1.is_nonzero());
      FUZZER_ASSERT_TRUE(d2.is_nonzero());
      FUZZER_ASSERT_TRUE(d1.is_negative());
      FUZZER_ASSERT_TRUE(d2.is_positive());
   }

   if(is_gt) {
      FUZZER_ASSERT_TRUE(!is_lt);
      FUZZER_ASSERT_TRUE(d1.is_nonzero());
      FUZZER_ASSERT_TRUE(d2.is_nonzero());
      FUZZER_ASSERT_TRUE(d1.is_positive());
      FUZZER_ASSERT_TRUE(d2.is_negative());
   }
}
