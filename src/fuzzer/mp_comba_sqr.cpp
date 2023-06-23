/*
* (C) 2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "mp_fuzzers.h"

void fuzz(const uint8_t in[], size_t in_len) {
   const size_t words = (in_len + sizeof(word) - 1) / sizeof(word);

   if(in_len == 0 || words > 24) {
      return;
   }

   word x[24] = {0};

   std::memcpy(x, in, in_len);

   word z4[2 * 4] = {0};
   word z6[2 * 6] = {0};
   word z8[2 * 8] = {0};
   word z9[2 * 9] = {0};
   word z16[2 * 16] = {0};
   word z24[2 * 24] = {0};

   word z_ref[2 * 24] = {0};

   //dump_word_vec("x", x, words);

   Botan::basecase_sqr(z_ref, 2 * 24, x, words);

   if(words <= 4) {
      Botan::bigint_comba_sqr4(z4, x);
      word z4m[2 * 4] = {0};
      Botan::bigint_comba_mul4(z4m, x, x);
      compare_word_vec(z4m, 2 * 4, z4, 2 * 4, "sqr4 vs mul4");
   }
   if(words <= 6) {
      Botan::bigint_comba_sqr6(z6, x);
      word z6m[2 * 6] = {0};
      Botan::bigint_comba_mul6(z6m, x, x);
      compare_word_vec(z6m, 2 * 6, z6, 2 * 6, "sqr6 vs mul6");
   }
   if(words <= 8) {
      Botan::bigint_comba_sqr8(z8, x);
      word z8m[2 * 8] = {0};
      Botan::bigint_comba_mul8(z8m, x, x);
      compare_word_vec(z8m, 2 * 8, z8, 2 * 8, "sqr8 vs mul8");
   }
   if(words <= 9) {
      Botan::bigint_comba_sqr9(z9, x);
      word z9m[2 * 9] = {0};
      Botan::bigint_comba_mul9(z9m, x, x);
      compare_word_vec(z9m, 2 * 9, z9, 2 * 9, "sqr9 vs mul9");
   }
   if(words <= 16) {
      Botan::bigint_comba_sqr16(z16, x);
      word z16m[2 * 16] = {0};
      Botan::bigint_comba_mul16(z16m, x, x);
      compare_word_vec(z16m, 2 * 16, z16, 2 * 16, "sqr16 vs mul16");
   }
   if(words <= 24) {
      Botan::bigint_comba_sqr24(z24, x);
      word z24m[2 * 24] = {0};
      Botan::bigint_comba_mul24(z24m, x, x);
      compare_word_vec(z24m, 2 * 24, z24, 2 * 24, "sqr24 vs mul24");
   }

   if(words <= 4) {
      compare_word_vec(z4, 2 * 4, z6, 2 * 6, "sqr4 vs sqr6");
   }
   if(words <= 6) {
      compare_word_vec(z6, 2 * 6, z8, 2 * 8, "sqr6 vs sqr8");
   }
   if(words <= 8) {
      compare_word_vec(z8, 2 * 8, z9, 2 * 9, "sqr8 vs sqr9");
   }
   if(words <= 9) {
      compare_word_vec(z9, 2 * 9, z16, 2 * 16, "sqr9 vs sqr16");
   }
   if(words <= 16) {
      compare_word_vec(z16, 2 * 16, z24, 2 * 24, "sqr16 vs sqr24");
   }

   compare_word_vec(z24, 2 * 24, z_ref, 2 * 24, "sqr24 vs basecase sqr");
}
