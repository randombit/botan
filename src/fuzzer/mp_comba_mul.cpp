/*
* (C) 2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "mp_fuzzers.h"

void fuzz(const uint8_t in[], size_t in_len) {
   const size_t words = (in_len + sizeof(word) - 1) / sizeof(word);

   if(in_len == 0 || words > 2 * 16) {
      return;
   }

   word x[24] = {0};
   word y[24] = {0};

   std::memcpy(x, in, in_len / 2);
   std::memcpy(y, in + in_len / 2, in_len - (in_len / 2));

   const size_t x_words = ((in_len / 2) + sizeof(word) - 1) / sizeof(word);
   const size_t y_words = ((in_len - (in_len / 2)) + sizeof(word) - 1) / sizeof(word);

   word z4[2 * 4] = {0};
   word z6[2 * 6] = {0};
   word z8[2 * 8] = {0};
   word z9[2 * 9] = {0};
   word z16[2 * 16] = {0};
   word z24[2 * 24] = {0};

   word z_ref[2 * 24] = {0};

   Botan::basecase_mul(z_ref, 2 * 24, x, x_words, y, y_words);

   if(words <= 8) {
      Botan::bigint_comba_mul4(z4, x, y);
   }
   if(words <= 12) {
      Botan::bigint_comba_mul6(z6, x, y);
   }
   if(words <= 16) {
      Botan::bigint_comba_mul8(z8, x, y);
   }
   if(words <= 18) {
      Botan::bigint_comba_mul9(z9, x, y);
   }
   if(words <= 32) {
      Botan::bigint_comba_mul16(z16, x, y);
   }
   if(words <= 48) {
      Botan::bigint_comba_mul24(z24, x, y);
   }

   if(words <= 8) {
      compare_word_vec(z4, 2 * 4, z6, 2 * 6, "mul4 vs mul6");
   }
   if(words <= 12) {
      compare_word_vec(z6, 2 * 6, z8, 2 * 8, "mul6 vs mul8");
   }
   if(words <= 16) {
      compare_word_vec(z8, 2 * 8, z9, 2 * 9, "mul8 vs mul9");
   }
   if(words <= 18) {
      compare_word_vec(z9, 2 * 9, z16, 2 * 16, "mul9 vs mul16");
   }
   if(words <= 32) {
      compare_word_vec(z16, 2 * 16, z24, 2 * 24, "mul16 vs mul24");
   }

   compare_word_vec(z24, 2 * 24, z_ref, 2 * 24, "mul24 vs basecase mul");
}
