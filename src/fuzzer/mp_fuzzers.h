/*
* (C) 2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_FUZZER_MP_HELPERS_H_
#define BOTAN_FUZZER_MP_HELPERS_H_

#include "fuzzers.h"

#include <botan/internal/mp_core.h>

#if BOTAN_MP_WORD_BITS == 64
   #define WORD_FORMAT_STRING "%016lX"
#else
   #define WORD_FORMAT_STRING "%08X"
#endif

using Botan::word;

namespace {

inline void dump_word_vec(const char* name, const word x[], size_t x_len) {
   fprintf(stderr, "%s = ", name);
   for(size_t i = 0; i != x_len; ++i) {
      fprintf(stderr, WORD_FORMAT_STRING, x[i]);
      fprintf(stderr, " ");
   }
   fprintf(stderr, "\n");
}

inline void compare_word_vec(const word x[], size_t x_len, const word y[], size_t y_len, const char* comparing) {
   const size_t common_words = std::min(x_len, y_len);

   for(size_t i = 0; i != common_words; ++i) {
      if(x[i] != y[i]) {
         dump_word_vec("x", x, x_len);
         dump_word_vec("y", y, y_len);
         FUZZER_WRITE_AND_CRASH("Comparison failed " << comparing);
      }
   }

   // all other words must be zero
   for(size_t i = common_words; i != x_len; ++i) {
      if(x[i] != 0) {
         dump_word_vec("x", x, x_len);
         dump_word_vec("y", y, y_len);
         FUZZER_WRITE_AND_CRASH("Unexpected non-zero in high words of x " << comparing);
      }
   }
   for(size_t i = common_words; i != y_len; ++i) {
      if(y[i] != 0) {
         dump_word_vec("x", x, x_len);
         dump_word_vec("y", y, y_len);
         FUZZER_WRITE_AND_CRASH("Unexpected non-zero in high words of y " << comparing);
      }
   }
}

}  // namespace

#endif
