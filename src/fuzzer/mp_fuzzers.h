/*
* (C) 2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_FUZZER_MP_HELPERS_H_
#define BOTAN_FUZZER_MP_HELPERS_H_

#include "fuzzers.h"

#include <botan/internal/mp_core.h>
#include <string_view>

using Botan::word;

inline std::string format_word_vec(std::string_view name, const word x[], size_t x_len) {
   std::ostringstream oss;
   oss << name << " = ";

   constexpr size_t width = 2 * sizeof(word);

   for(size_t i = 0; i != x_len; ++i) {
      oss << std::uppercase << std::setw(width) << std::setfill('0') << std::hex << x[i] << " ";
   }

   oss << "\n";
   return oss.str();
}

inline void dump_word_vec(std::string_view name, const word x[], size_t x_len) {
   std::cerr << format_word_vec(name, x, x_len);
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

#endif
