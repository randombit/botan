/*
* (C) 2019 Nuno Goncalves <nunojpg@gmail.com>
*     2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "fuzzers.h"

#include <botan/uri.h>

void fuzz(std::span<const uint8_t> input) {
   if(input.size() > max_fuzzer_input_size) {
      return;
   }

   const std::string s(reinterpret_cast<const char*>(input.data()), input.size());
   const auto uri = Botan::URI::parse(s);
   const auto authority = Botan::URI::Authority::parse(s);
}
