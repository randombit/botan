/*
* (C) 2019 Nuno Goncalves <nunojpg@gmail.com>
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "fuzzers.h"

#include <botan/internal/uri.h>

void fuzz(std::span<const uint8_t> input) {
   if(input.size() > max_fuzzer_input_size) {
      return;
   }

   try {
      Botan::URI::from_any(std::string(reinterpret_cast<const char*>(input.data()), input.size()));
   } catch(Botan::Exception& e) {}
}
