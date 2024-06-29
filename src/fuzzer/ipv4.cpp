/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "fuzzers.h"

#include <botan/internal/loadstor.h>
#include <botan/internal/parsing.h>

void fuzz(std::span<const uint8_t> in) {
   std::string_view str(reinterpret_cast<const char*>(in.data()), in.size());
   if(auto ipv4 = Botan::string_to_ipv4(str)) {
      const auto rt = Botan::ipv4_to_string(*ipv4);
      FUZZER_ASSERT_EQUAL(str, rt);
   }

   if(in.size() == 4) {
      uint32_t ip = Botan::load_be<uint32_t>(in.data(), 0);
      auto s = Botan::ipv4_to_string(ip);
      auto rt = Botan::string_to_ipv4(s);
      FUZZER_ASSERT_TRUE(rt.has_value());
      FUZZER_ASSERT_EQUAL(rt.value(), ip);
   }
}
