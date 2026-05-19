/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "fuzzers.h"

#include <botan/ipv4_address.h>
#include <botan/internal/loadstor.h>

void fuzz(std::span<const uint8_t> in) {
   const std::string_view str(reinterpret_cast<const char*>(in.data()), in.size());
   if(auto ipv4 = Botan::IPv4Address::from_string(str)) {
      const auto rt = ipv4->to_string();
      FUZZER_ASSERT_EQUAL(str, rt);
   }

   if(in.size() == 4) {
      const uint32_t ip = Botan::load_be<uint32_t>(in.data(), 0);
      const auto s = Botan::IPv4Address(ip);
      const auto rt = Botan::IPv4Address::from_string(s.to_string());
      FUZZER_ASSERT_TRUE(rt.has_value());
      FUZZER_ASSERT_EQUAL(rt->address(), ip);
   }
}
