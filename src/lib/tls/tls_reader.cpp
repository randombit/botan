/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_reader.h>

#include <botan/exceptn.h>
#include <botan/internal/fmt.h>

namespace Botan::TLS {

void TLS_Data_Reader::assert_at_least(size_t n) const {
   const size_t left = remaining_bytes();
   if(left < n) {
      throw_decode_error(fmt("Expected {} bytes remaining, only {} left", n, left));
   }
}

void TLS_Data_Reader::throw_decode_error(std::string_view why) const {
   throw Decoding_Error(fmt("Invalid {}: {}", m_typename, why));
}

}  // namespace Botan::TLS
