/*
* DTLS Hello Verify Request
* (C) 2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages_12.h>
#include <botan/internal/tls_messages_internal.h>
#include <botan/internal/tls_reader.h>

namespace Botan::TLS {

Hello_Verify_Request::Hello_Verify_Request(std::span<const uint8_t> client_hello_bits,
                                           std::string_view client_identity,
                                           std::span<const uint8_t> cookie_secret) {
   m_cookie = calculate_cookie(client_hello_bits, client_identity, cookie_secret);
}

std::vector<uint8_t> Hello_Verify_Request::serialize() const {
   /* DTLS 1.2 server implementations SHOULD use DTLS version 1.0
      regardless of the version of TLS that is expected to be
      negotiated (RFC 6347, section 4.2.1)
   */

   const Protocol_Version format_version(254, 255);  // DTLS 1.0

   std::vector<uint8_t> bits;
   bits.push_back(format_version.major_version());
   bits.push_back(format_version.minor_version());
   append_tls_length_value(bits, cookie(), 1);
   return bits;
}

}  // namespace Botan::TLS
