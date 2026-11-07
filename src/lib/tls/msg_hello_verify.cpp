/*
* DTLS Hello Verify Request
* (C) 2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages.h>

#include <botan/internal/tls_messages_internal.h>
#include <botan/internal/tls_reader.h>

namespace Botan::TLS {

Hello_Verify_Request_Shim::Hello_Verify_Request_Shim(std::span<const uint8_t> buf) {
   if(buf.size() < 3) {
      throw Decoding_Error("Hello verify request too small");
   }

   const Protocol_Version version(buf[0], buf[1]);

   if(!version.is_datagram_protocol()) {
      throw Decoding_Error("Unknown version from server in hello verify request");
   }

   if(static_cast<size_t>(buf[2]) + 3 != buf.size()) {
      throw Decoding_Error("Bad length in hello verify request");
   }

   m_cookie.assign(buf.begin() + 3, buf.end());
}

std::vector<uint8_t> Hello_Verify_Request_Shim::serialize() const {
   throw Not_Implemented("No support for TLS 1.2, cannot serialize Hello Verify Request");
}

}  // namespace Botan::TLS
