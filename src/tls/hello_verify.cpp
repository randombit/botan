/*
* DTLS Hello Verify Request
* (C) 2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/internal/tls_messages.h>
#include <botan/lookup.h>
#include <memory>

namespace Botan {

namespace TLS {

Hello_Verify_Request::Hello_Verify_Request(const std::vector<byte>& buf)
   {
   if(buf.size() < 3)
      throw Decoding_Error("Hello verify request too small");

   if(buf[0] != 254 || (buf[1] != 255 && buf[1] != 253))
      throw Decoding_Error("Unknown version from server in hello verify request");

   m_cookie.resize(buf.size() - 2);
   copy_mem(&m_cookie[0], &buf[2], buf.size() - 2);
   }

Hello_Verify_Request::Hello_Verify_Request(const std::vector<byte>& client_hello_bits,
                                           const std::string& client_identity,
                                           const SymmetricKey& secret_key)
   {
   std::unique_ptr<MessageAuthenticationCode> hmac(get_mac("HMAC(SHA-256)"));
   hmac->set_key(secret_key);

   hmac->update_be(client_hello_bits.size());
   hmac->update(client_hello_bits);
   hmac->update_be(client_identity.size());
   hmac->update(client_identity);

   m_cookie = unlock(hmac->final());
   }

std::vector<byte> Hello_Verify_Request::serialize() const
   {
   /* DTLS 1.2 server implementations SHOULD use DTLS version 1.0
      regardless of the version of TLS that is expected to be
      negotiated (RFC 6347, section 4.2.1)
   */

   Protocol_Version format_version(Protocol_Version::TLS_V11);

   std::vector<byte> bits;
   bits.push_back(format_version.major_version());
   bits.push_back(format_version.minor_version());
   bits += m_cookie;
   return bits;
   }

}

}
