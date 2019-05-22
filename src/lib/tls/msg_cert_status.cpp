/*
* Certificate Status
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages.h>
#include <botan/tls_extensions.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_handshake_hash.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>

namespace Botan {

namespace TLS {

Certificate_Status::Certificate_Status(const std::vector<uint8_t>& buf)
   {
   if(buf.size() < 5)
      throw Decoding_Error("Invalid Certificate_Status message: too small");

   if(buf[0] != 1) // not OCSP
      throw Decoding_Error("Unexpected Certificate_Status message: unexpected response type");

   size_t len = make_uint32(0, buf[1], buf[2], buf[3]);

   // Verify the redundant length field...
   if(buf.size() != len + 4)
      throw Decoding_Error("Invalid Certificate_Status: invalid length field");

   m_response.assign(buf.begin() + 4, buf.end());
   }

Certificate_Status::Certificate_Status(Handshake_IO& io,
                                       Handshake_Hash& hash,
                                       std::shared_ptr<const OCSP::Response> ocsp) :
   m_response(ocsp->raw_bits())
   {
   hash.update(io.send(*this));
   }

Certificate_Status::Certificate_Status(Handshake_IO& io,
                                       Handshake_Hash& hash,
                                       const std::vector<uint8_t>& raw_response_bytes) :
   m_response(raw_response_bytes)
   {
   hash.update(io.send(*this));
   }

std::vector<uint8_t> Certificate_Status::serialize() const
   {
   if(m_response.size() > 0xFFFFFF) // unlikely
      throw Encoding_Error("OCSP response too long to encode in TLS");

   const uint32_t response_len = static_cast<uint32_t>(m_response.size());

   std::vector<uint8_t> buf;
   buf.push_back(1); // type OCSP
   for(size_t i = 1; i < 4; ++i)
      buf.push_back(get_byte(i, response_len));

   buf += m_response;
   return buf;
   }

}

}
