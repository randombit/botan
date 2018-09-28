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

   if(buf[0] != 1)
      throw Decoding_Error("Unexpected Certificate_Status message: unexpected message type");

   size_t len = make_uint32(0, buf[1], buf[2], buf[3]);

   // Verify the redundant length field...
   if(buf.size() != len + 4)
      throw Decoding_Error("Invalid Certificate_Status: invalid length field");

   m_response = std::make_shared<OCSP::Response>(buf.data() + 4, buf.size() - 4);
   }

Certificate_Status::Certificate_Status(Handshake_IO& io,
                                       Handshake_Hash& hash,
                                       std::shared_ptr<const OCSP::Response> ocsp) :
   m_response(ocsp)
   {
   hash.update(io.send(*this));
   }
Certificate_Status::Certificate_Status(Handshake_IO& io,
                                       Handshake_Hash& hash,
                                       std::vector<uint8_t> const& raw_response_bytes) :
   m_raw_response_bytes(raw_response_bytes)
   {
   hash.update(io.send(*this));
   }

std::vector<uint8_t> Certificate_Status::serialize() const
   {
   const std::vector<uint8_t>* resp_bits;
   if(m_raw_response_bytes.size() == 0)
      {
      BOTAN_ASSERT_NONNULL(m_response);
      resp_bits = &m_response->raw_bits();
      }
   else
      {
      BOTAN_ASSERT(m_raw_response_bytes.size() != 0,
                   "Encoded OCSP response for the TLS server's Certificate_Status message has zero length");
      resp_bits = &m_raw_response_bytes;
      }

   if(resp_bits->size() > 0xFFFFFF) // unlikely
      throw Encoding_Error("OCSP response too long to encode in TLS");

   const uint32_t resp_bits_len = static_cast<uint32_t>(resp_bits->size());


   std::vector<uint8_t> buf;
   buf.push_back(1); // type OCSP
   for(size_t i = 1; i < 4; ++i)
      buf.push_back(get_byte(i, resp_bits_len));

   buf += *resp_bits;
   return buf;
   }

}

}
