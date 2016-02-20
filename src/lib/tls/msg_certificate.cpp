/*
* Certificate Message
* (C) 2004-2006,2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_messages.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_extensions.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/loadstor.h>

namespace Botan {

namespace TLS {

/**
* Create a new Certificate message
*/
Certificate::Certificate(Handshake_IO& io,
                         Handshake_Hash& hash,
                         const std::vector<X509_Certificate>& cert_list) :
   m_certs(cert_list)
   {
   hash.update(io.send(*this));
   }

/**
* Deserialize a Certificate message
*/
Certificate::Certificate(const std::vector<byte>& buf)
   {
   if(buf.size() < 3)
      throw Decoding_Error("Certificate: Message malformed");

   const size_t total_size = make_u32bit(0, buf[0], buf[1], buf[2]);

   if(total_size != buf.size() - 3)
      throw Decoding_Error("Certificate: Message malformed");

   const byte* certs = buf.data() + 3;

   while(size_t remaining_bytes = buf.data() + buf.size() - certs)
      {
      if(remaining_bytes < 3)
         throw Decoding_Error("Certificate: Message malformed");

      const size_t cert_size = make_u32bit(0, certs[0], certs[1], certs[2]);

      if(remaining_bytes < (3 + cert_size))
         throw Decoding_Error("Certificate: Message malformed");

      DataSource_Memory cert_buf(&certs[3], cert_size);
      m_certs.push_back(X509_Certificate(cert_buf));

      certs += cert_size + 3;
      }
   }

/**
* Serialize a Certificate message
*/
std::vector<byte> Certificate::serialize() const
   {
   std::vector<byte> buf(3);

   for(size_t i = 0; i != m_certs.size(); ++i)
      {
      std::vector<byte> raw_cert = m_certs[i].BER_encode();
      const size_t cert_size = raw_cert.size();
      for(size_t j = 0; j != 3; ++j)
         {
         buf.push_back(get_byte<u32bit>(j+1, cert_size));
         }
      buf += raw_cert;
      }

   const size_t buf_size = buf.size() - 3;
   for(size_t i = 0; i != 3; ++i)
      buf[i] = get_byte<u32bit>(i+1, buf_size);

   return buf;
   }

}

}
