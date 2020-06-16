/*
* Certificate Message
* (C) 2004-2006,2012,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages.h>
#include <botan/tls_extensions.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_alert.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_handshake_hash.h>
#include <botan/loadstor.h>
#include <botan/data_src.h>

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
Certificate::Certificate(const std::vector<uint8_t>& buf, const Policy& policy)
   {
   if(buf.size() < 3)
      throw Decoding_Error("Certificate: Message malformed");

   const size_t total_size = make_uint32(0, buf[0], buf[1], buf[2]);

   if(total_size != buf.size() - 3)
      throw Decoding_Error("Certificate: Message malformed");

   const size_t max_size = policy.maximum_certificate_chain_size();
   if(max_size > 0 && total_size > max_size)
      throw Decoding_Error("Certificate chain exceeds policy specified maximum size");

   const uint8_t* certs = buf.data() + 3;

   while(size_t remaining_bytes = buf.data() + buf.size() - certs)
      {
      if(remaining_bytes < 3)
         throw Decoding_Error("Certificate: Message malformed");

      const size_t cert_size = make_uint32(0, certs[0], certs[1], certs[2]);

      if(remaining_bytes < (3 + cert_size))
         throw Decoding_Error("Certificate: Message malformed");

      DataSource_Memory cert_buf(&certs[3], cert_size);
      m_certs.push_back(X509_Certificate(cert_buf));

      certs += cert_size + 3;
      }

   /*
   * TLS 1.0 through 1.2 all seem to require that the certificate be
   * precisely a v3 certificate. In fact the strict wording would seem
   * to require that every certificate in the chain be v3. But often
   * the intermediates are outside of the control of the server.
   * But, require that the leaf certificate be v3
   */
   if(m_certs.size() > 0 && m_certs[0].x509_version() != 3)
      {
      throw TLS_Exception(Alert::BAD_CERTIFICATE,
                          "The leaf certificate must be v3");
      }
   }

/**
* Serialize a Certificate message
*/
std::vector<uint8_t> Certificate::serialize() const
   {
   std::vector<uint8_t> buf(3);

   for(size_t i = 0; i != m_certs.size(); ++i)
      {
      std::vector<uint8_t> raw_cert = m_certs[i].BER_encode();
      const size_t cert_size = raw_cert.size();
      for(size_t j = 0; j != 3; ++j)
         {
         buf.push_back(get_byte(j+1, static_cast<uint32_t>(cert_size)));
         }
      buf += raw_cert;
      }

   const size_t buf_size = buf.size() - 3;
   for(size_t i = 0; i != 3; ++i)
      buf[i] = get_byte(i+1, static_cast<uint32_t>(buf_size));

   return buf;
   }

}

}
