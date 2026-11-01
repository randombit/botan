/*
* Certificate Message
* (C) 2004-2006,2012,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages_12.h>

#include <botan/data_src.h>
#include <botan/tls_alert.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_extensions.h>
#include <botan/tls_policy.h>
#include <botan/x509cert.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/tls_handshake_hash.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_reader.h>

namespace Botan::TLS {

Certificate_12::~Certificate_12() = default;

/**
* Create a new Certificate message
*/
Certificate_12::Certificate_12(Handshake_IO& io, Handshake_Hash& hash, std::vector<X509_Certificate> cert_list) :
      m_certs(std::move(cert_list)) {
   hash.update(io.send(*this));
}

/**
* Deserialize a Certificate message
*/
Certificate_12::Certificate_12(std::span<const uint8_t> buf, const Policy& policy) {
   if(buf.size() < 3) {
      throw Decoding_Error("Certificate: Message malformed");
   }

   const size_t total_size = make_uint32(0, buf[0], buf[1], buf[2]);

   if(total_size != buf.size() - 3) {
      throw Decoding_Error("Certificate: Message malformed");
   }

   const size_t max_size = policy.maximum_certificate_chain_size();
   if(max_size > 0 && total_size > max_size) {
      throw Decoding_Error("Certificate chain exceeds policy specified maximum size");
   }

   const uint8_t* certs = buf.data() + 3;

   while(const size_t remaining_bytes = buf.data() + buf.size() - certs) {
      if(remaining_bytes < 3) {
         throw Decoding_Error("Certificate: Message malformed");
      }

      const size_t cert_size = make_uint32(0, certs[0], certs[1], certs[2]);

      if(remaining_bytes < (3 + cert_size)) {
         throw Decoding_Error("Certificate: Message malformed");
      }

      DataSource_Memory cert_buf(&certs[3], cert_size);
      try {
         m_certs.push_back(X509_Certificate(cert_buf));
      } catch(Exception& e) {
         // bad_certificate would make more sense but BoGo expects decoding_error
         throw TLS_Exception(Alert::DecodeError, e.what());
      }

      certs += cert_size + 3;
   }

   /*
   * TLS 1.0 through 1.2 all seem to require that the certificate be
   * precisely a v3 certificate. In fact the strict wording would seem
   * to require that every certificate in the chain be v3. But often
   * the intermediates are outside of the control of the server.
   * But, require that the leaf certificate be v3
   */
   if(!m_certs.empty() && m_certs[0].x509_version() != 3) {
      throw TLS_Exception(Alert::BadCertificate, "The leaf certificate must be v3");
   }
}

/**
* Serialize a Certificate message
*/
std::vector<uint8_t> Certificate_12::serialize() const {
   // RFC 5246 7.4.2
   //    opaque ASN.1Cert<1..2^24-1>;
   //    [...]
   //    ASN.1Cert certificate_list<0..2^24-1>;
   std::vector<uint8_t> certs;
   for(const auto& cert : m_certs) {
      append_tls_length_value(certs, cert.BER_encode(), 3);
   }

   std::vector<uint8_t> buf;
   append_tls_length_value(buf, certs, 3);
   return buf;
}

size_t Certificate_12::count() const {
   return m_certs.size();
}

}  // namespace Botan::TLS
