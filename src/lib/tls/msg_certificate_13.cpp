/*
* Certificate Message
* (C) 2022 Jack Lloyd
* (C) 2022 Hannes Rantzsch, René Meusel
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
#include <botan/internal/loadstor.h>
#include <botan/data_src.h>

namespace Botan::TLS {

/**
* Create a new Certificate message
*/
Certificate_13::Certificate_13(Handshake_IO& io,
                               Handshake_Hash& hash,
                               std::vector<Certificate_Entry> entries,
                               const Connection_Side side) :
   m_entries(std::move(entries)),
   m_side(side)
   {
   hash.update(io.send(*this));
   }

/**
* Deserialize a Certificate message
*/
Certificate_13::Certificate_13(const std::vector<uint8_t>& buf,
                               const Policy& policy,
                               const Connection_Side side,
                               const Extensions& request_extensions)
   : m_side(side)
   {
   TLS_Data_Reader reader("cert message reader", buf);

   m_request_context = reader.get_range<uint8_t>(1, 0, 255);

   // RFC 8446 4.4.2
   //    [...] in the case of server authentication, this field SHALL be zero length.
   if(side == Connection_Side::SERVER && !m_request_context.empty())
      {
      throw TLS_Exception(Alert::ILLEGAL_PARAMETER,
                          "Server Certificate message must not contain a request context");
      }

   const auto cert_entries_len = reader.get_uint24_t();

   if(reader.remaining_bytes() != cert_entries_len)
      {
      throw TLS_Exception(Alert::DECODE_ERROR, "Certificate: Message malformed");
      }

   const size_t max_size = policy.maximum_certificate_chain_size();
   if(max_size > 0 && cert_entries_len > max_size)
      { throw Decoding_Error("Certificate chain exceeds policy specified maximum size"); }

   while(reader.has_remaining())
      {
      Certificate_Entry entry;
      entry.certificate = X509_Certificate(reader.get_tls_length_value(3));

      // RFC 8446 4.4.2.2
      //    The certificate type MUST be X.509v3 [RFC5280], unless explicitly
      //    negotiated otherwise (e.g., [RFC7250]).
      //
      // TLS 1.0 through 1.3 all seem to require that the certificate be
      // precisely a v3 certificate. In fact the strict wording would seem
      // to require that every certificate in the chain be v3. But often
      // the intermediates are outside of the control of the server.
      // But, require that the leaf certificate be v3.
      if(m_entries.size() == 0 && entry.certificate.x509_version() != 3)
         {
         throw TLS_Exception(Alert::BAD_CERTIFICATE, "The leaf certificate must be v3");
         }

      const auto exts_buf = reader.get_tls_length_value(2);
      // TODO: this is a lot of copying
      TLS_Data_Reader exts_reader("extensions reader", exts_buf);
      entry.extensions.deserialize(exts_reader, m_side);

      // RFC 8446 4.4.2
      //    Extensions in the Certificate message from the server MUST
      //    correspond to ones from the ClientHello message.  Extensions in
      //    the Certificate message from the client MUST correspond to
      //    extensions in the CertificateRequest message from the server.
      for(const auto& ext_type : entry.extensions.extension_types())
         {
         if(!request_extensions.has(ext_type))
            { throw TLS_Exception(Alert::ILLEGAL_PARAMETER, "Unexpected extension received"); }
         }

      m_entries.push_back(std::move(entry));
      }
   }

/**
* Serialize a Certificate message
*/
std::vector<uint8_t> Certificate_13::serialize() const
   {
   std::vector<uint8_t> buf;

   append_tls_length_value(buf, m_request_context, 1);

   std::vector<uint8_t> entries;
   for(const auto& entry : m_entries)
      {
      append_tls_length_value(entries, entry.certificate.BER_encode(), 3);
      append_tls_length_value(entries, entry.extensions.serialize(m_side), 2);
      }

   append_tls_length_value(buf, entries, 3);

   return buf;
   }

}
