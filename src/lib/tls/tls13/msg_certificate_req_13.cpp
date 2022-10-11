/*
* (C) 2022 Jack Lloyd
* (C) 2022 Hannes Rantzsch, René Meusel - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages.h>
#include <botan/internal/tls_reader.h>
#include <botan/tls_exceptn.h>

namespace Botan::TLS
{

Handshake_Type Certificate_Request_13::type() const
   {
   return Botan::TLS::Handshake_Type::CERTIFICATE_REQUEST;
   }

Certificate_Request_13::Certificate_Request_13(const std::vector<uint8_t>& buf, const Connection_Side side)
   {
   TLS_Data_Reader reader("Certificate_Request_13", buf);

   // RFC 8446 4.3.2
   //    A server which is authenticating with a certificate MAY optionally
   //    request a certificate from the client.
   if(side != Connection_Side::SERVER)
      {
      throw TLS_Exception(Alert::UNEXPECTED_MESSAGE, "Received a Certificate_Request message from a client");
      }

   m_context = reader.get_tls_length_value(1);
   m_extensions.deserialize(reader, side, type());

   // RFC 8446 4.3.2
   //    The "signature_algorithms" extension MUST be specified, and other
   //    extensions may optionally be included if defined for this message.
   //    Clients MUST ignore unrecognized extensions.

   if(!m_extensions.has<Signature_Algorithms>())
      {
      throw TLS_Exception(Alert::MISSING_EXTENSION, "Certificate_Request message did not provide a signature_algorithms extension");
      }

   // RFC 8446 4.2.
   //    The table below indicates the messages where a given extension may
   //    appear [...].  If an implementation receives an extension which it
   //    recognizes and which is not specified for the message in which it
   //    appears, it MUST abort the handshake with an "illegal_parameter" alert.
   //
   // For Certificate Request said table states:
   //    "status_request", "signature_algorithms", "signed_certificate_timestamp",
   //     "certificate_authorities", "oid_filters", "signature_algorithms_cert",
   std::set<Handshake_Extension_Type> allowed_extensions =
      {
      TLSEXT_CERT_STATUS_REQUEST,
      TLSEXT_SIGNATURE_ALGORITHMS,
      // TLSEXT_SIGNED_CERTIFICATE_TIMESTAMP,  // NYI
      TLSEXT_CERTIFICATE_AUTHORITIES,
      // TLSEXT_OID_FILTERS,                   // NYI
      TLSEXT_SIGNATURE_ALGORITHMS_CERT,
      };

   if(m_extensions.contains_implemented_extensions_other_than(allowed_extensions))
      {
      throw TLS_Exception(Alert::ILLEGAL_PARAMETER,
                          "Certificate Request contained an extension that is not allowed");
      }
   }

std::vector<X509_DN> Certificate_Request_13::acceptable_CAs() const
   {
   if(m_extensions.has<Certificate_Authorities>())
      return m_extensions.get<Certificate_Authorities>()->distinguished_names();
   return {};
   }

const std::vector<Signature_Scheme>& Certificate_Request_13::signature_schemes() const
   {
   // RFC 8446 4.3.2
   //    The "signature_algorithms" extension MUST be specified
   BOTAN_ASSERT_NOMSG(m_extensions.has<Signature_Algorithms>());

   return m_extensions.get<Signature_Algorithms>()->supported_schemes();
   }

std::vector<uint8_t> Certificate_Request_13::serialize() const
   {
   throw Botan::Not_Implemented("Certificate_Request_13::serialize");
   }

}  // namespace Botan::TLS
