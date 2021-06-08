/*
* TLS Extension Certificate_Status_Request
* (C) 2011,2012,2015,2016,2022 Jack Lloyd
*     2016 Juraj Somorovsky
*     2021 Elektrobit Automotive GmbH
*     2022 Hannes Rantzsch, René Meusel, neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_extensions.h>
#include <botan/tls_messages.h>
#include <botan/internal/tls_reader.h>
#include <botan/tls_exceptn.h>

namespace Botan::TLS
{

std::vector<uint8_t> Certificate_Status_Request::serialize(Connection_Side whoami) const
   {
   std::vector<uint8_t> buf;

   if(whoami == Connection_Side::SERVER)
      return buf; // server reply is empty

   /*
   opaque ResponderID<1..2^16-1>;
   opaque Extensions<0..2^16-1>;

   CertificateStatusType status_type = ocsp(1)
   ResponderID responder_id_list<0..2^16-1>
   Extensions  request_extensions;
   */

   buf.push_back(1); // CertificateStatusType ocsp

   buf.push_back(0);
   buf.push_back(0);
   buf.push_back(0);
   buf.push_back(0);

   return buf;
   }

Certificate_Status_Request::Certificate_Status_Request(TLS_Data_Reader& reader,
                                                       uint16_t extension_size,
                                                       Connection_Side from,
                                                       Handshake_Type message_type)
   {
   if(from == Connection_Side::SERVER)
      {
      // RFC 8446 4.4.2.1
      //    In TLS 1.2 and below, the server replies with an empty extension
      //    [in its Server Hello] [...]. In TLS 1.3, the server's OCSP information
      //    is carried in an extension in the [Certificate handshake message]
      //    containing the associated certificate.
      //
      // We use the `message_type` context information as an indication which
      // type of Certificate_Status_Request extension to expect.
      if(message_type == Handshake_Type::SERVER_HELLO)
         {
         // ... in a Server Hello the extension must have a zero-length body
         if(extension_size != 0)
            throw Decoding_Error("Server sent non-empty Certificate_Status_Request extension in Server Hello");
         }
      else if(message_type == Handshake_Type::CERTIFICATE)
         {
         // RFC 8446 4.4.2.1
         //    In TLS 1.3, the server's OCSP information is carried in an
         //    extension in the CertificateEntry [in a Certificate handshake
         //    message] [...]. Specifically, the body of the "status_request"
         //    extension from the server MUST be a CertificateStatus structure
         //    as defined in [RFC6066] [...].
         m_response = Certificate_Status(reader.get_fixed<uint8_t>(extension_size)).response();
         }
      else
         {
         throw TLS_Exception(Alert::UNSUPPORTED_EXTENSION, "Server sent a Certificate_Status_Request extension in an unsupported context");
         }
      }
   else if(extension_size > 0)
      {
      const uint8_t type = reader.get_byte();
      if(type == 1)
         {
         const size_t len_resp_id_list = reader.get_uint16_t();
         m_ocsp_names = reader.get_fixed<uint8_t>(len_resp_id_list);
         const size_t len_requ_ext = reader.get_uint16_t();
         m_extension_bytes = reader.get_fixed<uint8_t>(len_requ_ext);
         }
      else
         {
         reader.discard_next(extension_size - 1);
         }
      }
   }

Certificate_Status_Request::Certificate_Status_Request(const std::vector<uint8_t>& ocsp_responder_ids,
                                                       const std::vector<std::vector<uint8_t>>& ocsp_key_ids) :
   m_ocsp_names(ocsp_responder_ids),
   m_ocsp_keys(ocsp_key_ids)
   {
   }

}
