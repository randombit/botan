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
                                                       Handshake_Type)
   {
   if(from == Connection_Side::SERVER)
      {
      if(extension_size != 0)
         throw Decoding_Error("Server sent non-empty Certificate_Status_Request extension in Server Hello");
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
