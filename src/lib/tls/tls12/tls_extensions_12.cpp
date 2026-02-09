/*
* TLS 1.2 Specific Extensions
* (C) 2011,2012,2015,2016 Jack Lloyd
*     2016 Juraj Somorovsky
*     2021 Elektrobit Automotive GmbH
*     2022 René Meusel, Hannes Rantzsch - neXenio GmbH
*     2023 Mateusz Berezecki
*     2023 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
*     2026 René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_extensions_12.h>

#include <botan/tls_alert.h>
#include <botan/tls_exceptn.h>
#include <botan/internal/tls_reader.h>

namespace Botan::TLS {

Renegotiation_Extension::Renegotiation_Extension(TLS_Data_Reader& reader, uint16_t extension_size) :
      m_reneg_data(reader.get_range<uint8_t>(1, 0, 255)) {
   if(m_reneg_data.size() + 1 != extension_size) {
      throw Decoding_Error("Bad encoding for secure renegotiation extn");
   }
}

std::vector<uint8_t> Renegotiation_Extension::serialize(Connection_Side /*whoami*/) const {
   std::vector<uint8_t> buf;
   append_tls_length_value(buf, m_reneg_data, 1);
   return buf;
}

std::vector<uint8_t> Supported_Point_Formats::serialize(Connection_Side /*whoami*/) const {
   // if this extension is sent, it MUST include uncompressed (RFC 4492, section 5.1)
   if(m_prefers_compressed) {
      return std::vector<uint8_t>{2, ANSIX962_COMPRESSED_PRIME, UNCOMPRESSED};
   } else {
      return std::vector<uint8_t>{1, UNCOMPRESSED};
   }
}

Supported_Point_Formats::Supported_Point_Formats(TLS_Data_Reader& reader, uint16_t extension_size) {
   const uint8_t len = reader.get_byte();

   if(len + 1 != extension_size) {
      throw Decoding_Error("Inconsistent length field in supported point formats list");
   }

   bool includes_uncompressed = false;
   for(size_t i = 0; i != len; ++i) {
      const uint8_t format = reader.get_byte();

      if(static_cast<ECPointFormat>(format) == UNCOMPRESSED) {
         m_prefers_compressed = false;
         reader.discard_next(len - i - 1);
         return;
      } else if(static_cast<ECPointFormat>(format) == ANSIX962_COMPRESSED_PRIME) {
         m_prefers_compressed = true;
         std::vector<uint8_t> remaining_formats = reader.get_fixed<uint8_t>(len - i - 1);
         includes_uncompressed =
            std::any_of(std::begin(remaining_formats), std::end(remaining_formats), [](uint8_t remaining_format) {
               return static_cast<ECPointFormat>(remaining_format) == UNCOMPRESSED;
            });
         break;
      }

      // ignore ANSIX962_COMPRESSED_CHAR2, we don't support these curves
   }

   // RFC 4492 5.1.:
   //   If the Supported Point Formats Extension is indeed sent, it MUST contain the value 0 (uncompressed)
   //   as one of the items in the list of point formats.
   // Note:
   //   RFC 8422 5.1.2. explicitly requires this check,
   //   but only if the Supported Groups extension was sent.
   if(!includes_uncompressed) {
      throw TLS_Exception(Alert::IllegalParameter,
                          "Supported Point Formats Extension must contain the uncompressed point format");
   }
}

Session_Ticket_Extension::Session_Ticket_Extension(TLS_Data_Reader& reader, uint16_t extension_size) :
      m_ticket(Session_Ticket(reader.get_elem<uint8_t, std::vector<uint8_t>>(extension_size))) {}

Extended_Master_Secret::Extended_Master_Secret(TLS_Data_Reader& /*unused*/, uint16_t extension_size) {
   if(extension_size != 0) {
      throw Decoding_Error("Invalid extended_master_secret extension");
   }
}

std::vector<uint8_t> Extended_Master_Secret::serialize(Connection_Side /*whoami*/) const {
   return std::vector<uint8_t>();
}

Encrypt_then_MAC::Encrypt_then_MAC(TLS_Data_Reader& /*unused*/, uint16_t extension_size) {
   if(extension_size != 0) {
      throw Decoding_Error("Invalid encrypt_then_mac extension");
   }
}

std::vector<uint8_t> Encrypt_then_MAC::serialize(Connection_Side /*whoami*/) const {
   return std::vector<uint8_t>();
}

}  // namespace Botan::TLS
