/*
* TLS 1.3 Specific Extensions
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

#include <botan/tls_extensions_13.h>

#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/tls_alert.h>
#include <botan/tls_exceptn.h>
#include <botan/internal/tls_reader.h>

namespace Botan::TLS {

Cookie::Cookie(std::vector<uint8_t> cookie) : m_cookie(std::move(cookie)) {}

Cookie::Cookie(TLS_Data_Reader& reader, uint16_t extension_size) {
   // RFC 8446 4.2.2
   //    struct {
   //       opaque cookie<1..2^16-1>;
   //    } Cookie;
   //
   // The wire form requires a 2-byte length field plus at least one byte of
   // cookie data, so the minimum extension size is 3 bytes.
   if(extension_size < 3) {
      throw Decoding_Error("Empty cookie extension is illegal");
   }

   const uint16_t len = reader.get_uint16_t();

   if(static_cast<size_t>(len) + 2 != extension_size) {
      throw Decoding_Error("Inconsistent length in cookie extension");
   }

   m_cookie = reader.get_fixed<uint8_t>(len);
}

std::vector<uint8_t> Cookie::serialize(Connection_Side /*whoami*/) const {
   std::vector<uint8_t> buf;
   append_tls_length_value(buf, m_cookie, 2);
   return buf;
}

std::vector<uint8_t> PSK_Key_Exchange_Modes::serialize(Connection_Side /*whoami*/) const {
   std::vector<uint8_t> buf;

   BOTAN_ASSERT_NOMSG(m_modes.size() < 256);
   buf.push_back(static_cast<uint8_t>(m_modes.size()));
   for(const auto& mode : m_modes) {
      buf.push_back(static_cast<uint8_t>(mode));
   }

   return buf;
}

PSK_Key_Exchange_Modes::PSK_Key_Exchange_Modes(TLS_Data_Reader& reader, uint16_t extension_size) {
   // RFC 8446 4.2.9
   //    struct {
   //       PskKeyExchangeMode ke_modes<1..255>;
   //    } PskKeyExchangeModes;
   //
   // The wire form is a 1-byte length followed by mode_count mode bytes,
   // with mode_count in [1, 255], so the extension size is in [2, 256].
   if(extension_size < 2) {
      throw Decoding_Error("Empty psk_key_exchange_modes extension is illegal");
   }

   const auto mode_count = reader.get_byte();
   if(static_cast<size_t>(mode_count) + 1 != extension_size) {
      throw Decoding_Error("Inconsistent length in psk_key_exchange_modes extension");
   }

   for(uint16_t i = 0; i < mode_count; ++i) {
      const auto mode = static_cast<PSK_Key_Exchange_Mode>(reader.get_byte());
      if(mode == PSK_Key_Exchange_Mode::PSK_KE || mode == PSK_Key_Exchange_Mode::PSK_DHE_KE) {
         m_modes.push_back(mode);
      }
   }
}

std::vector<uint8_t> Certificate_Authorities::serialize(Connection_Side /*whoami*/) const {
   std::vector<uint8_t> out;
   std::vector<uint8_t> dn_list;

   for(const auto& dn : m_distinguished_names) {
      std::vector<uint8_t> encoded_dn;
      auto encoder = DER_Encoder(encoded_dn);
      dn.encode_into(encoder);
      append_tls_length_value(dn_list, encoded_dn, 2);
   }

   append_tls_length_value(out, dn_list, 2);

   return out;
}

Certificate_Authorities::Certificate_Authorities(TLS_Data_Reader& reader, uint16_t extension_size) {
   if(extension_size < 2) {
      throw Decoding_Error("Empty certificate_authorities extension is illegal");
   }

   const uint16_t purported_size = reader.get_uint16_t();

   if(reader.remaining_bytes() != purported_size) {
      throw Decoding_Error("Inconsistent length in certificate_authorities extension");
   }

   // RFC 8446 4.2.4: DistinguishedName authorities<3..2^16-1>;
   if(purported_size < 3) {
      throw Decoding_Error("Empty certificate_authorities list is illegal");
   }

   while(reader.has_remaining()) {
      // RFC 8446 4.2.4: opaque DistinguishedName<1..2^16-1>
      const std::vector<uint8_t> name_bits = reader.get_range<uint8_t>(2, 1, 65535);

      BER_Decoder decoder(name_bits, BER_Decoder::Limits::DER());
      m_distinguished_names.emplace_back();
      decoder.decode(m_distinguished_names.back()).verify_end();
   }
}

Certificate_Authorities::Certificate_Authorities(std::vector<X509_DN> acceptable_DNs) :
      m_distinguished_names(std::move(acceptable_DNs)) {}

std::vector<uint8_t> EarlyDataIndication::serialize(Connection_Side /*whoami*/) const {
   std::vector<uint8_t> result;
   if(m_max_early_data_size.has_value()) {
      const auto max_data = m_max_early_data_size.value();
      result.push_back(get_byte<0>(max_data));
      result.push_back(get_byte<1>(max_data));
      result.push_back(get_byte<2>(max_data));
      result.push_back(get_byte<3>(max_data));
   }
   return result;
}

EarlyDataIndication::EarlyDataIndication(TLS_Data_Reader& reader,
                                         uint16_t extension_size,
                                         Handshake_Type message_type) {
   if(message_type == Handshake_Type::NewSessionTicket) {
      if(extension_size != 4) {
         throw TLS_Exception(Alert::DecodeError,
                             "Received an early_data extension in a NewSessionTicket message "
                             "without maximum early data size indication");
      }

      m_max_early_data_size = reader.get_uint32_t();
   } else if(extension_size != 0) {
      throw TLS_Exception(Alert::DecodeError,
                          "Received an early_data extension containing an unexpected data "
                          "size indication");
   }
}

bool EarlyDataIndication::empty() const {
   // This extension may be empty by definition but still carry information
   return false;
}

}  // namespace Botan::TLS
