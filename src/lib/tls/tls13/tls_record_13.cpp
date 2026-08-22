/*
* TLS record structure implementation for TLS 1.3
* (C) 2022 Jack Lloyd
*     2022 Hannes Rantzsch, René Meusel - neXenio GmbH
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_record_13.h>

#include <botan/tls_exceptn.h>
#include <botan/internal/buffer_slicer.h>
#include <botan/internal/concat_util.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>

namespace Botan::TLS {

std::array<uint8_t, TLS_HEADER_SIZE> Record_TLS::serialize_header(Record_Type type,
                                                                  Protocol_Version legacy_version,
                                                                  uint16_t payload_length) {
   return concat(store_be(to_underlying(type)),            //
                 store_be(legacy_version.version_code()),  //
                 store_be(payload_length));
}

size_t Record_TLS::append(std::span<const uint8_t> bytes) {
   BOTAN_STATE_CHECK(!complete());

   BufferSlicer bs(bytes);

   if(!header_complete()) {
      // If we don't have the complete header yet, we have to first assemble
      // that before we can know the amount of payload to store.

      const auto remaining_header_portion = std::span{m_header}.subspan(m_header_bytes_stored);
      const auto bytes_to_consume = std::min(remaining_header_portion.size(), bs.remaining());
      bs.copy_into(remaining_header_portion.first(bytes_to_consume));
      m_header_bytes_stored = static_cast<uint8_t>(m_header_bytes_stored + bytes_to_consume);
   }

   if(header_complete()) {
      // Now we have the complete record header, we can look into the expected
      // header information and start assembling the payload.

      // The legacy major version is essentially ossified to 0x03 and anything
      // else can be rejected right away.
      if(legacy_version().major_version() != 0x03) {
         throw TLS_Exception(Alert::IllegalParameter, "Received unexpected record version");
      }

      // RFC 9846 5.
      //    Implementations MUST NOT send record types not defined in this
      //    document unless negotiated by some extension. If a TLS
      //    implementation receives an unexpected record type, it MUST terminate
      //    the connection with an "unexpected_message" alert.
      //
      // RFC 9846 5.1
      //    enum {
      //        invalid(0),
      //        change_cipher_spec(20),
      //        alert(21),
      //        handshake(22),
      //        application_data(23),
      //        (255)
      //    } ContentType;
      const auto record_type = type();
      if(record_type != Record_Type::ApplicationData &&  //
         record_type != Record_Type::Handshake &&        //
         record_type != Record_Type::Alert &&            //
         record_type != Record_Type::ChangeCipherSpec) {
         throw TLS_Exception(Alert::UnexpectedMessage, "TLS record type had unexpected value");
      }

      const size_t expected_payload_length = payload_length();

      // RFC 9846 5.1
      //    Implementations MUST NOT send zero-length fragments of Handshake
      //    types, even if those fragments contain padding.
      //
      //    Zero-length fragments of Application Data MAY be sent, as they are
      //    potentially useful as a traffic analysis countermeasure.
      //
      // Hence, the payload length must always be non-null. Even for application
      // data, the protected payload would contain at least the authentication
      // tag and won't ever be empty either.
      if(expected_payload_length == 0) {
         throw TLS_Exception(Alert::DecodeError, "empty record received");
      }

      // TODO: we could restrict the payload length sanity checks further based
      //       on the record type: e.g. a reasonable unprotected alert record
      //       should be much smaller than 2^14 bytes.
      if(record_type != Record_Type::ApplicationData) {
         // RFC 9846 5.1 "Record Layer"
         //    The length MUST NOT exceed 2^14 bytes. An endpoint that receives
         //    a record that exceeds this length MUST terminate the connection
         //    with a "record_overflow" alert.
         if(expected_payload_length > MAX_PLAINTEXT_SIZE) {
            throw TLS_Exception(Alert::RecordOverflow, "Received a record that exceeds maximum size");
         }
      } else {
         // RFC 9846 5.2 "Record Payload Protection"
         //    The length MUST NOT exceed 2^14 + 256 bytes. An endpoint that
         //    receives a record that exceeds this length MUST terminate the
         //    connection with a "record_overflow" alert.
         //
         // Note: Limits imposed by a "record_size_limit" extension do not come
         //       into play here, as those limits are on the plaintext _not_ the
         //       encrypted data. Constricted devices must be able to deal with
         //       data overhead inflicted by the AEAD.
         if(expected_payload_length > MAX_CIPHERTEXT_SIZE_TLS13) {
            throw TLS_Exception(Alert::RecordOverflow, "Received a protected record that exceeds maximum size");
         }
      }

      // We now know the expected size of the payload and we sanity-checked it
      // against the protocol limits. We can reserve enough space to hold it.
      m_payload.reserve(expected_payload_length);

      // Append as many payload bytes as we can, but don't overshoot into any
      // other records that may be present in the input buffer.
      const size_t remaining_payload_bytes = expected_payload_length - m_payload.size();
      const size_t bytes_to_consume = std::min(remaining_payload_bytes, bs.remaining());
      const auto new_payload_fragment = bs.take(bytes_to_consume);
      m_payload.insert(m_payload.end(), new_payload_fragment.begin(), new_payload_fragment.end());
   }

   // Calculate the number of bytes consumed from the input buffer.
   return bytes.size() - bs.remaining();
}

size_t Record_TLS::missing_bytes_hint() const {
   // If we don't even have the complete header, we need at least the remaining
   // header bytes to know the entire length of the record.
   if(!header_complete()) {
      return TLS_HEADER_SIZE - m_header_bytes_stored;
   }

   // If we have the header, we can determine the expected length of the
   // payload and return the number of bytes still needed to complete it.
   return payload_length() - m_payload.size();
}

Record_Type Record_TLS::type() const {
   BOTAN_STATE_CHECK(header_complete());
   return static_cast<Record_Type>(m_header[0]);
}

Protocol_Version Record_TLS::legacy_version() const {
   BOTAN_STATE_CHECK(header_complete());
   return Protocol_Version(load_be(std::span{m_header}.subspan<1, 2>()));
}

uint16_t Record_TLS::payload_length() const {
   BOTAN_STATE_CHECK(header_complete());
   return load_be(std::span{m_header}.subspan<3, 2>());
}

std::span<uint8_t, TLS_HEADER_SIZE> Record_TLS::header() {
   BOTAN_STATE_CHECK(header_complete());
   return m_header;
}

std::span<const uint8_t, TLS_HEADER_SIZE> Record_TLS::header() const {
   BOTAN_STATE_CHECK(header_complete());
   return m_header;
}

std::span<const uint8_t> Record_TLS::payload() const {
   BOTAN_STATE_CHECK(complete());
   return m_payload;
}

secure_vector<uint8_t> Record_TLS::take_payload() {
   BOTAN_STATE_CHECK(complete());
   return std::exchange(m_payload, {});
}

}  // namespace Botan::TLS
