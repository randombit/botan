/*
* TLS record structure of TLS 1.3
* (C) 2022 Jack Lloyd
*     2022 Hannes Rantzsch, René Meusel - neXenio GmbH
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_RECORD_13_H_
#define BOTAN_TLS_RECORD_13_H_

#include <botan/secmem.h>
#include <botan/tls_magic.h>
#include <botan/tls_version.h>
#include <optional>

namespace Botan::TLS {

/**
 * Represents the operational content of a (D)TLS record for further processing
 * throughout the TLS protocol or to be passed to the application layer.
 */
struct Record_Content final {
      Record_Type type;
      std::optional<uint64_t> sequence_number;
      secure_vector<uint8_t> payload;
};

/**
 * Represents a TLS record composed of a partially ossified header and payload.
 * The record might be incomplete, i.e. not all bytes of the header or the
 * payload have been received, yet. The record can be extended by appending more
 * bytes to it.
 *
 * Once fully re-assembled, the payload buffer can be extracted from this record
 * for decryption. This avoids an additional copy of the payload bytes.
 */
class BOTAN_TEST_API Record_TLS final {
   public:
      Record_TLS() = default;
      Record_TLS(const Record_TLS&) = delete;
      Record_TLS& operator=(const Record_TLS&) = delete;
      Record_TLS(Record_TLS&&) = default;
      Record_TLS& operator=(Record_TLS&&) = default;

      ~Record_TLS() = default;

   public:
      static std::array<uint8_t, TLS_HEADER_SIZE> serialize_header(Record_Type type,
                                                                   Protocol_Version legacy_version,
                                                                   uint16_t payload_length);

   public:
      /**
       * Appends bytes to an incomplete record. Once the record is complete,
       * additional invocations will throw. If @p bytes contains more bytes than
       * needed to complete the record, only the required number of bytes will
       * be consumed and the rest will be ignored. The caller is responsible for
       * keeping track of the number of bytes consumed and for discarding the
       * consumed bytes from the buffer.
       *
       * @returns the number of bytes that were consumed from the buffer.
       */
      size_t append(std::span<const uint8_t> bytes);

      /// Returns true if the record has collected all header bytes
      bool header_complete() const { return m_header_bytes_stored == TLS_HEADER_SIZE; }

      /// Returns true if the record has collected all its bytes
      bool complete() const { return missing_bytes_hint() == 0; }

      /// Returns the total number of bytes in this record, including the header
      size_t stored_bytes() const { return m_header_bytes_stored + m_payload.size(); }

      /// Returns the number of bytes needed to complete at least the record
      //  header or the entire record if the header is already complete.
      size_t missing_bytes_hint() const;

      Record_Type type() const;
      Protocol_Version legacy_version() const;
      uint16_t payload_length() const;

      std::span<uint8_t, TLS_HEADER_SIZE> header();
      std::span<const uint8_t, TLS_HEADER_SIZE> header() const;

      std::span<const uint8_t> payload() const;
      secure_vector<uint8_t> take_payload();

   private:
      uint8_t m_header_bytes_stored = 0;
      std::array<uint8_t, TLS_HEADER_SIZE> m_header = {};
      secure_vector<uint8_t> m_payload;
};

}  // namespace Botan::TLS

#endif
