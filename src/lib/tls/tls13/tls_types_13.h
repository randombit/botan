/**
 * TLS 1.3 Strong Type Wrappers
 * (C) 2026 Jack Lloyd
 *     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_TLS_TYPES_13_H_
#define BOTAN_TLS_TYPES_13_H_

#include <botan/assert.h>
#include <botan/strong_type.h>
#include <functional>
#include <limits>
#include <optional>
#include <vector>

namespace Botan::TLS {

using BytesNeeded = size_t;

using SecretLoggerFn = std::function<void(std::string_view label, std::span<const uint8_t> secret)>;

class EpochNumber final {
   public:
      using value_type = uint64_t;

   private:
      constexpr static value_type Unprotected = 0;
      constexpr static value_type EarlyTraffic = 1;
      constexpr static value_type HandshakeTraffic = 2;
      constexpr static value_type ApplicationTraffic_0 = 3;

      constexpr explicit EpochNumber(value_type index) : m_index(index) {}

   public:
      static constexpr EpochNumber create(value_type index) { return EpochNumber(index); }

      static constexpr EpochNumber unprotected() { return EpochNumber(Unprotected); }

      static constexpr EpochNumber early_traffic() { return EpochNumber(EarlyTraffic); }

      static constexpr EpochNumber handshake_traffic() { return EpochNumber(HandshakeTraffic); }

   public:
      constexpr bool is_unprotected() const noexcept { return m_index == Unprotected; }

      constexpr bool is_protected() const noexcept { return m_index >= EarlyTraffic; }

      constexpr bool is_early_traffic() const noexcept { return m_index == EarlyTraffic; }

      constexpr bool is_handshake_traffic() const noexcept { return m_index == HandshakeTraffic; }

      constexpr bool is_application_traffic() const noexcept { return m_index >= ApplicationTraffic_0; }

      constexpr bool is_exhausted_for_dtls() const noexcept {
         // RFC 9147 8.
         //    With a 128-bit key as in AES-128, rekeying 2^64 times has a high
         //    probability of key reuse within a given connection. [...] In
         //    order to provide an extra margin of security, sending
         //    implementations MUST NOT allow the epoch to exceed 2^48-1. [...]
         //
         // RFC 9147 8. (Errata-ID 8050)
         //    After the handshake, each epoch change consumes a message_seq
         //    value, which is limited to 2^16-1. Both sending and receiving
         //    implementations MAY instead enforce an epoch limit of 2^16-1. In
         //    this case, the implementation MUST check for this limit, if
         //    reached, terminate the association.
         return m_index >= std::numeric_limits<uint16_t>::max();
      }

      constexpr value_type index() const noexcept { return m_index; }

      constexpr std::optional<value_type> application_traffic_index() const noexcept {
         if(!is_application_traffic()) {
            return std::nullopt;
         }
         return index() - ApplicationTraffic_0;
      }

      EpochNumber next() const {
         BOTAN_STATE_CHECK(m_index < std::numeric_limits<value_type>::max());
         return EpochNumber(m_index + 1);
      }

      constexpr auto operator<=>(const EpochNumber&) const = default;

   private:
      value_type m_index;
};

/**
 * RFC 9147 Section 4
 */
struct RecordNumber {
      EpochNumber epoch;         // NOLINT(*-non-private-member-variable*)
      uint64_t sequence_number;  // NOLINT(*-non-private-member-variable*)

      auto operator<=>(const RecordNumber&) const = default;
};

/// Holds the serialization of a single TLS 1.3 handshake message without the
/// handshake protocol header.
using SerializedHandshakeMessage = Strong<std::vector<uint8_t>, struct SerializedHandshakeMessage_>;

/// Holds the serialization of a TLS 1.3 handshake protocol header.
using HandshakeProtocolHeader = Strong<std::array<uint8_t, 4>, struct HandshakeProtocolHeader_>;

/// Holds the serialization of a single TLS 1.3 handshake message along with
/// the handshake protocol header.
using MarshalledHandshakeMessage = Strong<std::vector<uint8_t>, struct MarshalledHandshakeMessage_>;

/// Holds the serialization of a TLS 1.3 handshake message flight containing
/// multiple handshake messages along with their handshake protocol headers.
using MarshalledHandshakeMessageFlight = Strong<std::vector<uint8_t>, struct MarshalledHandshakeMessageFlight_>;

/**
 * Wraps the epoch0 (unprotected) sequence numbers that are being handed down
 * from a DTLS 1.3 handshake to a DTLS 1.2 handshake during protocol downgrade.
 */
struct Epoch0_SequenceNumbers {
      uint64_t read;
      uint64_t write;
};

}  // namespace Botan::TLS

#endif
