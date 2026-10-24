/**
 * TLS 1.3 Strong Type Wrappers
 * (C) 2026 Jack Lloyd
 *     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_TLS_TYPES_13_H_
#define BOTAN_TLS_TYPES_13_H_

#include <botan/strong_type.h>
#include <functional>
#include <vector>

namespace Botan::TLS {

using BytesNeeded = size_t;

using SecretLoggerFn = std::function<void(std::string_view label, std::span<const uint8_t> secret)>;

enum class EpochNumber /* NOLINT(*-enum-size) */ : uint64_t {
   Unprotected = 0,
   EarlyTraffic = 1,
   HandshakeTraffic = 2,
   ApplicationTraffic_0 = 3,
   // ApplicationTraffic_1 = 4
   // ApplicationTraffic_2 = 5
   // ...
   // ApplicationTraffic_N = N + 3
};

constexpr EpochNumber operator+(EpochNumber current, size_t offset) {
   // NOLINTNEXTLINE(*.EnumCastOutOfRange)
   return static_cast<EpochNumber>(static_cast<uint64_t>(current) + offset);
}

constexpr EpochNumber operator-(EpochNumber current, EpochNumber offset) {
   // NOLINTNEXTLINE(*.EnumCastOutOfRange)
   return static_cast<EpochNumber>(static_cast<uint64_t>(current) - static_cast<uint64_t>(offset));
}

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
