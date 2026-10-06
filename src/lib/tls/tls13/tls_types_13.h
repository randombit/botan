/**
 * TLS 1.3 Strong Type Wrappers
 * (C) 2026 Jack Lloyd
 *     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_TLS_TYPES_13_H_
#define BOTAN_TLS_TYPES_13_H_

#include <botan/secmem.h>
#include <botan/strong_type.h>
#include <functional>
#include <vector>

namespace Botan::TLS {

using BytesNeeded = size_t;

using SecretLoggerFn = std::function<void(std::string_view label, std::span<const uint8_t> secret)>;

/// Holds the serialization of a single TLS 1.3 handshake message without the
/// handshake protocol header.
using SerializedHandshakeMessage = Strong<std::vector<uint8_t>, struct SerializedHandshakeMessage_>;

/// Holds the serialization of a TLS 1.3 handshake protocol header.
using HandshakeProtocolHeader = Strong<std::array<uint8_t, 4>, struct HandshakeProtocolHeader_>;

/// Holds the serialization of a single TLS 1.3 handshake message along
/// with the handshake protocol header.
using MarshalledHandshakeMessage = Strong<std::vector<uint8_t>, struct MarshalledHandshakeMessage_>;

/// Holds the serialization of a single TLS 1.3 record along with the record
/// protocol header. Protected records hold the encrypted payload and AEAD tag.
using MarshalledRecord = Strong<secure_vector<uint8_t>, struct MarshalledRecord_>;

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
