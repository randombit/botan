/*
* SSL/TLS Protocol Constants
* (C) 2004-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_PROTOCOL_MAGIC_H_
#define BOTAN_TLS_PROTOCOL_MAGIC_H_

#include <botan/strong_type.h>
#include <botan/types.h>
#include <array>
#include <vector>

//BOTAN_FUTURE_INTERNAL_HEADER(tls_magic.h)

namespace Botan::TLS {

/**
* Protocol Constants for SSL/TLS
*
* TODO(Botan4): this should not be an enum at all
*/
enum Size_Limits : size_t /* NOLINT(*-enum-size,*-use-enum-class) */ {
   TLS_HEADER_SIZE = 5,
   DTLS_HEADER_SIZE = TLS_HEADER_SIZE + 8,

   // The "TLSInnerPlaintext" length, i.e. the maximum amount of plaintext
   // application data that can be transmitted in a single TLS record.
   MAX_PLAINTEXT_SIZE = 16 * 1024,

   MAX_COMPRESSED_SIZE = MAX_PLAINTEXT_SIZE + 1024,
   MAX_CIPHERTEXT_SIZE = MAX_COMPRESSED_SIZE + 1024,

   // RFC 8446 5.2:
   //   This limit is derived from the maximum TLSInnerPlaintext length of 2^14
   //   octets + 1 octet for ContentType + the maximum AEAD expansion of 255
   //   octets.
   MAX_AEAD_EXPANSION_SIZE_TLS13 = 255,
   MAX_CIPHERTEXT_SIZE_TLS13 = MAX_PLAINTEXT_SIZE + MAX_AEAD_EXPANSION_SIZE_TLS13 + 1
};

enum class Connection_Side : uint8_t {
   Client = 1,
   Server = 2,

   CLIENT BOTAN_DEPRECATED("Use Connection_Side::Client") = Client,
   SERVER BOTAN_DEPRECATED("Use Connection_Side::Server") = Server,
};

enum class Record_Type : uint8_t {
   Invalid = 0,  // RFC 8446 (TLS 1.3)

   ChangeCipherSpec = 20,
   Alert = 21,
   Handshake = 22,
   ApplicationData = 23,

   Heartbeat = 24,  // RFC 6520 (TLS 1.3)
};

enum class Handshake_Type : uint8_t {
   HelloRequest = 0,
   ClientHello = 1,
   ServerHello = 2,
   HelloVerifyRequest = 3,
   NewSessionTicket = 4,  // RFC 5077

   EndOfEarlyData = 5,       // RFC 8446 (TLS 1.3)
   EncryptedExtensions = 8,  // RFC 8446 (TLS 1.3)

   Certificate = 11,
   ServerKeyExchange = 12,
   CertificateRequest = 13,
   ServerHelloDone = 14,
   CertificateVerify = 15,
   ClientKeyExchange = 16,
   Finished = 20,

   CertificateUrl = 21,
   CertificateStatus = 22,

   KeyUpdate = 24,  // RFC 8446 (TLS 1.3)

   HelloRetryRequest = 253,  // Not a wire value (HRR appears as an ordinary Server Hello)
   HandshakeCCS = 254,       // Not a wire value (TLS 1.3 uses this value for 'message_hash' -- RFC 8446 4.4.1)
   None = 255                // Null value
};

BOTAN_TEST_API const char* handshake_type_to_string(Handshake_Type t);

using Transcript_Hash = std::vector<uint8_t>;

/// @brief Used to derive the ticket's PSK from the resumption_master_secret
using Ticket_Nonce = Strong<std::vector<uint8_t>, struct Ticket_Nonce_>;

/**
 * Magic values used to signal a downgrade request to TLS 1.1.
 *
 * RFC 8446 4.1.3:
 *   TLS 1.3 has a downgrade protection mechanism embedded in the server's
 *   random value. TLS 1.3 servers which negotiate TLS 1.2 or below in
 *   response to a ClientHello MUST set the last 8 bytes of their Random
 *   value specially in their ServerHello.
 */
constexpr uint64_t DOWNGRADE_TLS11 = 0x444F574E47524400;

/**
 * Magic values used to signal a downgrade request to TLS 1.2.
 *
 * RFC 8446 4.1.3:
 *   TLS 1.3 has a downgrade protection mechanism embedded in the server's
 *   random value. TLS 1.3 servers which negotiate TLS 1.2 or below in
 *   response to a ClientHello MUST set the last 8 bytes of their Random
 *   value specially in their ServerHello.
 */
constexpr uint64_t DOWNGRADE_TLS12 = 0x444F574E47524401;

/** 
 * RFC 8446 4.1.3:
 *   For reasons of backward compatibility with middleboxes, the
 *   HelloRetryRequest message uses the same structure as the ServerHello, but
 *   with Random set to the special value of the SHA-256 of "HelloRetryRequest":
 */
constexpr std::array<uint8_t, 32> HELLO_RETRY_REQUEST_MARKER = {
   0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
   0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C};

}  // namespace Botan::TLS

#endif
