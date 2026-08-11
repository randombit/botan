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

namespace Botan::TLS {

/// Holds the serialization of a single TLS 1.3 record along with the record
/// protocol header. Protected records hold the encrypted payload and AEAD tag.
using MarshalledRecord = Strong<secure_vector<uint8_t>, struct MarshalledRecord_>;

}  // namespace Botan::TLS

#endif
