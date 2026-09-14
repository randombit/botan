/*
 * Common private key interface for the module-lattice schemes ML-KEM and ML-DSA
 *
 * (C) 2026 Jack Lloyd
 * (C) 2026 Falko Strenzke - MTG AG
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/module_lattice_keys.h>

namespace Botan {

secure_vector<uint8_t> Module_Lattice_PrivateKey::private_key_bits() const {
   return formatted_private_key_bits(private_key_format());
}

secure_vector<uint8_t> Module_Lattice_PrivateKey::raw_private_key_bits() const {
   // The "both" format has no raw encoding; the seed is its minimal raw representation.
   const auto format = private_key_format();
   return formatted_raw_private_key_bits(format == MlPrivateKeyFormat::Both ? MlPrivateKeyFormat::Seed : format);
}

}  // namespace Botan
