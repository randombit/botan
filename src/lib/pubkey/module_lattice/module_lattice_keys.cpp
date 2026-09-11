/*
 * Common private key interface for the module-lattice schemes ML-KEM and ML-DSA
 *
 * (C) 2026 Jack Lloyd
 * (C) 2026 Falko Strenzke - cryptosource GmbH
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/module_lattice_keys.h>

namespace Botan {

Module_Lattice_PrivateKey::~Module_Lattice_PrivateKey() = default;

secure_vector<uint8_t> Module_Lattice_PrivateKey::private_key_bits() const {
   return formatted_private_key_bits(private_key_format());
}

secure_vector<uint8_t> Module_Lattice_PrivateKey::raw_private_key_bits() const {
   return formatted_raw_private_key_bits(private_key_format());
}

}  // namespace Botan
