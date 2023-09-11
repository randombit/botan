/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/sym_algo.h>

#include <botan/exceptn.h>

namespace Botan {

void SymmetricAlgorithm::throw_key_not_set_error() const {
   throw Key_Not_Set(name());
}

void SymmetricAlgorithm::set_key(std::span<const uint8_t> key) {
   if(!valid_keylength(key.size())) {
      throw Invalid_Key_Length(name(), key.size());
   }
   key_schedule(key);
}

}  // namespace Botan
