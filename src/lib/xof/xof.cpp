/*
* Extendable Output Function Base Class
* (C) 2023 Jack Lloyd
*     2023 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/xof.h>

#include <botan/exceptn.h>
#include <botan/internal/fmt.h>

namespace Botan {

//static
std::unique_ptr<XOF> XOF::create(std::string_view algo_spec, std::string_view provider) {
   BOTAN_UNUSED(algo_spec, provider);
   return nullptr;
}

//static
std::unique_ptr<XOF> XOF::create_or_throw(std::string_view algo_spec, std::string_view provider) {
   BOTAN_UNUSED(algo_spec, provider);
   throw Not_Implemented("No XOFs implemented so far");
}

// static
std::vector<std::string> XOF::providers(std::string_view algo_spec) {
   BOTAN_UNUSED(algo_spec);
   return {};
}

std::string XOF::provider() const {
   return "base";
}

void XOF::start(std::span<const uint8_t> salt, std::span<const uint8_t> key) {
   if(!key_spec().valid_keylength(key.size())) {
      throw Invalid_Key_Length(name(), key.size());
   }

   if(!valid_salt_length(salt.size())) {
      throw Invalid_Argument(fmt("{} cannot accept a salt length of {}", name(), salt.size()));
   }

   start_msg(salt, key);
}

void XOF::start_msg(std::span<const uint8_t> salt, std::span<const uint8_t> key) {
   BOTAN_UNUSED(salt, key);
}

}  // namespace Botan
