/*
* Extendable Output Function Base Class
* (C) 2023 Jack Lloyd
*     2023 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/xof.h>
#include <botan/internal/scan_name.h>

#if defined(BOTAN_HAS_SHAKE_XOF)
   #include <botan/internal/shake_xof.h>
#endif

#include <botan/exceptn.h>
#include <botan/internal/fmt.h>

namespace Botan {

//static
std::unique_ptr<XOF> XOF::create(std::string_view algo_spec, std::string_view provider) {
   const SCAN_Name req(algo_spec);

   if(!provider.empty() && provider != "base") {
      return nullptr;  // unknown provider
   }

#if defined(BOTAN_HAS_SHAKE_XOF)
   if(req.algo_name() == "SHAKE-128" && req.arg_count() == 0) {
      return std::make_unique<SHAKE_128_XOF>();
   }
   if(req.algo_name() == "SHAKE-256" && req.arg_count() == 0) {
      return std::make_unique<SHAKE_256_XOF>();
   }
#endif

   return nullptr;
}

//static
std::unique_ptr<XOF> XOF::create_or_throw(std::string_view algo_spec, std::string_view provider) {
   if(auto xof = XOF::create(algo_spec, provider)) {
      return xof;
   }
   throw Lookup_Error("XOF", algo_spec, provider);
}

// static
std::vector<std::string> XOF::providers(std::string_view algo_spec) {
   return probe_providers_of<XOF>(algo_spec, {"base"});
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

   m_xof_started = true;
   start_msg(salt, key);
}

void XOF::start_msg(std::span<const uint8_t> salt, std::span<const uint8_t> key) {
   BOTAN_UNUSED(salt, key);
}

}  // namespace Botan
