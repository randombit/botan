/*
* Message Authentication Code base class
* (C) 1999-2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/mac.h>

#include <botan/exceptn.h>
#include <botan/internal/algorithm_spec.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/probe_providers.h>

#if defined(BOTAN_HAS_CMAC)
   #include <botan/internal/cmac.h>
#endif

#if defined(BOTAN_HAS_GMAC)
   #include <botan/block_cipher.h>
   #include <botan/internal/gmac.h>
#endif

#if defined(BOTAN_HAS_HMAC)
   #include <botan/hash.h>
   #include <botan/internal/hmac.h>
#endif

#if defined(BOTAN_HAS_POLY1305)
   #include <botan/internal/poly1305.h>
#endif

#if defined(BOTAN_HAS_SIPHASH)
   #include <botan/internal/siphash.h>
#endif

#if defined(BOTAN_HAS_ANSI_X919_MAC)
   #include <botan/internal/x919_mac.h>
#endif

#if defined(BOTAN_HAS_BLAKE2BMAC)
   #include <botan/internal/blake2bmac.h>
#endif

#if defined(BOTAN_HAS_KMAC)
   #include <botan/internal/kmac.h>
#endif

namespace Botan {

std::unique_ptr<MessageAuthenticationCode> MessageAuthenticationCode::create(std::string_view algo_spec,
                                                                             std::string_view provider) {
   const AlgorithmSpec req(algo_spec);

#if defined(BOTAN_HAS_BLAKE2BMAC)
   if(auto m = req.match("BLAKE2b|Blake2b({bits:int=512})")) {
      if(provider.empty() || provider == "base") {
         return std::make_unique<BLAKE2bMAC>(m->integer("bits"));
      }
   }
#endif

#if defined(BOTAN_HAS_GMAC)
   if(auto m = req.match("GMAC({cipher})")) {
      if(provider.empty() || provider == "base") {
         if(auto bc = BlockCipher::create(m->str("cipher"))) {
            return std::make_unique<GMAC>(std::move(bc));
         }
      }
   }
#endif

#if defined(BOTAN_HAS_HMAC)
   if(auto m = req.match("HMAC({hash})")) {
      if(provider.empty() || provider == "base") {
         if(auto hash = HashFunction::create(m->str("hash"))) {
            return std::make_unique<HMAC>(std::move(hash));
         }
      }
   }
#endif

#if defined(BOTAN_HAS_POLY1305)
   if(req.matches("Poly1305")) {
      if(provider.empty() || provider == "base") {
         return std::make_unique<Poly1305>();
      }
   }
#endif

#if defined(BOTAN_HAS_SIPHASH)
   if(auto m = req.match("SipHash({c:int=2},{d:int=4})")) {
      if(provider.empty() || provider == "base") {
         return std::make_unique<SipHash>(m->integer("c"), m->integer("d"));
      }
   }
#endif

#if defined(BOTAN_HAS_CMAC)
   if(auto m = req.match("CMAC|OMAC({cipher})")) {
      if(provider.empty() || provider == "base") {
         if(auto bc = BlockCipher::create(m->str("cipher"))) {
            return std::make_unique<CMAC>(std::move(bc));
         }
      }
   }
#endif

#if defined(BOTAN_HAS_ANSI_X919_MAC)
   if(req.matches("X9.19-MAC")) {
      if(provider.empty() || provider == "base") {
         return std::make_unique<ANSI_X919_MAC>();
      }
   }
#endif

#if defined(BOTAN_HAS_KMAC)
   if(auto m = req.match("KMAC-128({bits:int})")) {
      if(provider.empty() || provider == "base") {
         return std::make_unique<KMAC128>(m->integer("bits"));
      }
   }

   if(auto m = req.match("KMAC-256({bits:int})")) {
      if(provider.empty() || provider == "base") {
         return std::make_unique<KMAC256>(m->integer("bits"));
      }
   }
#endif

   BOTAN_UNUSED(req);
   BOTAN_UNUSED(provider);

   return nullptr;
}

std::vector<std::string> MessageAuthenticationCode::providers(std::string_view algo_spec) {
   return probe_providers_of<MessageAuthenticationCode>(algo_spec);
}

//static
std::unique_ptr<MessageAuthenticationCode> MessageAuthenticationCode::create_or_throw(std::string_view algo,
                                                                                      std::string_view provider) {
   if(auto mac = MessageAuthenticationCode::create(algo, provider)) {
      return mac;
   }
   throw Lookup_Error("MAC", algo, provider);
}

/*
* Default (deterministic) MAC verification operation
*/
bool MessageAuthenticationCode::verify_mac_result(std::span<const uint8_t> mac) {
   secure_vector<uint8_t> our_mac = final();

   if(our_mac.size() != mac.size()) {
      return false;
   }

   return CT::is_equal(our_mac.data(), mac.data(), mac.size()).as_bool();
}

}  // namespace Botan
