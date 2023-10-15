/*
* Message Authentication Code base class
* (C) 1999-2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/mac.h>

#include <botan/exceptn.h>
#include <botan/mem_ops.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/scan_name.h>

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
   const SCAN_Name req(algo_spec);

#if defined(BOTAN_HAS_BLAKE2BMAC)
   if(req.algo_name() == "Blake2b" || req.algo_name() == "BLAKE2b") {
      return std::make_unique<BLAKE2bMAC>(req.arg_as_integer(0, 512));
   }
#endif

#if defined(BOTAN_HAS_GMAC)
   if(req.algo_name() == "GMAC" && req.arg_count() == 1) {
      if(provider.empty() || provider == "base") {
         if(auto bc = BlockCipher::create(req.arg(0))) {
            return std::make_unique<GMAC>(std::move(bc));
         }
      }
   }
#endif

#if defined(BOTAN_HAS_HMAC)
   if(req.algo_name() == "HMAC" && req.arg_count() == 1) {
      if(provider.empty() || provider == "base") {
         if(auto hash = HashFunction::create(req.arg(0))) {
            return std::make_unique<HMAC>(std::move(hash));
         }
      }
   }
#endif

#if defined(BOTAN_HAS_POLY1305)
   if(req.algo_name() == "Poly1305" && req.arg_count() == 0) {
      if(provider.empty() || provider == "base") {
         return std::make_unique<Poly1305>();
      }
   }
#endif

#if defined(BOTAN_HAS_SIPHASH)
   if(req.algo_name() == "SipHash") {
      if(provider.empty() || provider == "base") {
         return std::make_unique<SipHash>(req.arg_as_integer(0, 2), req.arg_as_integer(1, 4));
      }
   }
#endif

#if defined(BOTAN_HAS_CMAC)
   if((req.algo_name() == "CMAC" || req.algo_name() == "OMAC") && req.arg_count() == 1) {
      if(provider.empty() || provider == "base") {
         if(auto bc = BlockCipher::create(req.arg(0))) {
            return std::make_unique<CMAC>(std::move(bc));
         }
      }
   }
#endif

#if defined(BOTAN_HAS_ANSI_X919_MAC)
   if(req.algo_name() == "X9.19-MAC") {
      if(provider.empty() || provider == "base") {
         return std::make_unique<ANSI_X919_MAC>();
      }
   }
#endif

#if defined(BOTAN_HAS_KMAC)
   if(req.algo_name() == "KMAC-128") {
      if(provider.empty() || provider == "base") {
         if(req.arg_count() != 1) {
            throw Invalid_Argument(
               "invalid algorithm specification for KMAC-128: need exactly one argument for output bit length");
         }
         return std::make_unique<KMAC128>(req.arg_as_integer(0));
      }
   }

   if(req.algo_name() == "KMAC-256") {
      if(provider.empty() || provider == "base") {
         if(req.arg_count() != 1) {
            throw Invalid_Argument(
               "invalid algorithm specification for KMAC-256: need exactly one argument for output bit length");
         }
         return std::make_unique<KMAC256>(req.arg_as_integer(0));
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

void MessageAuthenticationCode::start_msg(std::span<const uint8_t> nonce) {
   BOTAN_UNUSED(nonce);
   if(!nonce.empty()) {
      throw Invalid_IV_Length(name(), nonce.size());
   }
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
