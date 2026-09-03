/*
* Cipher Modes
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/cipher_mode.h>

#include <botan/exceptn.h>
#include <botan/internal/algorithm_spec.h>
#include <botan/internal/stream_mode.h>
#include <memory>
#include <utility>

#if defined(BOTAN_HAS_BLOCK_CIPHER)
   #include <botan/block_cipher.h>
#endif

#if defined(BOTAN_HAS_AEAD_MODES)
   #include <botan/aead.h>
#endif

#if defined(BOTAN_HAS_MODE_CBC)
   #include <botan/internal/cbc.h>
#endif

#if defined(BOTAN_HAS_MODE_CFB)
   #include <botan/internal/cfb.h>
#endif

#if defined(BOTAN_HAS_MODE_XTS)
   #include <botan/internal/xts.h>
#endif

#if defined(BOTAN_HAS_COMMONCRYPTO)
   #include <botan/internal/commoncrypto.h>
#endif

namespace Botan {

std::unique_ptr<Cipher_Mode> Cipher_Mode::create_or_throw(std::string_view algo,
                                                          Cipher_Dir direction,
                                                          std::string_view provider) {
   if(auto mode = Cipher_Mode::create(algo, direction, provider)) {
      return mode;
   }

   throw Lookup_Error("Cipher mode", algo, provider);
}

std::unique_ptr<Cipher_Mode> Cipher_Mode::create(std::string_view algo,
                                                 Cipher_Dir direction,
                                                 std::string_view provider) {
#if defined(BOTAN_HAS_COMMONCRYPTO)
   if(provider.empty() || provider == "commoncrypto") {
      if(auto cm = make_commoncrypto_cipher_mode(algo, direction))
         return cm;

      if(!provider.empty())
         return nullptr;
   }
#endif

   if(provider != "base" && !provider.empty()) {
      return nullptr;
   }

   const AlgorithmSpec spec(algo, AlgorithmSpec::Syntax::CipherMode);

#if defined(BOTAN_HAS_STREAM_CIPHER)
   // Stream ciphers such as CTR and OFB are also accepted in mode form, eg "AES-128/CTR-BE"
   if(auto sc = StreamCipher::create(spec.canonical_form())) {
      return std::make_unique<Stream_Cipher_Mode>(std::move(sc));
   }
#endif

#if defined(BOTAN_HAS_AEAD_MODES)
   if(auto aead = AEAD_Mode::create(algo, direction)) {
      return aead;
   }
#endif

#if defined(BOTAN_HAS_BLOCK_CIPHER)
   #if defined(BOTAN_HAS_MODE_CBC)
   if(auto m = spec.match("CBC({cipher},{padding:str=PKCS7})")) {
      if(auto bc = BlockCipher::create(m->str("cipher"), provider)) {
         const auto padding = m->str("padding");

         if(padding == "CTS") {
            if(direction == Cipher_Dir::Encryption) {
               return std::make_unique<CTS_Encryption>(std::move(bc));
            } else {
               return std::make_unique<CTS_Decryption>(std::move(bc));
            }
         } else if(auto pad = BlockCipherModePaddingMethod::create(padding)) {
            if(direction == Cipher_Dir::Encryption) {
               return std::make_unique<CBC_Encryption>(std::move(bc), std::move(pad));
            } else {
               return std::make_unique<CBC_Decryption>(std::move(bc), std::move(pad));
            }
         }
      }
   }
   #endif

   #if defined(BOTAN_HAS_MODE_XTS)
   if(auto m = spec.match("XTS({cipher})")) {
      if(auto bc = BlockCipher::create(m->str("cipher"), provider)) {
         if(direction == Cipher_Dir::Encryption) {
            return std::make_unique<XTS_Encryption>(std::move(bc));
         } else {
            return std::make_unique<XTS_Decryption>(std::move(bc));
         }
      }
   }
   #endif

   #if defined(BOTAN_HAS_MODE_CFB)
   if(auto m = spec.match("CFB({cipher},{feedback_bits:int?})")) {
      if(auto bc = BlockCipher::create(m->str("cipher"), provider)) {
         const size_t feedback_bits = m->has("feedback_bits") ? m->integer("feedback_bits") : 8 * bc->block_size();
         if(direction == Cipher_Dir::Encryption) {
            return std::make_unique<CFB_Encryption>(std::move(bc), feedback_bits);
         } else {
            return std::make_unique<CFB_Decryption>(std::move(bc), feedback_bits);
         }
      }
   }
   #endif

#endif

   BOTAN_UNUSED(spec);

   return std::unique_ptr<Cipher_Mode>();
}

//static
std::vector<std::string> Cipher_Mode::providers(std::string_view algo_spec) {
   const std::vector<std::string>& possible = {"base", "commoncrypto"};
   std::vector<std::string> providers;
   for(auto&& prov : possible) {
      auto mode = Cipher_Mode::create(algo_spec, Cipher_Dir::Encryption, prov);
      if(mode) {
         providers.push_back(prov);  // available
      }
   }
   return providers;
}

}  // namespace Botan
