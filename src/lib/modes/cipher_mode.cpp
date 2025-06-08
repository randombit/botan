/*
* Cipher Modes
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/cipher_mode.h>

#include <botan/internal/parsing.h>
#include <botan/internal/scan_name.h>
#include <botan/internal/stream_mode.h>
#include <sstream>

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

#if defined(BOTAN_HAS_STREAM_CIPHER)
   if(auto sc = StreamCipher::create(algo)) {
      return std::make_unique<Stream_Cipher_Mode>(std::move(sc));
   }
#endif

#if defined(BOTAN_HAS_AEAD_MODES)
   if(auto aead = AEAD_Mode::create(algo, direction)) {
      return aead;
   }
#endif

   if(algo.find('/') != std::string::npos) {
      const std::vector<std::string> algo_parts = split_on(algo, '/');
      std::string_view cipher_name = algo_parts[0];
      const std::vector<std::string> mode_info = parse_algorithm_name(algo_parts[1]);

      if(mode_info.empty()) {
         return std::unique_ptr<Cipher_Mode>();
      }

      std::ostringstream mode_name;

      mode_name << mode_info[0] << '(' << cipher_name;
      for(size_t i = 1; i < mode_info.size(); ++i) {
         mode_name << ',' << mode_info[i];
      }
      for(size_t i = 2; i < algo_parts.size(); ++i) {
         mode_name << ',' << algo_parts[i];
      }
      mode_name << ')';

      return Cipher_Mode::create(mode_name.str(), direction, provider);
   }

#if defined(BOTAN_HAS_BLOCK_CIPHER)

   SCAN_Name spec(algo);

   if(spec.arg_count() == 0) {
      return std::unique_ptr<Cipher_Mode>();
   }

   auto bc = BlockCipher::create(spec.arg(0), provider);

   if(!bc) {
      return std::unique_ptr<Cipher_Mode>();
   }

   #if defined(BOTAN_HAS_MODE_CBC)
   if(spec.algo_name() == "CBC") {
      const std::string padding = spec.arg(1, "PKCS7");

      if(padding == "CTS") {
         if(direction == Cipher_Dir::Encryption) {
            return std::make_unique<CTS_Encryption>(std::move(bc));
         } else {
            return std::make_unique<CTS_Decryption>(std::move(bc));
         }
      } else {
         auto pad = BlockCipherModePaddingMethod::create(padding);

         if(pad) {
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
   if(spec.algo_name() == "XTS") {
      if(direction == Cipher_Dir::Encryption) {
         return std::make_unique<XTS_Encryption>(std::move(bc));
      } else {
         return std::make_unique<XTS_Decryption>(std::move(bc));
      }
   }
   #endif

   #if defined(BOTAN_HAS_MODE_CFB)
   if(spec.algo_name() == "CFB") {
      const size_t feedback_bits = spec.arg_as_integer(1, 8 * bc->block_size());
      if(direction == Cipher_Dir::Encryption) {
         return std::make_unique<CFB_Encryption>(std::move(bc), feedback_bits);
      } else {
         return std::make_unique<CFB_Decryption>(std::move(bc), feedback_bits);
      }
   }
   #endif

#endif

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
