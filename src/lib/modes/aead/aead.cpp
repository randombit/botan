/*
* (C) 2013,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/aead.h>

#include <botan/internal/parsing.h>
#include <botan/internal/scan_name.h>
#include <sstream>

#if defined(BOTAN_HAS_BLOCK_CIPHER)
   #include <botan/block_cipher.h>
#endif

#if defined(BOTAN_HAS_AEAD_CCM)
   #include <botan/internal/ccm.h>
#endif

#if defined(BOTAN_HAS_AEAD_CHACHA20_POLY1305)
   #include <botan/internal/chacha20poly1305.h>
#endif

#if defined(BOTAN_HAS_AEAD_EAX)
   #include <botan/internal/eax.h>
#endif

#if defined(BOTAN_HAS_AEAD_GCM)
   #include <botan/internal/gcm.h>
#endif

#if defined(BOTAN_HAS_AEAD_OCB)
   #include <botan/internal/ocb.h>
#endif

#if defined(BOTAN_HAS_AEAD_SIV)
   #include <botan/internal/siv.h>
#endif

namespace Botan {

std::unique_ptr<AEAD_Mode> AEAD_Mode::create_or_throw(std::string_view algo,
                                                      Cipher_Dir dir,
                                                      std::string_view provider) {
   if(auto aead = AEAD_Mode::create(algo, dir, provider)) {
      return aead;
   }

   throw Lookup_Error("AEAD", algo, provider);
}

std::unique_ptr<AEAD_Mode> AEAD_Mode::create(std::string_view algo, Cipher_Dir dir, std::string_view provider) {
   BOTAN_UNUSED(provider);
#if defined(BOTAN_HAS_AEAD_CHACHA20_POLY1305)
   if(algo == "ChaCha20Poly1305") {
      if(dir == Cipher_Dir::Encryption) {
         return std::make_unique<ChaCha20Poly1305_Encryption>();
      } else {
         return std::make_unique<ChaCha20Poly1305_Decryption>();
      }
   }
#endif

   if(algo.find('/') != std::string::npos) {
      const std::vector<std::string> algo_parts = split_on(algo, '/');
      std::string_view cipher_name = algo_parts[0];
      const std::vector<std::string> mode_info = parse_algorithm_name(algo_parts[1]);

      if(mode_info.empty()) {
         return std::unique_ptr<AEAD_Mode>();
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

      return AEAD_Mode::create(mode_name.str(), dir);
   }

#if defined(BOTAN_HAS_BLOCK_CIPHER)

   SCAN_Name req(algo);

   if(req.arg_count() == 0) {
      return std::unique_ptr<AEAD_Mode>();
   }

   auto bc = BlockCipher::create(req.arg(0), provider);

   if(!bc) {
      return std::unique_ptr<AEAD_Mode>();
   }

   #if defined(BOTAN_HAS_AEAD_CCM)
   if(req.algo_name() == "CCM") {
      size_t tag_len = req.arg_as_integer(1, 16);
      size_t L_len = req.arg_as_integer(2, 3);
      if(dir == Cipher_Dir::Encryption) {
         return std::make_unique<CCM_Encryption>(std::move(bc), tag_len, L_len);
      } else {
         return std::make_unique<CCM_Decryption>(std::move(bc), tag_len, L_len);
      }
   }
   #endif

   #if defined(BOTAN_HAS_AEAD_GCM)
   if(req.algo_name() == "GCM") {
      size_t tag_len = req.arg_as_integer(1, 16);
      if(dir == Cipher_Dir::Encryption) {
         return std::make_unique<GCM_Encryption>(std::move(bc), tag_len);
      } else {
         return std::make_unique<GCM_Decryption>(std::move(bc), tag_len);
      }
   }
   #endif

   #if defined(BOTAN_HAS_AEAD_OCB)
   if(req.algo_name() == "OCB") {
      size_t tag_len = req.arg_as_integer(1, 16);
      if(dir == Cipher_Dir::Encryption) {
         return std::make_unique<OCB_Encryption>(std::move(bc), tag_len);
      } else {
         return std::make_unique<OCB_Decryption>(std::move(bc), tag_len);
      }
   }
   #endif

   #if defined(BOTAN_HAS_AEAD_EAX)
   if(req.algo_name() == "EAX") {
      size_t tag_len = req.arg_as_integer(1, bc->block_size());
      if(dir == Cipher_Dir::Encryption) {
         return std::make_unique<EAX_Encryption>(std::move(bc), tag_len);
      } else {
         return std::make_unique<EAX_Decryption>(std::move(bc), tag_len);
      }
   }
   #endif

   #if defined(BOTAN_HAS_AEAD_SIV)
   if(req.algo_name() == "SIV") {
      if(dir == Cipher_Dir::Encryption) {
         return std::make_unique<SIV_Encryption>(std::move(bc));
      } else {
         return std::make_unique<SIV_Decryption>(std::move(bc));
      }
   }
   #endif

#endif

   return std::unique_ptr<AEAD_Mode>();
}

}  // namespace Botan
