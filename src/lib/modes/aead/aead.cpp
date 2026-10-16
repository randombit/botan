/*
* (C) 2013,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/aead.h>

#include <botan/assert.h>
#include <botan/exceptn.h>
#include <botan/internal/algorithm_spec.h>

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

#if defined(BOTAN_HAS_AEAD_GCM_SIV)
   #include <botan/internal/gcm_siv.h>
#endif

#if defined(BOTAN_HAS_AEAD_OCB)
   #include <botan/internal/ocb.h>
#endif

#if defined(BOTAN_HAS_AEAD_SIV)
   #include <botan/internal/siv.h>
#endif

#if defined(BOTAN_HAS_ASCON_AEAD128)
   #include <botan/internal/ascon_aead128.h>
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

#if defined(BOTAN_HAS_ASCON_AEAD128)
   if(algo == "Ascon-AEAD128") {
      if(dir == Cipher_Dir::Encryption) {
         return std::make_unique<Ascon_AEAD128_Encryption>();
      } else {
         return std::make_unique<Ascon_AEAD128_Decryption>();
      }
   }
#endif

#if defined(BOTAN_HAS_BLOCK_CIPHER)
   const AlgorithmSpec req(algo, AlgorithmSpec::Syntax::CipherMode);

   #if defined(BOTAN_HAS_AEAD_CCM)
   if(auto m = req.match("CCM({cipher},{tag_len:int=16},{L:int=3})")) {
      if(auto bc = BlockCipher::create(m->str("cipher"), provider)) {
         const size_t tag_len = m->integer("tag_len");
         const size_t L_len = m->integer("L");
         if(dir == Cipher_Dir::Encryption) {
            return std::make_unique<CCM_Encryption>(std::move(bc), tag_len, L_len);
         } else {
            return std::make_unique<CCM_Decryption>(std::move(bc), tag_len, L_len);
         }
      }
   }
   #endif

   #if defined(BOTAN_HAS_AEAD_GCM)
   if(auto m = req.match("GCM({cipher},{tag_len:int=16})")) {
      if(auto bc = BlockCipher::create(m->str("cipher"), provider)) {
         const size_t tag_len = m->integer("tag_len");
         if(dir == Cipher_Dir::Encryption) {
            return std::make_unique<GCM_Encryption>(std::move(bc), tag_len);
         } else {
            return std::make_unique<GCM_Decryption>(std::move(bc), tag_len);
         }
      }
   }
   #endif

   #if defined(BOTAN_HAS_AEAD_GCM_SIV)
   // Unlike GCM the tag length is fixed, so reject eg "AES-128/GCM-SIV(12)"
   if(auto m = req.match("GCM-SIV({cipher})")) {
      if(auto bc = BlockCipher::create(m->str("cipher"), provider)) {
         if(dir == Cipher_Dir::Encryption) {
            return std::make_unique<GCM_SIV_Encryption>(std::move(bc));
         } else {
            return std::make_unique<GCM_SIV_Decryption>(std::move(bc));
         }
      }
   }
   #endif

   #if defined(BOTAN_HAS_AEAD_OCB)
   if(auto m = req.match("OCB({cipher},{tag_len:int=16})")) {
      if(auto bc = BlockCipher::create(m->str("cipher"), provider)) {
         const size_t tag_len = m->integer("tag_len");
         if(dir == Cipher_Dir::Encryption) {
            return std::make_unique<OCB_Encryption>(std::move(bc), tag_len);
         } else {
            return std::make_unique<OCB_Decryption>(std::move(bc), tag_len);
         }
      }
   }
   #endif

   #if defined(BOTAN_HAS_AEAD_EAX)
   if(auto m = req.match("EAX({cipher},{tag_len:int?})")) {
      if(auto bc = BlockCipher::create(m->str("cipher"), provider)) {
         const size_t tag_len = m->has("tag_len") ? m->integer("tag_len") : bc->block_size();
         if(dir == Cipher_Dir::Encryption) {
            return std::make_unique<EAX_Encryption>(std::move(bc), tag_len);
         } else {
            return std::make_unique<EAX_Decryption>(std::move(bc), tag_len);
         }
      }
   }
   #endif

   #if defined(BOTAN_HAS_AEAD_SIV)
   if(auto m = req.match("SIV({cipher})")) {
      if(auto bc = BlockCipher::create(m->str("cipher"), provider)) {
         if(dir == Cipher_Dir::Encryption) {
            return std::make_unique<SIV_Encryption>(std::move(bc));
         } else {
            return std::make_unique<SIV_Decryption>(std::move(bc));
         }
      }
   }
   #endif

   BOTAN_UNUSED(req);
#endif

   return std::unique_ptr<AEAD_Mode>();
}

}  // namespace Botan
