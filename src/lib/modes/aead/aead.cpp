/*
* (C) 2013,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/aead.h>
#include <botan/internal/mode_utils.h>
#include <botan/internal/algo_registry.h>

#if defined(BOTAN_HAS_AEAD_CCM)
  #include <botan/ccm.h>
#endif

#if defined(BOTAN_HAS_AEAD_CHACHA20_POLY1305)
  #include <botan/chacha20poly1305.h>
#endif

#if defined(BOTAN_HAS_AEAD_EAX)
  #include <botan/eax.h>
#endif

#if defined(BOTAN_HAS_AEAD_GCM)
  #include <botan/gcm.h>
#endif

#if defined(BOTAN_HAS_AEAD_OCB)
  #include <botan/ocb.h>
#endif

#if defined(BOTAN_HAS_AEAD_SIV)
  #include <botan/siv.h>
#endif

namespace Botan {

AEAD_Mode::~AEAD_Mode() {}

#if defined(BOTAN_HAS_AEAD_CCM)
BOTAN_REGISTER_BLOCK_CIPHER_MODE_LEN2(CCM_Encryption, CCM_Decryption, 16, 3);
#endif

#if defined(BOTAN_HAS_AEAD_CHACHA20_POLY1305)
BOTAN_REGISTER_T_NOARGS(Cipher_Mode, ChaCha20Poly1305_Encryption);
BOTAN_REGISTER_T_NOARGS(Cipher_Mode, ChaCha20Poly1305_Decryption);
#endif

#if defined(BOTAN_HAS_AEAD_EAX)
BOTAN_REGISTER_BLOCK_CIPHER_MODE_LEN(EAX_Encryption, EAX_Decryption, 0);
#endif

#if defined(BOTAN_HAS_AEAD_GCM)
BOTAN_REGISTER_BLOCK_CIPHER_MODE_LEN(GCM_Encryption, GCM_Decryption, 16);
#endif

#if defined(BOTAN_HAS_AEAD_OCB)
BOTAN_REGISTER_BLOCK_CIPHER_MODE_LEN(OCB_Encryption, OCB_Decryption, 16);
#endif

#if defined(BOTAN_HAS_AEAD_SIV)
BOTAN_REGISTER_BLOCK_CIPHER_MODE(SIV_Encryption, SIV_Decryption);
#endif

AEAD_Mode* get_aead(const std::string& algo_spec, Cipher_Dir direction)
   {
   std::unique_ptr<Cipher_Mode> mode(get_cipher_mode(algo_spec, direction));

   if(AEAD_Mode* aead = dynamic_cast<AEAD_Mode*>(mode.get()))
      {
      mode.release();
      return aead;
      }

   return nullptr;
   }

}
