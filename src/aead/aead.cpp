/*
* Interface for AEAD modes
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/aead.h>
#include <botan/libstate.h>

#if defined(BOTAN_HAS_AEAD_EAX)
  #include <botan/eax.h>
#endif

#if defined(BOTAN_HAS_AEAD_GCM)
  #include <botan/gcm.h>
#endif

#if defined(BOTAN_HAS_AEAD_OCB)
  #include <botan/ocb.h>
#endif

namespace Botan {

AEAD_Mode* get_aead(const std::string& algo_spec, Cipher_Dir direction)
   {
   Algorithm_Factory& af = global_state().algorithm_factory();

   const std::vector<std::string> algo_parts = split_on(algo_spec, '/');
   if(algo_parts.empty())
      throw Invalid_Algorithm_Name(algo_spec);

   const std::string cipher_name = algo_parts[0];
   const std::string mode_name = algo_parts[1];

   const size_t tag_size = 16; // default for all current AEAD

   const BlockCipher* cipher = af.prototype_block_cipher(cipher_name);
   if(!cipher)
      return nullptr;

#if defined(BOTAN_HAS_AEAD_EAX)
   if(mode_name == "EAX")
      {
      if(direction == ENCRYPTION)
         return new EAX_Encryption(cipher->clone(), tag_size);
      else
         return new EAX_Decryption(cipher->clone(), tag_size);
      }
#endif

#if defined(BOTAN_HAS_AEAD_GCM)
   if(mode_name == "GCM")
      {
      if(direction == ENCRYPTION)
         return new GCM_Encryption(cipher->clone(), tag_size);
      else
         return new GCM_Decryption(cipher->clone(), tag_size);
      }
#endif

#if defined(BOTAN_HAS_AEAD_OCB)
   if(mode_name == "OCB")
      {
      if(direction == ENCRYPTION)
         return new OCB_Encryption(cipher->clone(), tag_size);
      else
         return new OCB_Decryption(cipher->clone(), tag_size);
      }
#endif

   return nullptr;
   }

}
