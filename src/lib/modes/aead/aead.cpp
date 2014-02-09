/*
* Interface for AEAD modes
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/aead.h>
#include <botan/block_cipher.h>
#include <botan/libstate.h>

#if defined(BOTAN_HAS_AEAD_CCM)
  #include <botan/ccm.h>
#endif

#if defined(BOTAN_HAS_AEAD_EAX)
  #include <botan/eax.h>
#endif

#if defined(BOTAN_HAS_AEAD_GCM)
  #include <botan/gcm.h>
#endif

#if defined(BOTAN_HAS_AEAD_SIV)
  #include <botan/siv.h>
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

   if(algo_parts.size() < 2)
      return nullptr;

   const std::string cipher_name = algo_parts[0];
   const BlockCipher* cipher = af.prototype_block_cipher(cipher_name);
   if(!cipher)
      return nullptr;

   const std::vector<std::string> mode_info = parse_algorithm_name(algo_parts[1]);

   if(mode_info.empty())
      return nullptr;

   const std::string mode_name = mode_info[0];

   const size_t tag_size = (mode_info.size() > 1) ? to_u32bit(mode_info[1]) : cipher->block_size();

#if defined(BOTAN_HAS_AEAD_CCM)
   if(mode_name == "CCM-8")
      {
      if(direction == ENCRYPTION)
         return new CCM_Encryption(cipher->clone(), 8, 3);
      else
         return new CCM_Decryption(cipher->clone(), 8, 3);
      }

   if(mode_name == "CCM" || mode_name == "CCM-8")
      {
      const size_t L = (mode_info.size() > 2) ? to_u32bit(mode_info[2]) : 3;

      if(direction == ENCRYPTION)
         return new CCM_Encryption(cipher->clone(), tag_size, L);
      else
         return new CCM_Decryption(cipher->clone(), tag_size, L);
      }
#endif

#if defined(BOTAN_HAS_AEAD_EAX)
   if(mode_name == "EAX")
      {
      if(direction == ENCRYPTION)
         return new EAX_Encryption(cipher->clone(), tag_size);
      else
         return new EAX_Decryption(cipher->clone(), tag_size);
      }
#endif

#if defined(BOTAN_HAS_AEAD_SIV)
   if(mode_name == "SIV")
      {
      BOTAN_ASSERT(tag_size == 16, "Valid tag size for SIV");
      if(direction == ENCRYPTION)
         return new SIV_Encryption(cipher->clone());
      else
         return new SIV_Decryption(cipher->clone());
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
