/*
* (C) 2013,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/aead.h>
#include <botan/scan_name.h>
#include <botan/parsing.h>
#include <sstream>

#if defined(BOTAN_HAS_BLOCK_CIPHER)
  #include <botan/block_cipher.h>
#endif

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

AEAD_Mode* get_aead(const std::string& algo, Cipher_Dir dir)
   {
#if defined(BOTAN_HAS_AEAD_CHACHA20_POLY1305)
   if(algo == "ChaCha20Poly1305")
      {
      if(dir == ENCRYPTION)
         return new ChaCha20Poly1305_Encryption;
      else
         return new ChaCha20Poly1305_Decryption;

      }
#endif

   if(algo.find('/') != std::string::npos)
      {
      const std::vector<std::string> algo_parts = split_on(algo, '/');
      const std::string cipher_name = algo_parts[0];
      const std::vector<std::string> mode_info = parse_algorithm_name(algo_parts[1]);

      if(mode_info.empty())
         return nullptr;

      std::ostringstream alg_args;

      alg_args << '(' << cipher_name;
      for(size_t i = 1; i < mode_info.size(); ++i)
         alg_args << ',' << mode_info[i];
      for(size_t i = 2; i < algo_parts.size(); ++i)
         alg_args << ',' << algo_parts[i];
      alg_args << ')';

      const std::string mode_name = mode_info[0] + alg_args.str();
      return get_aead(mode_name, dir);
      }

#if defined(BOTAN_HAS_BLOCK_CIPHER)

   SCAN_Name req(algo);

   if(req.arg_count() == 0)
      {
      return nullptr;
      }

   std::unique_ptr<BlockCipher> bc(BlockCipher::create(req.arg(0)));

   if(!bc)
      {
      return nullptr;
      }

#if defined(BOTAN_HAS_AEAD_CCM)
   if(req.algo_name() == "CCM")
      {
      size_t tag_len = req.arg_as_integer(1, 16);
      size_t L_len = req.arg_as_integer(2, 3);
      if(dir == ENCRYPTION)
         return new CCM_Encryption(bc.release(), tag_len, L_len);
      else
         return new CCM_Decryption(bc.release(), tag_len, L_len);
      }
#endif

#if defined(BOTAN_HAS_AEAD_GCM)
   if(req.algo_name() == "GCM")
      {
      size_t tag_len = req.arg_as_integer(1, 16);
      if(dir == ENCRYPTION)
         return new GCM_Encryption(bc.release(), tag_len);
      else
         return new GCM_Decryption(bc.release(), tag_len);
      }
#endif

#if defined(BOTAN_HAS_AEAD_OCB)
   if(req.algo_name() == "OCB")
      {
      size_t tag_len = req.arg_as_integer(1, 16);
      if(dir == ENCRYPTION)
         return new OCB_Encryption(bc.release(), tag_len);
      else
         return new OCB_Decryption(bc.release(), tag_len);
      }
#endif

#if defined(BOTAN_HAS_AEAD_EAX)
   if(req.algo_name() == "EAX")
      {
      size_t tag_len = req.arg_as_integer(1, bc->block_size());
      if(dir == ENCRYPTION)
         return new EAX_Encryption(bc.release(), tag_len);
      else
         return new EAX_Decryption(bc.release(), tag_len);
      }
#endif

#if defined(BOTAN_HAS_AEAD_SIV)
   if(req.algo_name() == "SIV")
      {
      if(dir == ENCRYPTION)
         return new SIV_Encryption(bc.release());
      else
         return new SIV_Decryption(bc.release());
      }
#endif

#endif

   return nullptr;
   }

}
