/*
* Cipher Modes
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/cipher_mode.h>
#include <botan/stream_mode.h>
#include <botan/scan_name.h>
#include <sstream>

#if defined(BOTAN_HAS_BLOCK_CIPHER)
  #include <botan/block_cipher.h>
#endif

#if defined(BOTAN_HAS_AEAD_MODES)
  #include <botan/aead.h>
#endif

#if defined(BOTAN_HAS_MODE_CBC)
  #include <botan/cbc.h>
#endif

#if defined(BOTAN_HAS_MODE_CFB)
  #include <botan/cfb.h>
#endif

#if defined(BOTAN_HAS_MODE_XTS)
  #include <botan/xts.h>
#endif

#if defined(BOTAN_HAS_MODE_XTS)
  #include <botan/xts.h>
#endif

namespace Botan {

Cipher_Mode* get_cipher_mode(const std::string& algo, Cipher_Dir direction)
   {
   if(auto sc = StreamCipher::create(algo))
      {
      return new Stream_Cipher_Mode(sc.release());
      }

#if defined(BOTAN_HAS_AEAD_MODES)
   if(auto aead = get_aead(algo, direction))
      {
      return aead;
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
      return get_cipher_mode(mode_name, direction);
      }

#if defined(BOTAN_HAS_BLOCK_CIPHER)

   SCAN_Name spec(algo);

   if(spec.arg_count() == 0)
      {
      return nullptr;
      }

   std::unique_ptr<BlockCipher> bc(BlockCipher::create(spec.arg(0)));

   if(!bc)
      {
      return nullptr;
      }

#if defined(BOTAN_HAS_MODE_CBC)
   if(spec.algo_name() == "CBC")
      {
      const std::string padding = spec.arg(1, "PKCS7");

      if(padding == "CTS")
         {
         if(direction == ENCRYPTION)
            return new CTS_Encryption(bc.release());
         else
            return new CTS_Decryption(bc.release());
         }
      else
         {
         std::unique_ptr<BlockCipherModePaddingMethod> pad(get_bc_pad(padding));

         if(pad)
            {
            if(direction == ENCRYPTION)
               return new CBC_Encryption(bc.release(), pad.release());
            else
               return new CBC_Decryption(bc.release(), pad.release());
            }
         }
      }
#endif

#if defined(BOTAN_HAS_MODE_XTS)
   if(spec.algo_name() == "XTS")
      {
      if(direction == ENCRYPTION)
         return new XTS_Encryption(bc.release());
      else
         return new XTS_Decryption(bc.release());
      }
#endif

#if defined(BOTAN_HAS_MODE_CFB)
   if(spec.algo_name() == "CFB")
      {
      const size_t feedback_bits = spec.arg_as_integer(1, 8*bc->block_size());
      if(direction == ENCRYPTION)
         return new CFB_Encryption(bc.release(), feedback_bits);
      else
         return new CFB_Decryption(bc.release(), feedback_bits);
      }
#endif

#endif

   return nullptr;
   }

}
