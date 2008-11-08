/*************************************************
* Default Engine Source File                     *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/def_eng.h>
#include <botan/parsing.h>
#include <botan/filters.h>
#include <botan/lookup.h>

#if defined(BOTAN_HAS_ECB)
  #include <botan/ecb.h>
#endif

#if defined(BOTAN_HAS_CBC)
  #include <botan/cbc.h>
#endif

#if defined(BOTAN_HAS_CTS)
  #include <botan/cts.h>
#endif

#if defined(BOTAN_HAS_CFB)
  #include <botan/cfb.h>
#endif

#if defined(BOTAN_HAS_OFB)
  #include <botan/ofb.h>
#endif

#if defined(BOTAN_HAS_CTR)
  #include <botan/ctr.h>
#endif

#if defined(BOTAN_HAS_EAX)
  #include <botan/eax.h>
#endif

namespace Botan {

/*************************************************
* Get a cipher object                            *
*************************************************/
Keyed_Filter* Default_Engine::get_cipher(const std::string& algo_spec,
                                         Cipher_Dir direction)
   {
   std::vector<std::string> algo_parts = split_on(algo_spec, '/');
   if(algo_parts.empty())
      throw Invalid_Algorithm_Name(algo_spec);

   const std::string cipher = algo_parts[0];

   if(have_stream_cipher(cipher))
      {
      if(algo_parts.size() == 1)
         return new StreamCipher_Filter(cipher);
      return 0;
      }
   else if(have_block_cipher(cipher))
      {
      if(algo_parts.size() != 2 && algo_parts.size() != 3)
         return 0;

      std::string mode = algo_parts[1];
      u32bit bits = 0;

      if(mode.find("CFB") != std::string::npos ||
         mode.find("EAX") != std::string::npos)
         {
         std::vector<std::string> algo_info = parse_algorithm_name(mode);
         mode = algo_info[0];
         if(algo_info.size() == 1)
            bits = 8*block_size_of(cipher);
         else if(algo_info.size() == 2)
            bits = to_u32bit(algo_info[1]);
         else
            throw Invalid_Algorithm_Name(algo_spec);
         }

      std::string padding;
      if(algo_parts.size() == 3)
         padding = algo_parts[2];
      else
         padding = (mode == "CBC") ? "PKCS7" : "NoPadding";

      if(mode == "ECB" && padding == "CTS")
         return 0;
      else if((mode != "CBC" && mode != "ECB") && padding != "NoPadding")
         throw Invalid_Algorithm_Name(algo_spec);

      if(mode == "OFB")
         {
#if defined(BOTAN_HAS_OFB)
         return new OFB(get_block_cipher(cipher));
#else
         return 0;
#endif
         }
      else if(mode == "CTR-BE")
         {
#if defined(BOTAN_HAS_CTR)
         return new CTR_BE(get_block_cipher(cipher));
#else
         return 0;
#endif
         }
      else if(mode == "ECB" || mode == "CBC" || mode == "CTS" ||
              mode == "CFB" || mode == "EAX")
         {
         if(mode == "ECB")
            {
#if defined(BOTAN_HAS_ECB)
            if(direction == ENCRYPTION)
               return new ECB_Encryption(get_block_cipher(cipher),
                                         get_bc_pad(padding));
            else
               return new ECB_Decryption(get_block_cipher(cipher),
                                         get_bc_pad(padding));

#else
            return 0;
#endif
            }
         else if(mode == "CFB")
            {
#if defined(BOTAN_HAS_CFB)
            if(direction == ENCRYPTION)
               return new CFB_Encryption(get_block_cipher(cipher), bits);
            else
               return new CFB_Decryption(get_block_cipher(cipher), bits);
#else
            return 0;
#endif
            }
         else if(mode == "CBC")
            {
            if(padding == "CTS")
               {
#if defined(BOTAN_HAS_CTS)
               if(direction == ENCRYPTION)
                  return new CTS_Encryption(get_block_cipher(cipher));
               else
                  return new CTS_Decryption(get_block_cipher(cipher));
#else
               return 0;
#endif
               }

#if defined(BOTAN_HAS_CBC)
            if(direction == ENCRYPTION)
               return new CBC_Encryption(get_block_cipher(cipher),
                                         get_bc_pad(padding));
            else
               return new CBC_Decryption(get_block_cipher(cipher),
                                         get_bc_pad(padding));
#else
            return 0;
#endif
            }
         else if(mode == "EAX")
            {
#if defined(BOTAN_HAS_EAX)
            if(direction == ENCRYPTION)
               return new EAX_Encryption(get_block_cipher(cipher), bits);
            else
               return new EAX_Decryption(get_block_cipher(cipher), bits);
#else
            return 0;
#endif
            }
         else
            throw Internal_Error("get_mode: " + cipher + "/"
                                              + mode + "/" + padding);
         }
      else
         return 0;
      }

   return 0;
   }

}
