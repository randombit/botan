/*************************************************
* Default Engine Source File                     *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/eng_def.h>
#include <botan/parsing.h>
#include <botan/filters.h>
#include <botan/lookup.h>
#include <botan/ecb.h>
#include <botan/cbc.h>
#include <botan/cts.h>
#include <botan/cfb.h>
#include <botan/ofb.h>
#include <botan/ctr.h>
#include <botan/eax.h>

namespace Botan {

/*************************************************
* Get a cipher object                            *
*************************************************/
Engine::Keyed_Filter_Ptr
Default_Engine::get_cipher(const std::string& algo_spec,
                           Cipher_Dir direction)
   {

   std::vector<std::string> algo_parts = split_on(algo_spec, '/');
   if(algo_parts.empty())
      throw Invalid_Algorithm_Name(algo_spec);

   const std::string cipher = algo_parts[0];

   if(have_stream_cipher(cipher))
      {
      if(algo_parts.size() == 1)
        return create_shared_ptr<StreamCipher_Filter>(cipher);
      return Engine::Keyed_Filter_Ptr();
      }
   else if(have_block_cipher(cipher))
      {
      if(algo_parts.size() != 2 && algo_parts.size() != 3)
         return Engine::Keyed_Filter_Ptr();

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
         return Engine::Keyed_Filter_Ptr();
      else if((mode != "CBC" && mode != "ECB") && padding != "NoPadding")
         throw Invalid_Algorithm_Name(algo_spec);

      if(mode == "OFB")
        return create_shared_ptr<OFB>(cipher);
      else if(mode == "CTR-BE")
        return create_shared_ptr<CTR_BE>(cipher);
      else if(mode == "ECB" || mode == "CBC" || mode == "CTS" ||
              mode == "CFB" || mode == "EAX")
         {
         if(mode == "ECB")
            {
            if(direction == ENCRYPTION)
               return create_shared_ptr<ECB_Encryption>(cipher, padding);
            else
               return create_shared_ptr<ECB_Decryption>(cipher, padding);
            }
         else if(mode == "CFB")
            {
            if(direction == ENCRYPTION)
               return create_shared_ptr<CFB_Encryption>(cipher, bits);
            else
               return create_shared_ptr<CFB_Decryption>(cipher, bits);
            }
         else if(mode == "CBC")
            {
            if(padding == "CTS")
               {
               if(direction == ENCRYPTION)
                  return create_shared_ptr<CTS_Encryption>(cipher);
               else
                  return create_shared_ptr<CTS_Decryption>(cipher);
               }
            if(direction == ENCRYPTION)
               return create_shared_ptr<CBC_Encryption>(cipher, padding);
            else
               return create_shared_ptr<CBC_Decryption>(cipher, padding);
            }
         else if(mode == "EAX")
            {
            if(direction == ENCRYPTION)
               return create_shared_ptr<EAX_Encryption>(cipher, bits);
            else
               return create_shared_ptr<EAX_Decryption>(cipher, bits);
            }
         else
            throw Internal_Error("get_mode: " + cipher + "/"
                                              + mode + "/" + padding);
         }
      else
         return Engine::Keyed_Filter_Ptr();
      }

   return Engine::Keyed_Filter_Ptr();
   }

}
