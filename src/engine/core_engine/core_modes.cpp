/*
* Core Engine
* (C) 1999-2007,2011 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/core_engine.h>
#include <botan/parsing.h>
#include <botan/filters.h>
#include <botan/algo_factory.h>
#include <botan/mode_pad.h>
#include <memory>

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

#if defined(BOTAN_HAS_CTR_BE)
  #include <botan/ctr.h>
#endif

#if defined(BOTAN_HAS_EAX)
  #include <botan/eax.h>
#endif

#if defined(BOTAN_HAS_XTS)
  #include <botan/xts.h>
#endif

namespace Botan {

namespace {

/**
* Get a block cipher padding method by name
*/
BlockCipherModePaddingMethod* get_bc_pad(const std::string& algo_spec,
                                         const std::string& def_if_empty)
   {
#if defined(BOTAN_HAS_CIPHER_MODE_PADDING)
   if(algo_spec == "NoPadding" || (algo_spec == "" && def_if_empty == "NoPadding"))
      return new Null_Padding;

   if(algo_spec == "PKCS7" || (algo_spec == "" && def_if_empty == "PKCS7"))
      return new PKCS7_Padding;

   if(algo_spec == "OneAndZeros")
      return new OneAndZeros_Padding;

   if(algo_spec == "X9.23")
      return new ANSI_X923_Padding;

#endif

   throw Algorithm_Not_Found(algo_spec);
   }

}

Keyed_Filter* get_cipher_mode(const BlockCipher* block_cipher,
                              Cipher_Dir direction,
                              const std::string& mode,
                              const std::string& padding)
   {
#if defined(BOTAN_HAS_OFB)
   if(mode == "OFB")
      return new StreamCipher_Filter(new OFB(block_cipher->clone()));
#endif

#if defined(BOTAN_HAS_CTR_BE)
   if(mode == "CTR-BE")
      return new StreamCipher_Filter(new CTR_BE(block_cipher->clone()));
#endif

#if defined(BOTAN_HAS_ECB)
   if(mode == "ECB" || mode == "")
      {
      if(direction == ENCRYPTION)
         return new ECB_Encryption(block_cipher->clone(),
                                   get_bc_pad(padding, "NoPadding"));
      else
         return new ECB_Decryption(block_cipher->clone(),
                                   get_bc_pad(padding, "NoPadding"));
      }
#endif

   if(mode == "CBC")
      {
      if(padding == "CTS")
         {
#if defined(BOTAN_HAS_CTS)
         if(direction == ENCRYPTION)
            return new CTS_Encryption(block_cipher->clone());
         else
            return new CTS_Decryption(block_cipher->clone());
#else
         return 0;
#endif
         }

#if defined(BOTAN_HAS_CBC)
      if(direction == ENCRYPTION)
         return new CBC_Encryption(block_cipher->clone(),
                                   get_bc_pad(padding, "PKCS7"));
      else
         return new CBC_Decryption(block_cipher->clone(),
                                   get_bc_pad(padding, "PKCS7"));
#else
      return 0;
#endif
      }

#if defined(BOTAN_HAS_XTS)
   if(mode == "XTS")
      {
      if(direction == ENCRYPTION)
         return new XTS_Encryption(block_cipher->clone());
      else
         return new XTS_Decryption(block_cipher->clone());
      }
#endif

   if(mode.find("CFB") != std::string::npos ||
      mode.find("EAX") != std::string::npos)
      {
      size_t bits = 0;

      std::vector<std::string> algo_info = parse_algorithm_name(mode);
      std::string mode_name = algo_info[0];
      if(algo_info.size() == 1)
         bits = 8 * block_cipher->block_size();
      else if(algo_info.size() == 2)
         bits = to_u32bit(algo_info[1]);
      else
         return 0;

#if defined(BOTAN_HAS_CFB)
      if(mode_name == "CFB")
         {
         if(direction == ENCRYPTION)
            return new CFB_Encryption(block_cipher->clone(), bits);
         else
            return new CFB_Decryption(block_cipher->clone(), bits);
         }
#endif

#if defined(BOTAN_HAS_EAX)
      if(mode_name == "EAX")
         {
         if(direction == ENCRYPTION)
            return new EAX_Encryption(block_cipher->clone(), bits);
         else
            return new EAX_Decryption(block_cipher->clone(), bits);
         }
#endif
      }

   return 0;
   }

/*
* Get a cipher object
*/
Keyed_Filter* Core_Engine::get_cipher(const std::string& algo_spec,
                                      Cipher_Dir direction,
                                      Algorithm_Factory& af)
   {
   std::vector<std::string> algo_parts = split_on(algo_spec, '/');
   if(algo_parts.empty())
      throw Invalid_Algorithm_Name(algo_spec);

   const std::string cipher_name = algo_parts[0];

   // check if it is a stream cipher first (easy case)
   const StreamCipher* stream_cipher = af.prototype_stream_cipher(cipher_name);
   if(stream_cipher)
      return new StreamCipher_Filter(stream_cipher->clone());

   const BlockCipher* block_cipher = af.prototype_block_cipher(cipher_name);
   if(!block_cipher)
      return 0;

   if(algo_parts.size() >= 4)
      return 0; // 4 part mode, not something we know about

   if(algo_parts.size() < 2)
      throw Lookup_Error("Cipher specification '" + algo_spec +
                         "' is missing mode identifier");

   std::string mode = algo_parts[1];

   std::string padding;
   if(algo_parts.size() == 3)
      padding = algo_parts[2];
   else
      padding = (mode == "CBC") ? "PKCS7" : "NoPadding";

   if(mode == "ECB" && padding == "CTS")
      return 0;
   else if((mode != "CBC" && mode != "ECB") && padding != "NoPadding")
      throw Invalid_Algorithm_Name(algo_spec);

   Keyed_Filter* filt = get_cipher_mode(block_cipher, direction, mode, padding);
   if(filt)
      return filt;

   throw Algorithm_Not_Found(cipher_name + "/" + mode + "/" + padding);
   }

}
