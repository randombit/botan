/*
* Core Engine
* (C) 1999-2007,2011,2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/core_engine.h>
#include <botan/parsing.h>
#include <botan/filters.h>
#include <botan/algo_factory.h>
#include <botan/mode_pad.h>
#include <botan/transform_filter.h>
#include <memory>

#if defined(BOTAN_HAS_MODE_CFB)
  #include <botan/cfb.h>
#endif

#if defined(BOTAN_HAS_MODE_ECB)
  #include <botan/ecb.h>
#endif

#if defined(BOTAN_HAS_MODE_CBC)
  #include <botan/cbc.h>
#endif

#if defined(BOTAN_HAS_MODE_XTS)
  #include <botan/xts.h>
#endif

#if defined(BOTAN_HAS_OFB)
  #include <botan/ofb.h>
#endif

#if defined(BOTAN_HAS_CTR_BE)
  #include <botan/ctr.h>
#endif

#if defined(BOTAN_HAS_AEAD_FILTER)

#include <botan/aead_filt.h>

#if defined(BOTAN_HAS_AEAD_CCM)
  #include <botan/ccm.h>
#endif

#if defined(BOTAN_HAS_AEAD_EAX)
  #include <botan/eax.h>
#endif

#if defined(BOTAN_HAS_AEAD_OCB)
  #include <botan/ocb.h>
#endif

#if defined(BOTAN_HAS_AEAD_GCM)
  #include <botan/gcm.h>
#endif

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

#if defined(BOTAN_HAS_MODE_ECB)
   if(mode == "ECB" || mode == "")
      {
      if(direction == ENCRYPTION)
         return new Transformation_Filter(
            new ECB_Encryption(block_cipher->clone(), get_bc_pad(padding, "NoPadding")));
      else
         return new Transformation_Filter(
            new ECB_Decryption(block_cipher->clone(), get_bc_pad(padding, "NoPadding")));
      }
#endif

   if(mode == "CBC")
      {
#if defined(BOTAN_HAS_MODE_CBC)
      if(padding == "CTS")
         {
         if(direction == ENCRYPTION)
            return new Transformation_Filter(new CTS_Encryption(block_cipher->clone()));
         else
            return new Transformation_Filter(new CTS_Decryption(block_cipher->clone()));
         }

      if(direction == ENCRYPTION)
         return new Transformation_Filter(
            new CBC_Encryption(block_cipher->clone(), get_bc_pad(padding, "PKCS7")));
      else
         return new Transformation_Filter(
            new CBC_Decryption(block_cipher->clone(), get_bc_pad(padding, "PKCS7")));
#else
      return nullptr;
#endif
      }

#if defined(BOTAN_HAS_MODE_XTS)
   if(mode == "XTS")
      {
      if(direction == ENCRYPTION)
         return new Transformation_Filter(new XTS_Encryption(block_cipher->clone()));
      else
         return new Transformation_Filter(new XTS_Decryption(block_cipher->clone()));
      }
#endif

   if(mode.find("CFB") != std::string::npos ||
      mode.find("EAX") != std::string::npos ||
      mode.find("GCM") != std::string::npos ||
      mode.find("OCB") != std::string::npos ||
      mode.find("CCM") != std::string::npos)
      {
      std::vector<std::string> algo_info = parse_algorithm_name(mode);
      const std::string mode_name = algo_info[0];

      size_t bits = 8 * block_cipher->block_size();
      if(algo_info.size() > 1)
         bits = to_u32bit(algo_info[1]);

#if defined(BOTAN_HAS_MODE_CFB)
      if(mode_name == "CFB")
         {
         if(direction == ENCRYPTION)
            return new Transformation_Filter(new CFB_Encryption(block_cipher->clone(), bits));
         else
            return new Transformation_Filter(new CFB_Decryption(block_cipher->clone(), bits));
         }
#endif

      if(bits % 8 != 0)
         throw std::invalid_argument("AEAD interface does not support non-octet length tags");

#if defined(BOTAN_HAS_AEAD_FILTER)

      const size_t tag_size = bits / 8;

#if defined(BOTAN_HAS_AEAD_CCM)
      if(mode_name == "CCM")
         {
         const size_t L = (algo_info.size() == 3) ? to_u32bit(algo_info[2]) : 3;
         if(direction == ENCRYPTION)
            return new AEAD_Filter(new CCM_Encryption(block_cipher->clone(), tag_size, L));
         else
            return new AEAD_Filter(new CCM_Decryption(block_cipher->clone(), tag_size, L));
         }
#endif

#if defined(BOTAN_HAS_AEAD_EAX)
      if(mode_name == "EAX")
         {
         if(direction == ENCRYPTION)
            return new AEAD_Filter(new EAX_Encryption(block_cipher->clone(), tag_size));
         else
            return new AEAD_Filter(new EAX_Decryption(block_cipher->clone(), tag_size));
         }
#endif

#if defined(BOTAN_HAS_AEAD_OCB)
   if(mode_name == "OCB")
      {
      if(direction == ENCRYPTION)
         return new AEAD_Filter(new OCB_Encryption(block_cipher->clone(), tag_size));
      else
         return new AEAD_Filter(new OCB_Decryption(block_cipher->clone(), tag_size));
      }
#endif

#if defined(BOTAN_HAS_AEAD_GCM)
   if(mode_name == "GCM")
      {
      if(direction == ENCRYPTION)
         return new AEAD_Filter(new GCM_Encryption(block_cipher->clone(), tag_size));
      else
         return new AEAD_Filter(new GCM_Decryption(block_cipher->clone(), tag_size));
      }
#endif

#endif
      }

   return nullptr;
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
      return nullptr;

   if(algo_parts.size() >= 4)
      return nullptr; // 4 part mode, not something we know about

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
      return nullptr;
   else if((mode != "CBC" && mode != "ECB") && padding != "NoPadding")
      throw Invalid_Algorithm_Name(algo_spec);

   Keyed_Filter* filt = get_cipher_mode(block_cipher, direction, mode, padding);
   if(filt)
      return filt;

   if(padding != "NoPadding")
      throw Algorithm_Not_Found(cipher_name + "/" + mode + "/" + padding);
   else
      throw Algorithm_Not_Found(cipher_name + "/" + mode);
   }

}
