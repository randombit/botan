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

void AEAD_Mode::set_associated_data_n(size_t i, const uint8_t ad[], size_t ad_len)
   {
   if(i == 0)
      this->set_associated_data(ad, ad_len);
   else
      throw Invalid_Argument("AEAD '" + name() + "' does not support multiple associated data");
   }

std::unique_ptr<AEAD_Mode> AEAD_Mode::create_or_throw(const std::string& algo,
                                                      Cipher_Dir dir,
                                                      const std::string& provider)
   {
   if(auto aead = AEAD_Mode::create(algo, dir, provider))
      return aead;

   throw Lookup_Error("AEAD", algo, provider);
   }

std::unique_ptr<AEAD_Mode> AEAD_Mode::create(const std::string& algo,
                                             Cipher_Dir dir,
                                             const std::string& provider)
   {
   BOTAN_UNUSED(provider);
#if defined(BOTAN_HAS_AEAD_CHACHA20_POLY1305)
   if(algo == "ChaCha20Poly1305")
      {
      if(dir == ENCRYPTION)
         return std::unique_ptr<AEAD_Mode>(new ChaCha20Poly1305_Encryption);
      else
         return std::unique_ptr<AEAD_Mode>(new ChaCha20Poly1305_Decryption);

      }
#endif

   if(algo.find('/') != std::string::npos)
      {
      const std::vector<std::string> algo_parts = split_on(algo, '/');
      const std::string cipher_name = algo_parts[0];
      const std::vector<std::string> mode_info = parse_algorithm_name(algo_parts[1]);

      if(mode_info.empty())
         return std::unique_ptr<AEAD_Mode>();

      std::ostringstream alg_args;

      alg_args << '(' << cipher_name;
      for(size_t i = 1; i < mode_info.size(); ++i)
         alg_args << ',' << mode_info[i];
      for(size_t i = 2; i < algo_parts.size(); ++i)
         alg_args << ',' << algo_parts[i];
      alg_args << ')';

      const std::string mode_name = mode_info[0] + alg_args.str();
      return AEAD_Mode::create(mode_name, dir);
      }

#if defined(BOTAN_HAS_BLOCK_CIPHER)

   SCAN_Name req(algo);

   if(req.arg_count() == 0)
      {
      return std::unique_ptr<AEAD_Mode>();
      }

   std::unique_ptr<BlockCipher> bc(BlockCipher::create(req.arg(0), provider));

   if(!bc)
      {
      return std::unique_ptr<AEAD_Mode>();
      }

#if defined(BOTAN_HAS_AEAD_CCM)
   if(req.algo_name() == "CCM")
      {
      size_t tag_len = req.arg_as_integer(1, 16);
      size_t L_len = req.arg_as_integer(2, 3);
      if(dir == ENCRYPTION)
         return std::unique_ptr<AEAD_Mode>(new CCM_Encryption(bc.release(), tag_len, L_len));
      else
         return std::unique_ptr<AEAD_Mode>(new CCM_Decryption(bc.release(), tag_len, L_len));
      }
#endif

#if defined(BOTAN_HAS_AEAD_GCM)
   if(req.algo_name() == "GCM")
      {
      size_t tag_len = req.arg_as_integer(1, 16);
      if(dir == ENCRYPTION)
         return std::unique_ptr<AEAD_Mode>(new GCM_Encryption(bc.release(), tag_len));
      else
         return std::unique_ptr<AEAD_Mode>(new GCM_Decryption(bc.release(), tag_len));
      }
#endif

#if defined(BOTAN_HAS_AEAD_OCB)
   if(req.algo_name() == "OCB")
      {
      size_t tag_len = req.arg_as_integer(1, 16);
      if(dir == ENCRYPTION)
         return std::unique_ptr<AEAD_Mode>(new OCB_Encryption(bc.release(), tag_len));
      else
         return std::unique_ptr<AEAD_Mode>(new OCB_Decryption(bc.release(), tag_len));
      }
#endif

#if defined(BOTAN_HAS_AEAD_EAX)
   if(req.algo_name() == "EAX")
      {
      size_t tag_len = req.arg_as_integer(1, bc->block_size());
      if(dir == ENCRYPTION)
         return std::unique_ptr<AEAD_Mode>(new EAX_Encryption(bc.release(), tag_len));
      else
         return std::unique_ptr<AEAD_Mode>(new EAX_Decryption(bc.release(), tag_len));
      }
#endif

#if defined(BOTAN_HAS_AEAD_SIV)
   if(req.algo_name() == "SIV")
      {
      if(dir == ENCRYPTION)
         return std::unique_ptr<AEAD_Mode>(new SIV_Encryption(bc.release()));
      else
         return std::unique_ptr<AEAD_Mode>(new SIV_Decryption(bc.release()));
      }
#endif

#endif

   return std::unique_ptr<AEAD_Mode>();
   }



}
