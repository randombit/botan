/*
* Cipher Modes
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/cipher_mode.h>
#include <botan/stream_mode.h>
#include <botan/scan_name.h>
#include <botan/parsing.h>
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

#if defined(BOTAN_HAS_OPENSSL)
  #include <botan/internal/openssl.h>
#endif

#if defined(BOTAN_HAS_COMMONCRYPTO)
  #include <botan/internal/commoncrypto.h>
#endif

namespace Botan {

std::unique_ptr<Cipher_Mode> Cipher_Mode::create_or_throw(const std::string& algo,
                                                          Cipher_Dir direction,
                                                          const std::string& provider)
   {
   if(auto mode = Cipher_Mode::create(algo, direction, provider))
      return mode;

   throw Lookup_Error("Cipher mode", algo, provider);
   }

std::unique_ptr<Cipher_Mode> Cipher_Mode::create(const std::string& algo,
                                                 Cipher_Dir direction,
                                                 const std::string& provider)
   {
#if defined(BOTAN_HAS_COMMONCRYPTO)
   if(provider.empty() || provider == "commoncrypto")
      {
      std::unique_ptr<Cipher_Mode> commoncrypto_cipher(make_commoncrypto_cipher_mode(algo, direction));

      if(commoncrypto_cipher)
         return commoncrypto_cipher;

      if(!provider.empty())
         return std::unique_ptr<Cipher_Mode>();
      }
#endif

#if defined(BOTAN_HAS_OPENSSL)
   if(provider.empty() || provider == "openssl")
      {
      std::unique_ptr<Cipher_Mode> openssl_cipher(make_openssl_cipher_mode(algo, direction));

      if(openssl_cipher)
         return openssl_cipher;

      if(!provider.empty())
         return std::unique_ptr<Cipher_Mode>();
      }
#endif

#if defined(BOTAN_HAS_STREAM_CIPHER)
   if(auto sc = StreamCipher::create(algo))
      {
      return std::unique_ptr<Cipher_Mode>(new Stream_Cipher_Mode(sc.release()));
      }
#endif

#if defined(BOTAN_HAS_AEAD_MODES)
   if(auto aead = AEAD_Mode::create(algo, direction))
      {
      return std::unique_ptr<Cipher_Mode>(aead.release());
      }
#endif

   if(algo.find('/') != std::string::npos)
      {
      const std::vector<std::string> algo_parts = split_on(algo, '/');
      const std::string cipher_name = algo_parts[0];
      const std::vector<std::string> mode_info = parse_algorithm_name(algo_parts[1]);

      if(mode_info.empty())
         return std::unique_ptr<Cipher_Mode>();

      std::ostringstream alg_args;

      alg_args << '(' << cipher_name;
      for(size_t i = 1; i < mode_info.size(); ++i)
         alg_args << ',' << mode_info[i];
      for(size_t i = 2; i < algo_parts.size(); ++i)
         alg_args << ',' << algo_parts[i];
      alg_args << ')';

      const std::string mode_name = mode_info[0] + alg_args.str();
      return Cipher_Mode::create(mode_name, direction, provider);
      }

#if defined(BOTAN_HAS_BLOCK_CIPHER)

   SCAN_Name spec(algo);

   if(spec.arg_count() == 0)
      {
      return std::unique_ptr<Cipher_Mode>();
      }

   std::unique_ptr<BlockCipher> bc(BlockCipher::create(spec.arg(0), provider));

   if(!bc)
      {
      return std::unique_ptr<Cipher_Mode>();
      }

#if defined(BOTAN_HAS_MODE_CBC)
   if(spec.algo_name() == "CBC")
      {
      const std::string padding = spec.arg(1, "PKCS7");

      if(padding == "CTS")
         {
         if(direction == ENCRYPTION)
            return std::unique_ptr<Cipher_Mode>(new CTS_Encryption(bc.release()));
         else
            return std::unique_ptr<Cipher_Mode>(new CTS_Decryption(bc.release()));
         }
      else
         {
         std::unique_ptr<BlockCipherModePaddingMethod> pad(get_bc_pad(padding));

         if(pad)
            {
            if(direction == ENCRYPTION)
               return std::unique_ptr<Cipher_Mode>(new CBC_Encryption(bc.release(), pad.release()));
            else
               return std::unique_ptr<Cipher_Mode>(new CBC_Decryption(bc.release(), pad.release()));
            }
         }
      }
#endif

#if defined(BOTAN_HAS_MODE_XTS)
   if(spec.algo_name() == "XTS")
      {
      if(direction == ENCRYPTION)
         return std::unique_ptr<Cipher_Mode>(new XTS_Encryption(bc.release()));
      else
         return std::unique_ptr<Cipher_Mode>(new XTS_Decryption(bc.release()));
      }
#endif

#if defined(BOTAN_HAS_MODE_CFB)
   if(spec.algo_name() == "CFB")
      {
      const size_t feedback_bits = spec.arg_as_integer(1, 8*bc->block_size());
      if(direction == ENCRYPTION)
         return std::unique_ptr<Cipher_Mode>(new CFB_Encryption(bc.release(), feedback_bits));
      else
         return std::unique_ptr<Cipher_Mode>(new CFB_Decryption(bc.release(), feedback_bits));
      }
#endif

#endif

   return std::unique_ptr<Cipher_Mode>();
   }

//static
std::vector<std::string> Cipher_Mode::providers(const std::string& algo_spec)
   {
   const std::vector<std::string>& possible = { "base", "openssl", "commoncrypto" };
   std::vector<std::string> providers;
   for(auto&& prov : possible)
      {
      std::unique_ptr<Cipher_Mode> mode = Cipher_Mode::create(algo_spec, ENCRYPTION, prov);
      if(mode)
         {
         providers.push_back(prov); // available
         }
      }
   return providers;
   }

}
