/*
* Cipher Modes
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/cipher_mode.h>
#include <botan/stream_mode.h>
#include <botan/internal/mode_utils.h>
#include <botan/internal/algo_registry.h>
#include <sstream>

#if defined(BOTAN_HAS_MODE_ECB)
  #include <botan/ecb.h>
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

namespace Botan {

#define BOTAN_REGISTER_CIPHER_MODE(name, maker) BOTAN_REGISTER_T(Cipher_Mode, name, maker)
#define BOTAN_REGISTER_CIPHER_MODE_NOARGS(name) BOTAN_REGISTER_T_NOARGS(Cipher_Mode, name)

#if defined(BOTAN_HAS_MODE_ECB)

template<typename T>
Cipher_Mode* make_ecb_mode(const Cipher_Mode::Spec& spec)
   {
   std::unique_ptr<BlockCipher> bc(BlockCipher::create(spec.arg(0)));
   std::unique_ptr<BlockCipherModePaddingMethod> pad(get_bc_pad(spec.arg(1, "NoPadding")));
   if(bc && pad)
      return new T(bc.release(), pad.release());
   return nullptr;
   }

BOTAN_REGISTER_CIPHER_MODE(ECB_Encryption, make_ecb_mode<ECB_Encryption>);
BOTAN_REGISTER_CIPHER_MODE(ECB_Decryption, make_ecb_mode<ECB_Decryption>);
#endif

#if defined(BOTAN_HAS_MODE_CBC)

template<typename CBC_T, typename CTS_T>
Cipher_Mode* make_cbc_mode(const Cipher_Mode::Spec& spec)
   {
   std::unique_ptr<BlockCipher> bc(BlockCipher::create(spec.arg(0)));

   if(bc)
      {
      const std::string padding = spec.arg(1, "PKCS7");

      if(padding == "CTS")
         return new CTS_T(bc.release());
      else
         return new CBC_T(bc.release(), get_bc_pad(padding));
      }

   return nullptr;
   }

BOTAN_REGISTER_CIPHER_MODE(CBC_Encryption, (make_cbc_mode<CBC_Encryption,CTS_Encryption>));
BOTAN_REGISTER_CIPHER_MODE(CBC_Decryption, (make_cbc_mode<CBC_Decryption,CTS_Decryption>));
#endif

#if defined(BOTAN_HAS_MODE_CFB)
BOTAN_REGISTER_BLOCK_CIPHER_MODE_LEN(CFB_Encryption, CFB_Decryption, 0);
#endif

#if defined(BOTAN_HAS_MODE_XTS)
BOTAN_REGISTER_BLOCK_CIPHER_MODE(XTS_Encryption, XTS_Decryption);
#endif

Cipher_Mode* get_cipher_mode(const std::string& algo_spec, Cipher_Dir direction)
   {
   const std::string provider = "";

   const char* dir_string = (direction == ENCRYPTION) ? "_Encryption" : "_Decryption";

   Cipher_Mode::Spec spec(algo_spec, dir_string);

   std::unique_ptr<Cipher_Mode> cipher_mode(
      Algo_Registry<Cipher_Mode>::global_registry().make(
         Cipher_Mode::Spec(algo_spec, dir_string),
         provider)
      );

   if(cipher_mode)
      {
      return cipher_mode.release();
      }

   const std::vector<std::string> algo_parts = split_on(algo_spec, '/');
   if(algo_parts.size() < 2)
      return nullptr;

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
   const std::string mode_name_directional = mode_info[0] + dir_string + alg_args.str();

   cipher_mode.reset(
      Algo_Registry<Cipher_Mode>::global_registry().make(
         Cipher_Mode::Spec(mode_name_directional),
         provider)
      );

   if(cipher_mode)
      {
      return cipher_mode.release();
      }

   cipher_mode.reset(
      Algo_Registry<Cipher_Mode>::global_registry().make(
         Cipher_Mode::Spec(mode_name),
         provider)
      );

   if(cipher_mode)
      {
      return cipher_mode.release();
      }

   if(auto sc = StreamCipher::create(mode_name, provider))
      {
      return new Stream_Cipher_Mode(sc.release());
      }

   return nullptr;
   }

}
