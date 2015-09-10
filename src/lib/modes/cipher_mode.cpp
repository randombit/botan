/*
* Cipher Modes
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/cipher_mode.h>
#include <botan/stream_mode.h>
#include <botan/lookup.h>
#include <botan/internal/mode_utils.h>
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

#if defined(BOTAN_HAS_MODE_ECB)

template<typename T>
Transform* make_ecb_mode(const Transform::Spec& spec)
   {
   std::unique_ptr<BlockCipher> bc(get_block_cipher(spec.arg(0)));
   std::unique_ptr<BlockCipherModePaddingMethod> pad(get_bc_pad(spec.arg(1, "NoPadding")));
   if(bc && pad)
      return new T(bc.release(), pad.release());
   return nullptr;
   }

BOTAN_REGISTER_TRANSFORM(ECB_Encryption, make_ecb_mode<ECB_Encryption>);
BOTAN_REGISTER_TRANSFORM(ECB_Decryption, make_ecb_mode<ECB_Decryption>);
#endif

#if defined(BOTAN_HAS_MODE_CBC)

template<typename CBC_T, typename CTS_T>
Transform* make_cbc_mode(const Transform::Spec& spec)
   {
   std::unique_ptr<BlockCipher> bc(get_block_cipher(spec.arg(0)));

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

BOTAN_REGISTER_TRANSFORM(CBC_Encryption, (make_cbc_mode<CBC_Encryption,CTS_Encryption>));
BOTAN_REGISTER_TRANSFORM(CBC_Decryption, (make_cbc_mode<CBC_Decryption,CTS_Decryption>));
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

   std::unique_ptr<Transform> t;

   t.reset(get_transform(algo_spec, provider, dir_string));

   if(Cipher_Mode* cipher = dynamic_cast<Cipher_Mode*>(t.get()))
      {
      t.release();
      return cipher;
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

   t.reset(get_transform(mode_name_directional, provider));

   if(Cipher_Mode* cipher = dynamic_cast<Cipher_Mode*>(t.get()))
      {
      t.release();
      return cipher;
      }

   t.reset(get_transform(mode_name, provider));

   if(Cipher_Mode* cipher = dynamic_cast<Cipher_Mode*>(t.get()))
      {
      t.release();
      return cipher;
      }

   if(StreamCipher* stream_cipher = get_stream_cipher(mode_name, provider))
      return new Stream_Cipher_Mode(stream_cipher);

   return nullptr;
   }

}
