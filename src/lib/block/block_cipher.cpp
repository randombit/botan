/*
* Block Ciphers
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/block_cipher.h>
#include <botan/cpuid.h>
#include <botan/internal/algo_registry.h>

#if defined(BOTAN_HAS_AES)
  #include <botan/aes.h>
#endif

#if defined(BOTAN_HAS_BLOWFISH)
  #include <botan/blowfish.h>
#endif

#if defined(BOTAN_HAS_CAMELLIA)
  #include <botan/camellia.h>
#endif

#if defined(BOTAN_HAS_CAST)
  #include <botan/cast128.h>
  #include <botan/cast256.h>
#endif

#if defined(BOTAN_HAS_CASCADE)
  #include <botan/cascade.h>
#endif

#if defined(BOTAN_HAS_DES)
  #include <botan/des.h>
  #include <botan/desx.h>
#endif

#if defined(BOTAN_HAS_GOST_28147_89)
  #include <botan/gost_28147.h>
#endif

#if defined(BOTAN_HAS_IDEA)
  #include <botan/idea.h>
#endif

#if defined(BOTAN_HAS_KASUMI)
  #include <botan/kasumi.h>
#endif

#if defined(BOTAN_HAS_LION)
  #include <botan/lion.h>
#endif

#if defined(BOTAN_HAS_MISTY1)
  #include <botan/misty1.h>
#endif

#if defined(BOTAN_HAS_NOEKEON)
  #include <botan/noekeon.h>
#endif

#if defined(BOTAN_HAS_SEED)
  #include <botan/seed.h>
#endif

#if defined(BOTAN_HAS_SERPENT)
  #include <botan/serpent.h>
#endif

#if defined(BOTAN_HAS_TWOFISH)
  #include <botan/twofish.h>
#endif

#if defined(BOTAN_HAS_THREEFISH_512)
  #include <botan/threefish.h>
#endif

#if defined(BOTAN_HAS_XTEA)
  #include <botan/xtea.h>
#endif

namespace Botan {

BlockCipher::~BlockCipher() {}

std::unique_ptr<BlockCipher> BlockCipher::create(const std::string& algo_spec,
                                                 const std::string& provider)
   {
   return std::unique_ptr<BlockCipher>(make_a<BlockCipher>(Botan::BlockCipher::Spec(algo_spec), provider));
   }

std::vector<std::string> BlockCipher::providers(const std::string& algo_spec)
   {
   return providers_of<BlockCipher>(BlockCipher::Spec(algo_spec));
   }

#define BOTAN_REGISTER_BLOCK_CIPHER(name, maker) BOTAN_REGISTER_T(BlockCipher, name, maker)
#define BOTAN_REGISTER_BLOCK_CIPHER_NOARGS(name) BOTAN_REGISTER_T_NOARGS(BlockCipher, name)

#define BOTAN_REGISTER_BLOCK_CIPHER_1LEN(name, def) BOTAN_REGISTER_T_1LEN(BlockCipher, name, def)

#define BOTAN_REGISTER_BLOCK_CIPHER_NAMED_NOARGS(type, name) \
   BOTAN_REGISTER_NAMED_T(BlockCipher, name, type, make_new_T<type>)
#define BOTAN_REGISTER_BLOCK_CIPHER_NAMED_1LEN(type, name, def) \
   BOTAN_REGISTER_NAMED_T(BlockCipher, name, type, (make_new_T_1len<type,def>))
#define BOTAN_REGISTER_BLOCK_CIPHER_NAMED_1STR(type, name, def) \
   BOTAN_REGISTER_NAMED_T(BlockCipher, name, type, std::bind(make_new_T_1str<type>, std::placeholders::_1, def))

#define BOTAN_REGISTER_BLOCK_CIPHER_NOARGS_IF(cond, type, name, provider, pref) \
   BOTAN_COND_REGISTER_NAMED_T_NOARGS(cond, BlockCipher, type, name, provider, pref)

#if defined(BOTAN_HAS_AES)
BOTAN_REGISTER_BLOCK_CIPHER_NAMED_NOARGS(AES_128, "AES-128");
BOTAN_REGISTER_BLOCK_CIPHER_NAMED_NOARGS(AES_192, "AES-192");
BOTAN_REGISTER_BLOCK_CIPHER_NAMED_NOARGS(AES_256, "AES-256");
#endif

#if defined(BOTAN_HAS_BLOWFISH)
BOTAN_REGISTER_BLOCK_CIPHER_NOARGS(Blowfish);
#endif

#if defined(BOTAN_HAS_CAMELLIA)
BOTAN_REGISTER_BLOCK_CIPHER_NAMED_NOARGS(Camellia_128, "Camellia-128");
BOTAN_REGISTER_BLOCK_CIPHER_NAMED_NOARGS(Camellia_192, "Camellia-192");
BOTAN_REGISTER_BLOCK_CIPHER_NAMED_NOARGS(Camellia_256, "Camellia-256");
#endif

#if defined(BOTAN_HAS_CAST)
BOTAN_REGISTER_BLOCK_CIPHER_NAMED_NOARGS(CAST_128, "CAST-128");
BOTAN_REGISTER_BLOCK_CIPHER_NAMED_NOARGS(CAST_256, "CAST-256");
#endif

#if defined(BOTAN_HAS_DES)
BOTAN_REGISTER_BLOCK_CIPHER_NOARGS(DES);
BOTAN_REGISTER_BLOCK_CIPHER_NOARGS(TripleDES);
BOTAN_REGISTER_BLOCK_CIPHER_NOARGS(DESX);
#endif

#if defined(BOTAN_HAS_GOST_28147_89)
BOTAN_REGISTER_BLOCK_CIPHER_NAMED_1STR(GOST_28147_89, "GOST-28147-89", "R3411_94_TestParam");
#endif

#if defined(BOTAN_HAS_IDEA)
BOTAN_REGISTER_BLOCK_CIPHER_NOARGS(IDEA);
#endif

#if defined(BOTAN_HAS_KASUMI)
BOTAN_REGISTER_BLOCK_CIPHER_NOARGS(KASUMI);
#endif

#if defined(BOTAN_HAS_MISTY1)
BOTAN_REGISTER_BLOCK_CIPHER_NOARGS(MISTY1);
#endif

#if defined(BOTAN_HAS_NOEKEON)
BOTAN_REGISTER_BLOCK_CIPHER_NOARGS(Noekeon);
#endif

#if defined(BOTAN_HAS_SEED)
BOTAN_REGISTER_BLOCK_CIPHER_NOARGS(SEED);
#endif

#if defined(BOTAN_HAS_SERPENT)
BOTAN_REGISTER_BLOCK_CIPHER_NOARGS(Serpent);
#endif

#if defined(BOTAN_HAS_TWOFISH)
BOTAN_REGISTER_BLOCK_CIPHER_NOARGS(Twofish);
#endif

#if defined(BOTAN_HAS_THREEFISH_512)
BOTAN_REGISTER_BLOCK_CIPHER_NAMED_NOARGS(Threefish_512, "Threefish-512");
#endif

#if defined(BOTAN_HAS_XTEA)
BOTAN_REGISTER_BLOCK_CIPHER_NOARGS(XTEA);
#endif

#if defined(BOTAN_HAS_CASCADE)
BOTAN_REGISTER_NAMED_T(BlockCipher, "Cascade", Cascade_Cipher, Cascade_Cipher::make);
#endif

#if defined(BOTAN_HAS_LION)
BOTAN_REGISTER_NAMED_T(BlockCipher, "Lion", Lion, Lion::make);
#endif

}
