/*
* Block Ciphers
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/block_cipher.h>

#include <botan/exceptn.h>
#include <botan/internal/scan_name.h>

#if defined(BOTAN_HAS_AES)
   #include <botan/internal/aes.h>
#endif

#if defined(BOTAN_HAS_ARIA)
   #include <botan/internal/aria.h>
#endif

#if defined(BOTAN_HAS_BLOWFISH)
   #include <botan/internal/blowfish.h>
#endif

#if defined(BOTAN_HAS_CAMELLIA)
   #include <botan/internal/camellia.h>
#endif

#if defined(BOTAN_HAS_CAST_128)
   #include <botan/internal/cast128.h>
#endif

#if defined(BOTAN_HAS_CASCADE)
   #include <botan/internal/cascade.h>
#endif

#if defined(BOTAN_HAS_DES)
   #include <botan/internal/des.h>
#endif

#if defined(BOTAN_HAS_GOST_28147_89)
   #include <botan/internal/gost_28147.h>
#endif

#if defined(BOTAN_HAS_IDEA)
   #include <botan/internal/idea.h>
#endif

#if defined(BOTAN_HAS_KUZNYECHIK)
   #include <botan/internal/kuznyechik.h>
#endif

#if defined(BOTAN_HAS_LION)
   #include <botan/internal/lion.h>
#endif

#if defined(BOTAN_HAS_NOEKEON)
   #include <botan/internal/noekeon.h>
#endif

#if defined(BOTAN_HAS_SEED)
   #include <botan/internal/seed.h>
#endif

#if defined(BOTAN_HAS_SERPENT)
   #include <botan/internal/serpent.h>
#endif

#if defined(BOTAN_HAS_SHACAL2)
   #include <botan/internal/shacal2.h>
#endif

#if defined(BOTAN_HAS_SM4)
   #include <botan/internal/sm4.h>
#endif

#if defined(BOTAN_HAS_TWOFISH)
   #include <botan/internal/twofish.h>
#endif

#if defined(BOTAN_HAS_THREEFISH_512)
   #include <botan/internal/threefish_512.h>
#endif

#if defined(BOTAN_HAS_COMMONCRYPTO)
   #include <botan/internal/commoncrypto.h>
#endif

namespace Botan {

std::unique_ptr<BlockCipher> BlockCipher::create(std::string_view algo, std::string_view provider) {
#if defined(BOTAN_HAS_COMMONCRYPTO)
   if(provider.empty() || provider == "commoncrypto") {
      if(auto bc = make_commoncrypto_block_cipher(algo))
         return bc;

      if(!provider.empty())
         return nullptr;
   }
#endif

   // TODO: CryptoAPI
   // TODO: /dev/crypto

   // Only base providers from here on out
   if(provider.empty() == false && provider != "base") {
      return nullptr;
   }

#if defined(BOTAN_HAS_AES)
   if(algo == "AES-128") {
      return std::make_unique<AES_128>();
   }

   if(algo == "AES-192") {
      return std::make_unique<AES_192>();
   }

   if(algo == "AES-256") {
      return std::make_unique<AES_256>();
   }
#endif

#if defined(BOTAN_HAS_ARIA)
   if(algo == "ARIA-128") {
      return std::make_unique<ARIA_128>();
   }

   if(algo == "ARIA-192") {
      return std::make_unique<ARIA_192>();
   }

   if(algo == "ARIA-256") {
      return std::make_unique<ARIA_256>();
   }
#endif

#if defined(BOTAN_HAS_SERPENT)
   if(algo == "Serpent") {
      return std::make_unique<Serpent>();
   }
#endif

#if defined(BOTAN_HAS_SHACAL2)
   if(algo == "SHACAL2") {
      return std::make_unique<SHACAL2>();
   }
#endif

#if defined(BOTAN_HAS_TWOFISH)
   if(algo == "Twofish") {
      return std::make_unique<Twofish>();
   }
#endif

#if defined(BOTAN_HAS_THREEFISH_512)
   if(algo == "Threefish-512") {
      return std::make_unique<Threefish_512>();
   }
#endif

#if defined(BOTAN_HAS_BLOWFISH)
   if(algo == "Blowfish") {
      return std::make_unique<Blowfish>();
   }
#endif

#if defined(BOTAN_HAS_CAMELLIA)
   if(algo == "Camellia-128") {
      return std::make_unique<Camellia_128>();
   }

   if(algo == "Camellia-192") {
      return std::make_unique<Camellia_192>();
   }

   if(algo == "Camellia-256") {
      return std::make_unique<Camellia_256>();
   }
#endif

#if defined(BOTAN_HAS_DES)
   if(algo == "DES") {
      return std::make_unique<DES>();
   }

   if(algo == "TripleDES" || algo == "3DES" || algo == "DES-EDE") {
      return std::make_unique<TripleDES>();
   }
#endif

#if defined(BOTAN_HAS_NOEKEON)
   if(algo == "Noekeon") {
      return std::make_unique<Noekeon>();
   }
#endif

#if defined(BOTAN_HAS_CAST_128)
   if(algo == "CAST-128" || algo == "CAST5") {
      return std::make_unique<CAST_128>();
   }
#endif

#if defined(BOTAN_HAS_IDEA)
   if(algo == "IDEA") {
      return std::make_unique<IDEA>();
   }
#endif

#if defined(BOTAN_HAS_KUZNYECHIK)
   if(algo == "Kuznyechik") {
      return std::make_unique<Kuznyechik>();
   }
#endif

#if defined(BOTAN_HAS_SEED)
   if(algo == "SEED") {
      return std::make_unique<SEED>();
   }
#endif

#if defined(BOTAN_HAS_SM4)
   if(algo == "SM4") {
      return std::make_unique<SM4>();
   }
#endif

   const SCAN_Name req(algo);

#if defined(BOTAN_HAS_GOST_28147_89)
   if(req.algo_name() == "GOST-28147-89") {
      return std::make_unique<GOST_28147_89>(req.arg(0, "R3411_94_TestParam"));
   }
#endif

#if defined(BOTAN_HAS_CASCADE)
   if(req.algo_name() == "Cascade" && req.arg_count() == 2) {
      auto c1 = BlockCipher::create(req.arg(0));
      auto c2 = BlockCipher::create(req.arg(1));

      if(c1 && c2) {
         return std::make_unique<Cascade_Cipher>(std::move(c1), std::move(c2));
      }
   }
#endif

#if defined(BOTAN_HAS_LION)
   if(req.algo_name() == "Lion" && req.arg_count_between(2, 3)) {
      auto hash = HashFunction::create(req.arg(0));
      auto stream = StreamCipher::create(req.arg(1));

      if(hash && stream) {
         const size_t block_size = req.arg_as_integer(2, 1024);
         return std::make_unique<Lion>(std::move(hash), std::move(stream), block_size);
      }
   }
#endif

   BOTAN_UNUSED(req);
   BOTAN_UNUSED(provider);

   return nullptr;
}

//static
std::unique_ptr<BlockCipher> BlockCipher::create_or_throw(std::string_view algo, std::string_view provider) {
   if(auto bc = BlockCipher::create(algo, provider)) {
      return bc;
   }
   throw Lookup_Error("Block cipher", algo, provider);
}

std::vector<std::string> BlockCipher::providers(std::string_view algo) {
   return probe_providers_of<BlockCipher>(algo, {"base", "commoncrypto"});
}

}  // namespace Botan
