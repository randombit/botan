/*
* Block Cipher Lookup
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/core_engine.h>
#include <botan/scan_name.h>
#include <botan/algo_factory.h>

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

#if defined(BOTAN_HAS_LUBY_RACKOFF)
  #include <botan/lubyrack.h>
#endif

#if defined(BOTAN_HAS_MARS)
  #include <botan/mars.h>
#endif

#if defined(BOTAN_HAS_MISTY1)
  #include <botan/misty1.h>
#endif

#if defined(BOTAN_HAS_NOEKEON)
  #include <botan/noekeon.h>
#endif

#if defined(BOTAN_HAS_RC2)
  #include <botan/rc2.h>
#endif

#if defined(BOTAN_HAS_RC5)
  #include <botan/rc5.h>
#endif

#if defined(BOTAN_HAS_RC6)
  #include <botan/rc6.h>
#endif

#if defined(BOTAN_HAS_SAFER)
  #include <botan/safer_sk.h>
#endif

#if defined(BOTAN_HAS_SEED)
  #include <botan/seed.h>
#endif

#if defined(BOTAN_HAS_SERPENT)
  #include <botan/serpent.h>
#endif

#if defined(BOTAN_HAS_SKIPJACK)
  #include <botan/skipjack.h>
#endif

#if defined(BOTAN_HAS_SQUARE)
  #include <botan/square.h>
#endif

#if defined(BOTAN_HAS_TEA)
  #include <botan/tea.h>
#endif

#if defined(BOTAN_HAS_TWOFISH)
  #include <botan/twofish.h>
#endif

#if defined(BOTAN_HAS_XTEA)
  #include <botan/xtea.h>
#endif

namespace Botan {

/*
* Look for an algorithm with this name
*/
BlockCipher* Core_Engine::find_block_cipher(const SCAN_Name& request,
                                            Algorithm_Factory& af) const
   {

#if defined(BOTAN_HAS_AES)
   if(request.algo_name() == "AES-128")
      return new AES_128;
   if(request.algo_name() == "AES-192")
      return new AES_192;
   if(request.algo_name() == "AES-256")
      return new AES_256;
#endif

#if defined(BOTAN_HAS_BLOWFISH)
   if(request.algo_name() == "Blowfish")
      return new Blowfish;
#endif

#if defined(BOTAN_HAS_CAMELLIA)
   if(request.algo_name() == "Camellia-128")
      return new Camellia_128;
   if(request.algo_name() == "Camellia-192")
      return new Camellia_192;
   if(request.algo_name() == "Camellia-256")
      return new Camellia_256;
#endif

#if defined(BOTAN_HAS_CAST)
   if(request.algo_name() == "CAST-128")
      return new CAST_128;
   if(request.algo_name() == "CAST-256")
      return new CAST_256;
#endif

#if defined(BOTAN_HAS_DES)
   if(request.algo_name() == "DES")
      return new DES;
   if(request.algo_name() == "DESX")
      return new DESX;
   if(request.algo_name() == "TripleDES")
      return new TripleDES;
#endif

#if defined(BOTAN_HAS_GOST_28147_89)
   if(request.algo_name() == "GOST-28147-89")
      return new GOST_28147_89(request.arg(0, "R3411_94_TestParam"));
#endif

#if defined(BOTAN_HAS_IDEA)
   if(request.algo_name() == "IDEA")
      return new IDEA;
#endif

#if defined(BOTAN_HAS_KASUMI)
   if(request.algo_name() == "KASUMI")
      return new KASUMI;
#endif

#if defined(BOTAN_HAS_MARS)
   if(request.algo_name() == "MARS")
      return new MARS;
#endif

#if defined(BOTAN_HAS_MISTY1)
   if(request.algo_name() == "MISTY1")
      return new MISTY1(request.arg_as_integer(0, 8));
#endif

#if defined(BOTAN_HAS_NOEKEON)
   if(request.algo_name() == "Noekeon")
      return new Noekeon;
#endif

#if defined(BOTAN_HAS_RC2)
   if(request.algo_name() == "RC2")
      return new RC2;
#endif

#if defined(BOTAN_HAS_RC5)
   if(request.algo_name() == "RC5")
      return new RC5(request.arg_as_integer(0, 12));
#endif

#if defined(BOTAN_HAS_RC6)
   if(request.algo_name() == "RC6")
      return new RC6;
#endif

#if defined(BOTAN_HAS_SAFER)
   if(request.algo_name() == "SAFER-SK")
      return new SAFER_SK(request.arg_as_integer(0, 10));
#endif

#if defined(BOTAN_HAS_SEED)
   if(request.algo_name() == "SEED")
      return new SEED;
#endif

#if defined(BOTAN_HAS_SERPENT)
   if(request.algo_name() == "Serpent")
      return new Serpent;
#endif

#if defined(BOTAN_HAS_SKIPJACK)
   if(request.algo_name() == "Skipjack")
      return new Skipjack;
#endif

#if defined(BOTAN_HAS_SQUARE)
   if(request.algo_name() == "Square")
      return new Square;
#endif

#if defined(BOTAN_HAS_TEA)
   if(request.algo_name() == "TEA")
      return new TEA;
#endif

#if defined(BOTAN_HAS_TWOFISH)
   if(request.algo_name() == "Twofish")
      return new Twofish;
#endif

#if defined(BOTAN_HAS_XTEA)
   if(request.algo_name() == "XTEA")
      return new XTEA;
#endif

#if defined(BOTAN_HAS_LUBY_RACKOFF)
   if(request.algo_name() == "Luby-Rackoff" && request.arg_count() == 1)
      {
      const HashFunction* hash = af.prototype_hash_function(request.arg(0));

      if(hash)
         return new LubyRackoff(hash->clone());
      }
#endif

#if defined(BOTAN_HAS_CASCADE)
   if(request.algo_name() == "Cascade" && request.arg_count() == 2)
      {
      const BlockCipher* c1 = af.prototype_block_cipher(request.arg(0));
      const BlockCipher* c2 = af.prototype_block_cipher(request.arg(1));

      if(c1 && c2)
         return new Cascade_Cipher(c1->clone(), c2->clone());
      }
#endif

#if defined(BOTAN_HAS_LION)
   if(request.algo_name() == "Lion" && request.arg_count_between(2, 3))
      {
      const size_t block_size = request.arg_as_integer(2, 1024);

      const HashFunction* hash =
         af.prototype_hash_function(request.arg(0));

      const StreamCipher* stream_cipher =
         af.prototype_stream_cipher(request.arg(1));

      if(!hash || !stream_cipher)
         return 0;

      return new Lion(hash->clone(), stream_cipher->clone(), block_size);
      }
#endif

   return 0;
   }

}
