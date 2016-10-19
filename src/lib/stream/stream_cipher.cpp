/*
* Stream Ciphers
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/stream_cipher.h>
#include <botan/internal/algo_registry.h>

#if defined(BOTAN_HAS_CHACHA)
  #include <botan/chacha.h>
#endif

#if defined(BOTAN_HAS_SALSA20)
  #include <botan/salsa20.h>
#endif

#if defined(BOTAN_HAS_SHAKE_CIPHER)
  #include <botan/shake_cipher.h>
#endif

#if defined(BOTAN_HAS_CTR_BE)
  #include <botan/ctr.h>
#endif

#if defined(BOTAN_HAS_OFB)
  #include <botan/ofb.h>
#endif

#if defined(BOTAN_HAS_RC4)
  #include <botan/rc4.h>
#endif

namespace Botan {

std::unique_ptr<StreamCipher> StreamCipher::create(const std::string& algo_spec,
                                                   const std::string& provider)
   {
   return std::unique_ptr<StreamCipher>(make_a<StreamCipher>(Botan::StreamCipher::Spec(algo_spec), provider));
   }

std::vector<std::string> StreamCipher::providers(const std::string& algo_spec)
   {
   return providers_of<StreamCipher>(StreamCipher::Spec(algo_spec));
   }

StreamCipher::StreamCipher() {}
StreamCipher::~StreamCipher() {}

#if defined(BOTAN_HAS_CHACHA)
BOTAN_REGISTER_T_1LEN(StreamCipher, ChaCha, 20);
#endif

#if defined(BOTAN_HAS_SALSA20)
BOTAN_REGISTER_T_NOARGS(StreamCipher, Salsa20);
#endif

#if defined(BOTAN_HAS_SHAKE_CIPHER)
BOTAN_REGISTER_NAMED_T(StreamCipher, "SHAKE-128", SHAKE_128, make_new_T<SHAKE_128>);
#endif

#if defined(BOTAN_HAS_CTR_BE)
BOTAN_REGISTER_NAMED_T(StreamCipher, "CTR-BE", CTR_BE, CTR_BE::make);
#endif

#if defined(BOTAN_HAS_OFB)
BOTAN_REGISTER_NAMED_T(StreamCipher, "OFB", OFB, OFB::make);
#endif

#if defined(BOTAN_HAS_RC4)
BOTAN_REGISTER_NAMED_T(StreamCipher, "RC4", RC4, RC4::make);
#endif

}
