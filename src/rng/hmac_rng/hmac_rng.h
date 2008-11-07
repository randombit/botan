/*************************************************
* HMAC RNG                                       *
* (C) 2008 Jack Lloyd                            *
*************************************************/

#ifndef BOTAN_HMAC_RNG_H__
#define BOTAN_HMAC_RNG_H__

#include <botan/rng.h>
#include <botan/base.h>
#include <vector>

namespace Botan {

/**
HMAC_RNG - based on the design described in "On Extract-then-Expand
Key Derivation Functions and an HMAC-based KDF" by Hugo Krawczyk
(henceforce, 'E-t-E')

However it actually can be parameterized with any two MAC functions,
not restricted to HMAC (this variation is also described in Krawczyk's
paper), for instance one could use HMAC(SHA-512) as the extractor
and CMAC(AES-256) as the PRF.
*/
class BOTAN_DLL HMAC_RNG : public RandomNumberGenerator
   {
   public:
      void randomize(byte buf[], u32bit len);
      bool is_seeded() const;
      void clear() throw();
      std::string name() const;

      void reseed();
      void add_entropy_source(EntropySource* es);
      void add_entropy(const byte[], u32bit);

      HMAC_RNG(MessageAuthenticationCode* extractor,
               MessageAuthenticationCode* prf);

      ~HMAC_RNG();
   private:
      void reseed_with_input(const byte input[], u32bit length);

      MessageAuthenticationCode* extractor;
      MessageAuthenticationCode* prf;

      std::vector<EntropySource*> entropy_sources;
      u32bit entropy;

      SecureVector<byte> K, io_buffer;
      u32bit counter, source_index;
   };

}

#endif
