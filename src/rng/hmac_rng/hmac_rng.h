/*
* HMAC RNG
* (C) 2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_HMAC_RNG_H__
#define BOTAN_HMAC_RNG_H__

#include <botan/mac.h>
#include <botan/rng.h>
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
      void randomize(byte buf[], size_t len);
      bool is_seeded() const { return seeded; }
      void clear();
      std::string name() const;

      void reseed(size_t poll_bits);
      void add_entropy_source(EntropySource* es);
      void add_entropy(const byte[], size_t);

      /**
      * @param extractor a MAC used for extracting the entropy
      * @param prf a MAC used as a PRF using HKDF construction
      */
      HMAC_RNG(MessageAuthenticationCode* extractor,
               MessageAuthenticationCode* prf);

      ~HMAC_RNG();
   private:
      MessageAuthenticationCode* extractor;
      MessageAuthenticationCode* prf;

      std::vector<EntropySource*> entropy_sources;
      bool seeded;

      SecureVector<byte> K, io_buffer;
      size_t output_since_reseed;
      u32bit counter;
   };

}

#endif
