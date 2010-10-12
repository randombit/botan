/*
* ANSI X9.31 RNG
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ANSI_X931_RNG_H__
#define BOTAN_ANSI_X931_RNG_H__

#include <botan/rng.h>
#include <botan/block_cipher.h>

namespace Botan {

/**
* ANSI X9.31 RNG
*/
class BOTAN_DLL ANSI_X931_RNG : public RandomNumberGenerator
   {
   public:
      void randomize(byte[], size_t);
      bool is_seeded() const;
      void clear();
      std::string name() const;

      void reseed(size_t poll_bits);
      void add_entropy_source(EntropySource*);
      void add_entropy(const byte[], size_t);

      /**
      * @param cipher the block cipher to use in this PRNG
      * @param rng the underlying PRNG for generating inputs
      * (eg, an HMAC_RNG)
      */
      ANSI_X931_RNG(BlockCipher* cipher,
                    RandomNumberGenerator* rng);
      ~ANSI_X931_RNG();
   private:
      void rekey();
      void update_buffer();

      BlockCipher* cipher;
      RandomNumberGenerator* prng;
      SecureVector<byte> V, R;
      size_t position;
   };

}

#endif
