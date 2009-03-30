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
      void randomize(byte[], u32bit);
      bool is_seeded() const;
      void clear() throw();
      std::string name() const;

      void reseed(u32bit poll_bits);
      void add_entropy_source(EntropySource*);
      void add_entropy(const byte[], u32bit);

      ANSI_X931_RNG(BlockCipher*, RandomNumberGenerator*);
      ~ANSI_X931_RNG();
   private:
      void rekey();
      void update_buffer();

      BlockCipher* cipher;
      RandomNumberGenerator* prng;
      SecureVector<byte> V, R;
      u32bit position;
   };

}

#endif
