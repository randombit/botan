/*
* Randpool
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_RANDPOOL_H__
#define BOTAN_RANDPOOL_H__

#include <botan/rng.h>
#include <botan/block_cipher.h>
#include <botan/mac.h>
#include <vector>

namespace Botan {

/**
* Randpool
*/
class BOTAN_DLL Randpool : public RandomNumberGenerator
   {
   public:
      void randomize(byte[], u32bit);
      bool is_seeded() const { return seeded; }
      void clear() throw();
      std::string name() const;

      void reseed(u32bit bits_to_collect);
      void add_entropy_source(EntropySource* es);
      void add_entropy(const byte input[], u32bit length);

      Randpool(BlockCipher* cipher, MessageAuthenticationCode* mac,
               u32bit pool_blocks = 32,
               u32bit iterations_before_reseed = 128);

      ~Randpool();
   private:
      void update_buffer();
      void mix_pool();

      u32bit ITERATIONS_BEFORE_RESEED, POOL_BLOCKS;
      BlockCipher* cipher;
      MessageAuthenticationCode* mac;

      std::vector<EntropySource*> entropy_sources;
      SecureVector<byte> pool, buffer, counter;
      bool seeded;
   };

}

#endif
