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
      void randomize(byte[], size_t);
      bool is_seeded() const { return seeded; }
      void clear();
      std::string name() const;

      void reseed(size_t bits_to_collect);
      void add_entropy_source(EntropySource* es);
      void add_entropy(const byte input[], size_t length);

      /**
      * @param cipher a block cipher to use
      * @param mac a message authentication code to use
      * @param pool_blocks how many cipher blocks to use for the pool
      * @param iterations_before_reseed how many times we'll use the
      * internal state to generate output before reseeding
      */
      Randpool(BlockCipher* cipher,
               MessageAuthenticationCode* mac,
               size_t pool_blocks = 32,
               size_t iterations_before_reseed = 128);

      ~Randpool();
   private:
      void update_buffer();
      void mix_pool();

      size_t ITERATIONS_BEFORE_RESEED, POOL_BLOCKS;
      BlockCipher* cipher;
      MessageAuthenticationCode* mac;

      std::vector<EntropySource*> entropy_sources;
      SecureVector<byte> pool, buffer, counter;
      bool seeded;
   };

}

#endif
