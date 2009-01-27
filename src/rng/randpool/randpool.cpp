/*
* Randpool Source File
* (C) 1999-2009 Jack Lloyd
*/

#include <botan/randpool.h>
#include <botan/loadstor.h>
#include <botan/xor_buf.h>
#include <botan/util.h>
#include <botan/stl_util.h>
#include <algorithm>

namespace Botan {

namespace {

/**
* PRF based on a MAC
*/
enum RANDPOOL_PRF_TAG {
   CIPHER_KEY = 0,
   MAC_KEY    = 1,
   GEN_OUTPUT = 2
};

}

/**
* Generate a buffer of random bytes
*/
void Randpool::randomize(byte out[], u32bit length)
   {
   if(!is_seeded())
      {
      reseed(8 * mac->OUTPUT_LENGTH);

      if(!is_seeded())
         throw PRNG_Unseeded(name());
      }

   update_buffer();
   while(length)
      {
      const u32bit copied = std::min(length, buffer.size());
      copy_mem(out, buffer.begin(), copied);
      out += copied;
      length -= copied;
      update_buffer();
      }
   }

/**
* Refill the output buffer
*/
void Randpool::update_buffer()
   {
   const u64bit timestamp = system_time();

   for(u32bit i = 0; i != counter.size(); ++i)
      if(++counter[i])
         break;
   store_be(timestamp, counter + 4);

   mac->update(static_cast<byte>(GEN_OUTPUT));
   mac->update(counter, counter.size());
   SecureVector<byte> mac_val = mac->final();

   for(u32bit i = 0; i != mac_val.size(); ++i)
      buffer[i % buffer.size()] ^= mac_val[i];
   cipher->encrypt(buffer);

   if(counter[0] % ITERATIONS_BEFORE_RESEED == 0)
      mix_pool();
   }

/**
* Mix the entropy pool
*/
void Randpool::mix_pool()
   {
   const u32bit BLOCK_SIZE = cipher->BLOCK_SIZE;

   mac->update(static_cast<byte>(MAC_KEY));
   mac->update(pool, pool.size());
   mac->set_key(mac->final());

   mac->update(static_cast<byte>(CIPHER_KEY));
   mac->update(pool, pool.size());
   cipher->set_key(mac->final());

   xor_buf(pool, buffer, BLOCK_SIZE);
   cipher->encrypt(pool);
   for(u32bit i = 1; i != POOL_BLOCKS; ++i)
      {
      const byte* previous_block = pool + BLOCK_SIZE*(i-1);
      byte* this_block = pool + BLOCK_SIZE*i;
      xor_buf(this_block, previous_block, BLOCK_SIZE);
      cipher->encrypt(this_block);
      }

   update_buffer();
   }

/**
* Reseed the internal state
*/
void Randpool::reseed(u32bit poll_bits)
   {
   Entropy_Accumulator accum(poll_bits);

   for(u32bit i = 0; i != entropy_sources.size(); ++i)
      {
      entropy_sources[i]->poll(accum);

      if(accum.polling_goal_achieved())
         break;
      }

   SecureVector<byte> mac_val = mac->process(accum.get_entropy_buffer());

   xor_buf(pool, mac_val, mac_val.size());
   mix_pool();

   entropy = std::min<u32bit>(entropy + accum.bits_collected(),
                              8 * mac_val.size());
   }

/**
* Add user-supplied entropy
*/
void Randpool::add_entropy(const byte input[], u32bit length)
   {
   SecureVector<byte> mac_val = mac->process(input, length);
   xor_buf(pool, mac_val, mac_val.size());
   mix_pool();

   // Assume 1 bit conditional entropy per byte of input
   entropy = std::min<u32bit>(entropy + length, 8 * mac_val.size());
   }

/**
* Add another entropy source to the list
*/
void Randpool::add_entropy_source(EntropySource* src)
   {
   entropy_sources.push_back(src);
   }

/**
* Check if the the pool is seeded
*/
bool Randpool::is_seeded() const
   {
   return (entropy >= 7 * mac->OUTPUT_LENGTH);
   }

/**
* Clear memory of sensitive data
*/
void Randpool::clear() throw()
   {
   cipher->clear();
   mac->clear();
   pool.clear();
   buffer.clear();
   counter.clear();
   entropy = 0;
   }

/**
* Return the name of this type
*/
std::string Randpool::name() const
   {
   return "Randpool(" + cipher->name() + "," + mac->name() + ")";
   }

/**
* Randpool Constructor
*/
Randpool::Randpool(BlockCipher* cipher_in,
                   MessageAuthenticationCode* mac_in,
                   u32bit pool_blocks,
                   u32bit iter_before_reseed) :
   ITERATIONS_BEFORE_RESEED(iter_before_reseed),
   POOL_BLOCKS(pool_blocks),
   cipher(cipher_in),
   mac(mac_in)
   {
   const u32bit BLOCK_SIZE = cipher->BLOCK_SIZE;
   const u32bit OUTPUT_LENGTH = mac->OUTPUT_LENGTH;

   if(OUTPUT_LENGTH < BLOCK_SIZE ||
      !cipher->valid_keylength(OUTPUT_LENGTH) ||
      !mac->valid_keylength(OUTPUT_LENGTH))
      {
      delete cipher;
      delete mac;
      throw Internal_Error("Randpool: Invalid algorithm combination " +
                           cipher->name() + "/" + mac->name());
      }

   buffer.create(BLOCK_SIZE);
   pool.create(POOL_BLOCKS * BLOCK_SIZE);
   counter.create(12);
   entropy = 0;
   }

/**
* Randpool Destructor
*/
Randpool::~Randpool()
   {
   delete cipher;
   delete mac;

   std::for_each(entropy_sources.begin(), entropy_sources.end(),
                 del_fun<EntropySource>());

   entropy = 0;
   }

}
