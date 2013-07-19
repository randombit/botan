/*
* Randpool
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/randpool.h>
#include <botan/get_byte.h>
#include <botan/internal/xor_buf.h>
#include <botan/internal/stl_util.h>
#include <algorithm>

namespace Botan {

namespace {

/*
* PRF based on a MAC
*/
enum RANDPOOL_PRF_TAG {
   CIPHER_KEY = 0,
   MAC_KEY    = 1,
   GEN_OUTPUT = 2
};

}

/*
* Generate a buffer of random bytes
*/
void Randpool::randomize(byte out[], size_t length)
   {
   if(!is_seeded())
      throw PRNG_Unseeded(name());

   update_buffer();
   while(length)
      {
      const size_t copied = std::min<size_t>(length, buffer.size());
      copy_mem(out, &buffer[0], copied);
      out += copied;
      length -= copied;
      update_buffer();
      }
   }

/*
* Refill the output buffer
*/
void Randpool::update_buffer()
   {
   for(size_t i = 0; i != counter.size(); ++i)
      if(++counter[i])
         break;

   mac->update(static_cast<byte>(GEN_OUTPUT));
   mac->update(counter);
   SecureVector<byte> mac_val = mac->final();

   for(size_t i = 0; i != mac_val.size(); ++i)
      buffer[i % buffer.size()] ^= mac_val[i];
   cipher->encrypt(buffer);

   if(counter[0] % ITERATIONS_BEFORE_RESEED == 0)
      mix_pool();
   }

/*
* Mix the entropy pool
*/
void Randpool::mix_pool()
   {
   const size_t BLOCK_SIZE = cipher->block_size();

   mac->update(static_cast<byte>(MAC_KEY));
   mac->update(pool);
   mac->set_key(mac->final());

   mac->update(static_cast<byte>(CIPHER_KEY));
   mac->update(pool);
   cipher->set_key(mac->final());

   xor_buf(pool, buffer, BLOCK_SIZE);
   cipher->encrypt(pool);
   for(size_t i = 1; i != POOL_BLOCKS; ++i)
      {
      const byte* previous_block = &pool[BLOCK_SIZE*(i-1)];
      byte* this_block = &pool[BLOCK_SIZE*i];
      xor_buf(this_block, previous_block, BLOCK_SIZE);
      cipher->encrypt(this_block);
      }

   update_buffer();
   }

/*
* Reseed the internal state
*/
void Randpool::reseed(size_t poll_bits)
   {
   Entropy_Accumulator_BufferedComputation accum(*mac, poll_bits);

   if(!entropy_sources.empty())
      {
      size_t poll_attempt = 0;

      while(!accum.polling_goal_achieved() && poll_attempt < poll_bits)
         {
         entropy_sources[poll_attempt % entropy_sources.size()]->poll(accum);
         ++poll_attempt;
         }
      }

   SecureVector<byte> mac_val = mac->final();

   xor_buf(pool, mac_val, mac_val.size());
   mix_pool();

   if(accum.bits_collected() >= poll_bits)
      seeded = true;
   }

/*
* Add user-supplied entropy
*/
void Randpool::add_entropy(const byte input[], size_t length)
   {
   SecureVector<byte> mac_val = mac->process(input, length);
   xor_buf(pool, mac_val, mac_val.size());
   mix_pool();

   if(length)
      seeded = true;
   }

/*
* Add another entropy source to the list
*/
void Randpool::add_entropy_source(EntropySource* src)
   {
   entropy_sources.push_back(src);
   }

/*
* Clear memory of sensitive data
*/
void Randpool::clear()
   {
   cipher->clear();
   mac->clear();
   zeroise(pool);
   zeroise(buffer);
   zeroise(counter);
   seeded = false;
   }

/*
* Return the name of this type
*/
std::string Randpool::name() const
   {
   return "Randpool(" + cipher->name() + "," + mac->name() + ")";
   }

/*
* Randpool Constructor
*/
Randpool::Randpool(BlockCipher* cipher_in,
                   MessageAuthenticationCode* mac_in,
                   size_t pool_blocks,
                   size_t iter_before_reseed) :
   ITERATIONS_BEFORE_RESEED(iter_before_reseed),
   POOL_BLOCKS(pool_blocks),
   cipher(cipher_in),
   mac(mac_in)
   {
   const size_t BLOCK_SIZE = cipher->block_size();
   const size_t OUTPUT_LENGTH = mac->output_length();

   if(OUTPUT_LENGTH < BLOCK_SIZE ||
      !cipher->valid_keylength(OUTPUT_LENGTH) ||
      !mac->valid_keylength(OUTPUT_LENGTH))
      {
      delete cipher;
      delete mac;
      throw Internal_Error("Randpool: Invalid algorithm combination");
      }

   buffer.resize(BLOCK_SIZE);
   pool.resize(POOL_BLOCKS * BLOCK_SIZE);
   counter.resize(12);
   seeded = false;
   }

/*
* Randpool Destructor
*/
Randpool::~Randpool()
   {
   delete cipher;
   delete mac;

   std::for_each(entropy_sources.begin(), entropy_sources.end(),
                 del_fun<EntropySource>());
   }

}
