/*
* ANSI X9.31 RNG
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/x931_rng.h>
#include <botan/xor_buf.h>
#include <algorithm>

namespace Botan {

/**
* Generate a buffer of random bytes
*/
void ANSI_X931_RNG::randomize(byte out[], u32bit length)
   {
   if(!is_seeded())
      throw PRNG_Unseeded(name());

   while(length)
      {
      if(position == R.size())
         update_buffer();

      const u32bit copied = std::min(length, R.size() - position);

      copy_mem(out, R + position, copied);
      out += copied;
      length -= copied;
      position += copied;
      }
   }

/**
* Refill the internal state
*/
void ANSI_X931_RNG::update_buffer()
   {
   SecureVector<byte> DT(cipher->BLOCK_SIZE);

   prng->randomize(DT, DT.size());
   cipher->encrypt(DT);

   xor_buf(R, V, DT, cipher->BLOCK_SIZE);
   cipher->encrypt(R);

   xor_buf(V, R, DT, cipher->BLOCK_SIZE);
   cipher->encrypt(V);

   position = 0;
   }

/**
* Reset V and the cipher key with new values
*/
void ANSI_X931_RNG::rekey()
   {
   if(prng->is_seeded())
      {
      SecureVector<byte> key(cipher->MAXIMUM_KEYLENGTH);
      prng->randomize(key, key.size());
      cipher->set_key(key, key.size());

      if(V.size() != cipher->BLOCK_SIZE)
         V.create(cipher->BLOCK_SIZE);
      prng->randomize(V, V.size());

      update_buffer();
      }
   }

/**
* Reseed the internal state
*/
void ANSI_X931_RNG::reseed(u32bit poll_bits)
   {
   prng->reseed(poll_bits);
   rekey();
   }

/**
* Add a entropy source to the underlying PRNG
*/
void ANSI_X931_RNG::add_entropy_source(EntropySource* src)
   {
   prng->add_entropy_source(src);
   }

/**
* Add some entropy to the underlying PRNG
*/
void ANSI_X931_RNG::add_entropy(const byte input[], u32bit length)
   {
   prng->add_entropy(input, length);
   rekey();
   }

/**
* Check if the the PRNG is seeded
*/
bool ANSI_X931_RNG::is_seeded() const
   {
   return V.has_items();
   }

/**
* Clear memory of sensitive data
*/
void ANSI_X931_RNG::clear() throw()
   {
   cipher->clear();
   prng->clear();
   R.clear();
   V.destroy();

   position = 0;
   }

/**
* Return the name of this type
*/
std::string ANSI_X931_RNG::name() const
   {
   return "X9.31(" + cipher->name() + ")";
   }

/**
* ANSI X931 RNG Constructor
*/
ANSI_X931_RNG::ANSI_X931_RNG(BlockCipher* cipher_in,
                             RandomNumberGenerator* prng_in)
   {
   if(!prng_in || !cipher_in)
      throw Invalid_Argument("ANSI_X931_RNG constructor: NULL arguments");

   cipher = cipher_in;
   prng = prng_in;

   R.create(cipher->BLOCK_SIZE);
   position = 0;
   }

/**
* ANSI X931 RNG Destructor
*/
ANSI_X931_RNG::~ANSI_X931_RNG()
   {
   delete cipher;
   delete prng;
   }

}
