/*
* ANSI X9.31 RNG
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/x931_rng.h>
#include <botan/internal/xor_buf.h>
#include <algorithm>

namespace Botan {

/*
* Generate a buffer of random bytes
*/
void ANSI_X931_RNG::randomize(byte out[], size_t length)
   {
   if(!is_seeded())
      throw PRNG_Unseeded(name());

   while(length)
      {
      if(position == R.size())
         update_buffer();

      const size_t copied = std::min<size_t>(length, R.size() - position);

      copy_mem(out, &R[position], copied);
      out += copied;
      length -= copied;
      position += copied;
      }
   }

/*
* Refill the internal state
*/
void ANSI_X931_RNG::update_buffer()
   {
   const size_t BLOCK_SIZE = cipher->block_size();

   secure_vector<byte> DT = prng->random_vec(BLOCK_SIZE);
   cipher->encrypt(DT);

   xor_buf(&R[0], &V[0], &DT[0], BLOCK_SIZE);
   cipher->encrypt(R);

   xor_buf(&V[0], &R[0], &DT[0], BLOCK_SIZE);
   cipher->encrypt(V);

   position = 0;
   }

/*
* Reset V and the cipher key with new values
*/
void ANSI_X931_RNG::rekey()
   {
   const size_t BLOCK_SIZE = cipher->block_size();

   if(prng->is_seeded())
      {
      cipher->set_key(prng->random_vec(cipher->maximum_keylength()));

      if(V.size() != BLOCK_SIZE)
         V.resize(BLOCK_SIZE);
      prng->randomize(&V[0], V.size());

      update_buffer();
      }
   }

/*
* Reseed the internal state
*/
void ANSI_X931_RNG::reseed(size_t poll_bits)
   {
   prng->reseed(poll_bits);
   rekey();
   }

/*
* Add some entropy to the underlying PRNG
*/
void ANSI_X931_RNG::add_entropy(const byte input[], size_t length)
   {
   prng->add_entropy(input, length);
   rekey();
   }

/*
* Check if the the PRNG is seeded
*/
bool ANSI_X931_RNG::is_seeded() const
   {
   return (V.size() > 0);
   }

/*
* Clear memory of sensitive data
*/
void ANSI_X931_RNG::clear()
   {
   cipher->clear();
   prng->clear();
   zeroise(R);
   V.clear();

   position = 0;
   }

/*
* Return the name of this type
*/
std::string ANSI_X931_RNG::name() const
   {
   return "X9.31(" + cipher->name() + ")";
   }

/*
* ANSI X931 RNG Constructor
*/
ANSI_X931_RNG::ANSI_X931_RNG(BlockCipher* cipher_in,
                             RandomNumberGenerator* prng_in)
   {
   if(!prng_in || !cipher_in)
      throw Invalid_Argument("ANSI_X931_RNG constructor: NULL arguments");

   cipher = cipher_in;
   prng = prng_in;

   R.resize(cipher->block_size());
   position = 0;
   }

/*
* ANSI X931 RNG Destructor
*/
ANSI_X931_RNG::~ANSI_X931_RNG()
   {
   delete cipher;
   delete prng;
   }

}
