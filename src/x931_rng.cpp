/*************************************************
* ANSI X9.31 RNG Source File                     *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/x931_rng.h>
#include <botan/lookup.h>
#include <botan/randpool.h>
#include <botan/bit_ops.h>
#include <algorithm>

namespace Botan {

/*************************************************
* Generate a buffer of random bytes              *
*************************************************/
void ANSI_X931_RNG::randomize(byte out[], u32bit length) throw(PRNG_Unseeded)
   {
   if(!is_seeded())
      throw PRNG_Unseeded(name());

   while(length)
      {
      const u32bit copied = std::min(length, R.size() - position);

      copy_mem(out, R + position, copied);
      out += copied;
      length -= copied;
      position += copied;

      if(position == R.size())
         {
         update_buffer();
         position = 0;
         }
      }
   }

/*************************************************
* Refill the internal state                      *
*************************************************/
void ANSI_X931_RNG::update_buffer()
   {
   const u32bit BLOCK_SIZE = cipher->BLOCK_SIZE;

   SecureVector<byte> DT(BLOCK_SIZE);

   prng->randomize(DT, DT.size());
   cipher->encrypt(DT);

   xor_buf(R, V, DT, BLOCK_SIZE);
   cipher->encrypt(R);

   xor_buf(V, R, DT, BLOCK_SIZE);
   cipher->encrypt(V);
   }

/*************************************************
* Add entropy to internal state                  *
*************************************************/
void ANSI_X931_RNG::add_randomness(const byte data[], u32bit length)
   {
   prng->add_entropy(data, length);

   if(is_seeded())
      {
      SecureVector<byte> key(cipher->MAXIMUM_KEYLENGTH);
      prng->randomize(key, key.size());
      cipher->set_key(key, key.size());

      prng->randomize(V, V.size());

      update_buffer();
      }
   }

/*************************************************
* Check if the the PRNG is seeded                *
*************************************************/
bool ANSI_X931_RNG::is_seeded() const
   {
   return prng->is_seeded();
   }

/*************************************************
* Clear memory of sensitive data                 *
*************************************************/
void ANSI_X931_RNG::clear() throw()
   {
   cipher->clear();
   prng->clear();
   R.clear();
   V.clear();

   position = 0;
   }

/*************************************************
* Return the name of this type                   *
*************************************************/
std::string ANSI_X931_RNG::name() const
   {
   return "X9.31(" + cipher->name() + ")";
   }

/*************************************************
* ANSI X931 RNG Constructor                      *
*************************************************/
ANSI_X931_RNG::ANSI_X931_RNG(const std::string& cipher_name,
                             RandomNumberGenerator* prng_ptr)
   {
   if(cipher_name == "")
      cipher = get_block_cipher("AES-256");
   else
      cipher = get_block_cipher(cipher_name);

   const u32bit BLOCK_SIZE = cipher->BLOCK_SIZE;

   V.create(BLOCK_SIZE);
   R.create(BLOCK_SIZE);

   prng = (prng_ptr ? prng_ptr : new Randpool);

   position = 0;
   }

/*************************************************
* ANSI X931 RNG Destructor                       *
*************************************************/
ANSI_X931_RNG::~ANSI_X931_RNG()
   {
   delete cipher;
   delete prng;
   }

}
