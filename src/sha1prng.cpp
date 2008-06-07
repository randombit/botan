/*************************************************
* SHA1PRNG Source File                           *
* (C) 2007 FlexSecure GmbH / Manuel Hartl        *
* (C) 2008 Jack Lloyd                            *
*************************************************/

#include <botan/sha1prng.h>
#include <botan/lookup.h>
#include <botan/bit_ops.h>
#include <algorithm>

namespace Botan {

/*************************************************
* Generate a buffer of random bytes              *
*************************************************/
void SHA1PRNG::randomize(byte result[], u32bit length) throw(PRNG_Unseeded)
   {
   if(!is_seeded())
      throw PRNG_Unseeded(name());

   const u32bit SHA1_BYTES = hash->OUTPUT_LENGTH;

   u32bit resultIndex=0;
   /**
    * use ramining bytes from buffer for result
    */
   if(buf_pos>0)
   {
       u32bit remainderCountIndex=buf_pos;
       unsigned int j = length >= (unsigned)(SHA1_BYTES - buf_pos) ? SHA1_BYTES - buf_pos : length;

       for(;resultIndex < j;resultIndex++)
       {
           result[resultIndex] = buffer[remainderCountIndex];
           buffer[remainderCountIndex++] = 0;
       }

       buf_pos += j;
   }

   /**
    * fill result with fresh random bytes
    */
   while(resultIndex < length)
       {
       hash->update(state.begin(),SHA1_BYTES);
       hash->final(buffer.begin());
       update_state(buffer.begin());
       int k=length-1 <= SHA1_BYTES ? length : SHA1_BYTES;
       for(int j = 0;j < k; j++)
       {
           result[resultIndex++] = buffer[j];
           buffer[j] = 0;
       }
       buf_pos+=k;
       }
   buf_pos %=SHA1_BYTES;
   }

/*************************************************
* Refill the internal state                      *
*************************************************/
void SHA1PRNG::update_state(byte update[])
   {
   signed int i = 1;
   bool flag2 = false;

   for(u32bit k = 0; k < state.size(); k++)
      {
      int b1 = state[k]%256;
      if(b1>128)
         {
         b1-=256;
         }

      int b2 = update[k]%256;
      if(b2>128)
         {
         b2-=256;
         }
      int j = b1+b2+i;
      if(j>256)
         {
         j-=256;
         }
      flag2 |= state.begin()[k] != (byte)j;
      state.begin()[k] = (byte)j;
      i = j >> 8;
      }

   if(!flag2)
      {
      state[0]++;
      }
   }

/*************************************************
* Add entropy to internal state                  *
*************************************************/
void SHA1PRNG::add_randomness(const byte data[], u32bit length)
   {
   prng->add_entropy(data, length);
   MemoryVector<byte> for_rand;
   for_rand.set(data, length);

   if(prng->is_seeded())
      {
      prng->randomize(for_rand, length);
      hash->clear();
      hash->update(for_rand,length);
      hash->final(state.begin());
      }
   }

/*************************************************
* Check if the RNG is seeded                     *
*************************************************/
bool SHA1PRNG::is_seeded() const
   {
   return prng->is_seeded();
   }

/*************************************************
* Clear memory of sensitive data                 *
*************************************************/
void SHA1PRNG::clear() throw()
   {
   hash->clear();
   prng->clear();
   }

/*************************************************
* Return the name of this type                   *
*************************************************/
std::string SHA1PRNG::name() const
   {
   return "SHA1PRNG";
   }

/*************************************************
* SHA1PRNG Constructor                           *
*************************************************/
SHA1PRNG::SHA1PRNG(RandomNumberGenerator* prng_ptr)
   {
   if(!prng_ptr)
      throw Invalid_Argument("SHA1PRNG constructor: NULL prng");

   hash = get_hash("SHA-1");
   prng = prng_ptr;

   buf_pos = 0;

   state.grow_to(hash->OUTPUT_LENGTH);
   buffer.grow_to(hash->OUTPUT_LENGTH);
   }

/*************************************************
* SHA1PRNG Destructor                            *
*************************************************/
SHA1PRNG::~SHA1PRNG()
   {
   delete hash;
   delete prng;
   }

}
