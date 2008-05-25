/*************************************************
* SHA1PRNG Source File                           *
* (C) 2007 FlexSecure GmbH / Manuel Hartl        *
*************************************************/

#include <botan/types.h>
#include <botan/sha1prng.h>
#include <botan/lookup.h>
#include <botan/randpool.h>
#include <botan/bit_ops.h>
#include <algorithm>
#include <iostream>

namespace Botan {

static unsigned short SHA1_BYTES = 20;

/*************************************************
* Generate a buffer of random bytes              *
*************************************************/
void SHA1PRNG::randomize(byte result[], u32bit length) throw(PRNG_Unseeded)
   {
   if(!is_seeded()) {
      throw PRNG_Unseeded(name());
   }

   SecureVector<byte> remainder_tmp = remainder;

   u32bit resultIndex=0;
   /**
    * use ramining bytes from buffer for result
    */
   if (remCount>0)
   {
       u32bit remainderCountIndex=remCount;
       unsigned int j = length >= (unsigned)(SHA1_BYTES - remCount) ? SHA1_BYTES - remCount : length;

       for(;resultIndex < j;resultIndex++)
       {
           result[resultIndex] = remainder_tmp[remainderCountIndex];
           remainder_tmp[remainderCountIndex++] = 0;
       }

       remCount += j;
   }

   /**
    * fill result with fresh random bytes
    */
   while (resultIndex < length)
       {
       hash->update(state.begin(),SHA1_BYTES);
       hash->final(remainder_tmp.begin());
       update_state(remainder_tmp.begin());
       int k=length-1 <= SHA1_BYTES ? length : SHA1_BYTES;
       for (int j = 0;j < k; j++)
       {
           result[resultIndex++] = remainder_tmp[j];
           remainder_tmp[j] = 0;
       }
       remCount+=k;
       }
   remainder = remainder_tmp;
   remCount %=SHA1_BYTES;
   }

/*************************************************
* Refill the internal state                      *
*************************************************/
void SHA1PRNG::update_state(byte update[])
   {
    signed int i = 1;
    bool flag2 = false;
    for(int k = 0; k < SHA1_BYTES; k++)
    {
    	int b1 = state[k]%256;
  		if (b1>128)
  		{
  			b1-=256;
  		}

  		int b2 = update[k]%256;
  		if (b2>128)
  		{
  			b2-=256;
  		}
    	int j = b1+b2+i;
        if (j>256)
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
     if (prng->is_seeded())
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
SHA1PRNG::SHA1PRNG(SharedPtrConverter<RandomNumberGenerator> prng_ptr) : hash(get_hash("SHA1").release())
   {
   prng = (prng_ptr.get_shared().get() ? prng_ptr.get_shared() : std::tr1::shared_ptr<RandomNumberGenerator>(new Randpool));
   remCount=0;
   state.grow_to(SHA1_BYTES);
   for (int i=0;i<SHA1_BYTES;i++)
       {
	   state[i]=0;
       }

   remainder.grow_to(SHA1_BYTES);
   }

/*************************************************
* SHA1PRNG Destructor                            *
*************************************************/
SHA1PRNG::~SHA1PRNG()
   {

   }

}
