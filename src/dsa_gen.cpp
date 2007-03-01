/*************************************************
* DSA Parameter Generation Source File           *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/dl_group.h>
#include <botan/numthry.h>
#include <botan/libstate.h>
#include <botan/lookup.h>
#include <botan/bit_ops.h>
#include <botan/parsing.h>
#include <botan/rng.h>
#include <algorithm>
#include <memory>

namespace Botan {

namespace {

/*************************************************
* Increment the seed by one                      *
*************************************************/
void increment(SecureVector<byte>& seed)
   {
   for(u32bit j = seed.size(); j > 0; --j)
      if(++seed[j-1])
         break;
   }

}

/*************************************************
* Attempt DSA prime generation with given seed   *
*************************************************/
bool DL_Group::generate_dsa_primes(BigInt& p, BigInt& q,
                                   const byte const_seed[], u32bit seed_len,
                                   u32bit pbits, u32bit counter_start)
   {
   if(seed_len < 20)
      throw Invalid_Argument("DSA prime generation needs a seed "
                             "at least 160 bits long");
   if((pbits % 64 != 0) || (pbits > 1024) || (pbits < 512))
      throw Invalid_Argument("DSA prime generation algorithm does not support "
                             "prime size " + to_string(pbits));

   std::auto_ptr<HashFunction> sha1(get_hash("SHA-1"));

   SecureVector<byte> seed(const_seed, seed_len);

   SecureVector<byte> qhash = sha1->process(seed);
   increment(seed);
   SecureVector<byte> qhash2 = sha1->process(seed);
   xor_buf(qhash, qhash2, qhash.size());

   qhash[0] |= 0x80;
   qhash[19] |= 0x01;
   q.binary_decode(qhash, qhash.size());
   if(!is_prime(q))
      return false;
   global_state().pulse(PRIME_FOUND);

   u32bit n = (pbits-1) / 160, b = (pbits-1) % 160;
   SecureVector<byte> W(20 * (n+1));
   BigInt X;

   for(u32bit j = 0; j != counter_start; ++j)
      for(u32bit k = 0; k != n + 1; ++k)
         increment(seed);

   for(u32bit j = 0; j != 4096 - counter_start; ++j)
      {
      global_state().pulse(PRIME_SEARCHING);

      for(u32bit k = 0; k != n + 1; ++k)
         {
         increment(seed);
         sha1->update(seed);
         sha1->final(W + 20 * (n-k));
         }
      X.binary_decode(W + (20 - 1 - b/8), W.size() - (20 - 1 - b/8));
      X.set_bit(pbits-1);

      p = X - (X % (2*q) - 1);

      if(p.bits() == pbits && is_prime(p))
         {
         global_state().pulse(PRIME_FOUND);
         return true;
         }
      }
   return false;
   }

/*************************************************
* Generate DSA Primes                            *
*************************************************/
SecureVector<byte> DL_Group::generate_dsa_primes(BigInt& p, BigInt& q,
                                                 u32bit pbits)
   {
   SecureVector<byte> seed(20);

   while(true)
      {
      Global_RNG::randomize(seed, seed.size());
      global_state().pulse(PRIME_SEARCHING);
      if(generate_dsa_primes(p, q, seed, seed.size(), pbits, 0))
         return seed;
      }
   }

}
