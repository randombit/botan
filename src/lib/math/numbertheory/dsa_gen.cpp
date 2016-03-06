/*
* DSA Parameter Generation
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/numthry.h>
#include <botan/hash.h>
#include <botan/parsing.h>
#include <algorithm>

namespace Botan {

namespace {

/*
* Check if this size is allowed by FIPS 186-3
*/
bool fips186_3_valid_size(size_t pbits, size_t qbits)
   {
   if(qbits == 160)
      return (pbits == 512 || pbits == 768 || pbits == 1024);

   if(qbits == 224)
      return (pbits == 2048);

   if(qbits == 256)
      return (pbits == 2048 || pbits == 3072);

   return false;
   }

}

/*
* Attempt DSA prime generation with given seed
*/
bool generate_dsa_primes(RandomNumberGenerator& rng,
                         BigInt& p, BigInt& q,
                         size_t pbits, size_t qbits,
                         const std::vector<byte>& seed_c)
   {
   if(!fips186_3_valid_size(pbits, qbits))
      throw Invalid_Argument(
         "FIPS 186-3 does not allow DSA domain parameters of " +
         std::to_string(pbits) + "/" + std::to_string(qbits) + " bits long");

   if(seed_c.size() * 8 < qbits)
      throw Invalid_Argument(
         "Generating a DSA parameter set with a " + std::to_string(qbits) +
         "long q requires a seed at least as many bits long");

   const std::string hash_name = "SHA-" + std::to_string(qbits);
   std::unique_ptr<HashFunction> hash(HashFunction::create(hash_name));
   if(!hash)
      throw Algorithm_Not_Found(hash_name);

   const size_t HASH_SIZE = hash->output_length();

   class Seed
      {
      public:
         explicit Seed(const std::vector<byte>& s) : m_seed(s) {}

         operator std::vector<byte>& () { return m_seed; }

         Seed& operator++()
            {
            for(size_t j = m_seed.size(); j > 0; --j)
               if(++m_seed[j-1])
                  break;
            return (*this);
            }
      private:
         std::vector<byte> m_seed;
      };

   Seed seed(seed_c);

   q.binary_decode(hash->process(seed));
   q.set_bit(qbits-1);
   q.set_bit(0);

   if(!is_prime(q, rng))
      return false;

   const size_t n = (pbits-1) / (HASH_SIZE * 8),
                b = (pbits-1) % (HASH_SIZE * 8);

   BigInt X;
   std::vector<byte> V(HASH_SIZE * (n+1));

   for(size_t j = 0; j != 4096; ++j)
      {
      for(size_t k = 0; k <= n; ++k)
         {
         ++seed;
         hash->update(seed);
         hash->final(&V[HASH_SIZE * (n-k)]);
         }

      X.binary_decode(&V[HASH_SIZE - 1 - b/8],
                      V.size() - (HASH_SIZE - 1 - b/8));
      X.set_bit(pbits-1);

      p = X - (X % (2*q) - 1);

      if(p.bits() == pbits && is_prime(p, rng))
         return true;
      }
   return false;
   }

/*
* Generate DSA Primes
*/
std::vector<byte> generate_dsa_primes(RandomNumberGenerator& rng,
                                      BigInt& p, BigInt& q,
                                      size_t pbits, size_t qbits)
   {
   while(true)
      {
      std::vector<byte> seed(qbits / 8);
      rng.randomize(seed.data(), seed.size());

      if(generate_dsa_primes(rng, p, q, pbits, qbits, seed))
         return seed;
      }
   }

}
