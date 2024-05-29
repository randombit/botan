/*
* DSA Parameter Generation
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/primality.h>

#include <botan/hash.h>
#include <botan/numthry.h>
#include <botan/reducer.h>
#include <botan/rng.h>
#include <botan/internal/fmt.h>

namespace Botan {

namespace {

/*
* Check if this size is allowed by FIPS 186-3
*/
bool fips186_3_valid_size(size_t pbits, size_t qbits) {
   if(qbits == 160) {
      return (pbits == 1024);
   }

   if(qbits == 224) {
      return (pbits == 2048);
   }

   if(qbits == 256) {
      return (pbits == 2048 || pbits == 3072);
   }

   return false;
}

// qbits assumed to be a valid size for FIPS param gen
std::string hash_function_for(size_t qbits) {
   if(qbits == 160) {
      return "SHA-1";
   }

   return "SHA-" + std::to_string(qbits);
}

}  // namespace

/*
* Attempt DSA prime generation with given seed
*/
bool generate_dsa_primes(RandomNumberGenerator& rng,
                         BigInt& p,
                         BigInt& q,
                         size_t pbits,
                         size_t qbits,
                         const std::vector<uint8_t>& seed_c,
                         size_t offset) {
   if(!fips186_3_valid_size(pbits, qbits)) {
      throw Invalid_Argument(fmt("FIPS 186-3 does not allow DSA domain parameters of {}/{} bits long", pbits, qbits));
   }

   if(seed_c.size() * 8 < qbits) {
      throw Invalid_Argument(
         fmt("Generating a DSA parameter set with a {} bit long q requires a seed at least as many bits long", qbits));
   }

   const std::string hash_name = hash_function_for(qbits);
   auto hash = HashFunction::create_or_throw(hash_name);

   const size_t HASH_SIZE = hash->output_length();

   class Seed final {
      public:
         explicit Seed(const std::vector<uint8_t>& s) : m_seed(s) {}

         const std::vector<uint8_t>& value() const { return m_seed; }

         Seed& operator++() {
            for(size_t j = m_seed.size(); j > 0; --j) {
               if(++m_seed[j - 1]) {
                  break;
               }
            }
            return (*this);
         }

      private:
         std::vector<uint8_t> m_seed;
   };

   Seed seed(seed_c);

   q._assign_from_bytes(hash->process(seed.value()));
   q.set_bit(qbits - 1);
   q.set_bit(0);

   if(!is_prime(q, rng, 128, true)) {
      return false;
   }

   const size_t n = (pbits - 1) / (HASH_SIZE * 8), b = (pbits - 1) % (HASH_SIZE * 8);

   BigInt X;
   std::vector<uint8_t> V(HASH_SIZE * (n + 1));

   Modular_Reducer mod_2q(2 * q);

   for(size_t j = 0; j != 4 * pbits; ++j) {
      for(size_t k = 0; k <= n; ++k) {
         ++seed;
         hash->update(seed.value());
         hash->final(&V[HASH_SIZE * (n - k)]);
      }

      if(j >= offset) {
         X._assign_from_bytes(std::span{V}.subspan(HASH_SIZE - 1 - b / 8));
         X.set_bit(pbits - 1);

         p = X - (mod_2q.reduce(X) - 1);

         if(p.bits() == pbits && is_prime(p, rng, 128, true)) {
            return true;
         }
      }
   }
   return false;
}

/*
* Generate DSA Primes
*/
std::vector<uint8_t> generate_dsa_primes(RandomNumberGenerator& rng, BigInt& p, BigInt& q, size_t pbits, size_t qbits) {
   while(true) {
      std::vector<uint8_t> seed(qbits / 8);
      rng.randomize(seed.data(), seed.size());

      if(generate_dsa_primes(rng, p, q, pbits, qbits, seed)) {
         return seed;
      }
   }
}

}  // namespace Botan
