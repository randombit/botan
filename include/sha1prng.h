/*************************************************
* SHA1PRNG RNG Header File                       *
* (C) 2007 FlexSecure GmbH / Manuel Hartl        *
*************************************************/

#ifndef BOTAN_SHA1PRNG_H__
#define BOTAN_SHA1PRNG_H__

#include <botan/base.h>
#include <botan/mdx_hash.h>
#include <botan/freestore.h>

namespace Botan {

/*************************************************
* SHA1PRNG (propriery                            *
*************************************************/
class SHA1PRNG : public RandomNumberGenerator
   {
   public:
      void randomize(byte[], u32bit) throw(PRNG_Unseeded);
      bool is_seeded() const;
      void clear() throw();
      std::string name() const;

      SHA1PRNG(SharedPtrConverter<RandomNumberGenerator> = SharedPtrConverter<RandomNumberGenerator>());
      ~SHA1PRNG();
   private:
      void add_randomness(const byte[], u32bit);
      void update_state(byte[]);

      std::tr1::shared_ptr<HashFunction> hash;
      std::tr1::shared_ptr<RandomNumberGenerator> prng;
      SecureVector<byte> remainder;
      SecureVector<byte> state;
      int remCount;
   };

}

#endif
