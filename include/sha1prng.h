/*************************************************
* SHA1PRNG RNG Header File                       *
* (C) 2007 FlexSecure GmbH / Manuel Hartl        *
* (C) 2008 Jack Lloyd                            *
*************************************************/

#ifndef BOTAN_SHA1PRNG_H__
#define BOTAN_SHA1PRNG_H__

#include <botan/rng.h>
#include <botan/base.h>

namespace Botan {

/*************************************************
* SHA1PRNG                                       *
*************************************************/
class BOTAN_DLL SHA1PRNG : public RandomNumberGenerator
   {
   public:
      void randomize(byte[], u32bit) throw(PRNG_Unseeded);
      bool is_seeded() const;
      void clear() throw();
      std::string name() const;

      SHA1PRNG(RandomNumberGenerator* = 0);
      ~SHA1PRNG();
   private:
      void add_randomness(const byte[], u32bit);
      void update_state(byte[]);

      RandomNumberGenerator* prng;
      HashFunction* hash;
      SecureVector<byte> buffer;
      SecureVector<byte> state;
      int buf_pos;
   };

}

#endif
