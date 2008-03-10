/*************************************************
* ANSI X9.31 RNG Header File                     *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_ANSI_X931_RNG_H__
#define BOTAN_ANSI_X931_RNG_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* ANSI X9.31 RNG                                 *
*************************************************/
class ANSI_X931_RNG : public RandomNumberGenerator
   {
   public:
      void randomize(byte[], u32bit) throw(PRNG_Unseeded);
      bool is_seeded() const;
      void clear() throw();
      std::string name() const;

      ANSI_X931_RNG(const std::string& = "", RandomNumberGenerator* = 0);
      ~ANSI_X931_RNG();
   private:
      void add_randomness(const byte[], u32bit);
      void update_buffer();

      BlockCipher* cipher;
      RandomNumberGenerator* prng;
      SecureVector<byte> V, R;
      u32bit position;
   };

}

#endif
