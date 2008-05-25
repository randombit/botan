/*************************************************
* BLUM BLUM SHUB RNG Header File                 *
* (C) 2007 FlexSecure GmbH / Manuel Hartl        *
*************************************************/

#ifndef BOTAN_BBS_H__
#define BOTAN_BBS_H__

#include <botan/base.h>
#include <botan/mdx_hash.h>
#include <botan/bigint.h>
#include <botan/freestore.h>


namespace Botan {

/*************************************************
* SHA1PRNG (propriery                            *
*************************************************/
class BBS : public RandomNumberGenerator
   {
   public:
      void randomize(byte[], u32bit) throw(PRNG_Unseeded);
      bool is_seeded() const;
      void clear() throw();
      std::string name() const;

      BBS(SharedPtrConverter<RandomNumberGenerator> = SharedPtrConverter<RandomNumberGenerator>());
      ~BBS();
      void lcg(u32bit bitLength, byte[]);
   private:
      const static int SECURITY_PARAMETER = 1024;
      const static int CERTAINTY = 10;

      bool parametersGenerated;
      bool isSeeded;

	  BigInt BIG2;
      BigInt BIG3;
      BigInt BIG4;
      BigInt BIG5;
      BigInt BIG7;
      BigInt BIG11;
      BigInt BIG13;
      BigInt BIG17;
      BigInt BIG19;
      BigInt BIG23;
      BigInt BIG27;


      void add_randomness(const byte[], u32bit);
      void update_buffer();
      void generateParameters();
      std::tr1::shared_ptr<RandomNumberGenerator> prng;

      BigInt seed;
      BigInt LCG_A;
      BigInt LCG_B;
      BigInt LCG_MODULUS;

      BigInt p,q,n,x;
      int bitsPerRound;

   };

}

#endif
