/*************************************************
* RandomNumberGenerator Header File              *
* (C) 1999-2008 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_RANDOM_NUMBER_GENERATOR__
#define BOTAN_RANDOM_NUMBER_GENERATOR__

#include <botan/exceptn.h>

namespace Botan {

/*************************************************
* Entropy Source                                 *
*************************************************/
class BOTAN_DLL EntropySource
   {
   public:
      virtual u32bit slow_poll(byte[], u32bit) = 0;
      virtual u32bit fast_poll(byte[], u32bit);
      virtual ~EntropySource() {}
   };

/*************************************************
* Random Number Generator                        *
*************************************************/
class BOTAN_DLL RandomNumberGenerator
   {
   public:
      static RandomNumberGenerator* make_rng();

      virtual void randomize(byte[], u32bit) = 0;
      virtual bool is_seeded() const = 0;
      virtual void clear() throw() = 0;

      byte next_byte();

      virtual void reseed() {}
      virtual void add_entropy_source(EntropySource*) = 0;
      virtual void add_entropy(const byte[], u32bit) = 0;

      RandomNumberGenerator() {}
      virtual ~RandomNumberGenerator() {}
   private:
      RandomNumberGenerator(const RandomNumberGenerator&) {}
      RandomNumberGenerator& operator=(const RandomNumberGenerator&)
         { return (*this); }
   };

/*************************************************
* Null Random Number Generator                   *
*************************************************/
class BOTAN_DLL Null_RNG : public RandomNumberGenerator
   {
   public:
      void randomize(byte[], u32bit) { throw PRNG_Unseeded("Null_RNG"); }
      void clear() throw() {};

      bool is_seeded() const { return false; }
      void add_entropy(const byte[], u32bit) {}
      void add_entropy_source(EntropySource* es) { delete es; }
   };

}

#endif
