/*************************************************
* RandomNumberGenerator Header File              *
* (C) 1999-2008 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_RANDOM_NUMBER_GENERATOR_H__
#define BOTAN_RANDOM_NUMBER_GENERATOR_H__

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

/**
* This class represents a random number (RNG) generator object.
*/
class BOTAN_DLL RandomNumberGenerator
   {
   public:
      /**
      * Create a seeded and active RNG object for general application use
      */
      static RandomNumberGenerator* make_rng();

      /**
      * Randomize a byte array.
      * @param output the byte array to hold the random output.
      * @param length the length of the byte array output.
      */
      virtual void randomize(byte output[], u32bit length) = 0;

      /**
      * Return a random byte
      * @return random byte
      */
      byte next_byte();

      /**
      * Check whether this RNG is seeded.
      * @return true if this RNG was already seeded, false otherwise.
      */
      virtual bool is_seeded() const { return true; }

      /**
      * Clear all internally held values of this RNG.
      */
      virtual void clear() throw() = 0;

      /**
      * Return the name of this object
      */
      virtual std::string name() const = 0;

      /**
      * Force a reseed of the PRNG
      */
      virtual void reseed() {}

      /**
      * Add this entropy source to the RNG object
      * @param source the entropy source which will be retained and used by RNG
      */
      virtual void add_entropy_source(EntropySource* source) = 0;

      /**
      * Add entropy to this RNG.
      * @param in a byte array containg the entropy to be added
      * @param length the length of the byte array in
      */
      virtual void add_entropy(const byte in[], u32bit length) = 0;

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
      std::string name() const { return "Null_RNG"; }

      bool is_seeded() const { return false; }
      void add_entropy(const byte[], u32bit) {}
      void add_entropy_source(EntropySource* es) { delete es; }
   };

}

#endif
