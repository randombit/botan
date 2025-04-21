/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_BARRETT_REDUCTION_H_
#define BOTAN_BARRETT_REDUCTION_H_

#include <botan/bigint.h>

namespace Botan {

/**
* Barrett Reduction
*/
class BOTAN_TEST_API Barrett_Reduction final {
   public:
      /**
      * Setup for reduction where the modulus itself is public
      *
      * Requires that m > 0
      */
      static Barrett_Reduction for_public_modulus(const BigInt& m);

      /**
      * Setup for reduction where the modulus itself is secret.
      *
      * This is slower than for_public_modulus since it must avoid using
      * variable time division.
      *
      * Requires that m > 0
      */
      static Barrett_Reduction for_secret_modulus(const BigInt& m);

      /**
      * Perform modular reduction of x
      *
      * The parameter must be greater than or equal to zero, and less than 2^(2*b), where
      * b is the bitlength of the modulus.
      */
      BigInt reduce(const BigInt& x) const;

      /**
      * Multiply mod p
      * @param x the first operand in [0..p)
      * @param y the second operand in [0..p)
      * @return (x * y) % p
      */
      BigInt multiply(const BigInt& x, const BigInt& y) const;

      /**
      * Square mod p
      * @param x a value to square must be in [0..p)
      * @return (x * x) % p
      */
      BigInt square(const BigInt& x) const;

      /**
      * Cube mod p
      * @param x the value to cube
      * @return (x * x * x) % p
      *
      * TODO(Botan4) remove this, last few remaining callers go away in Botan4
      */
      BigInt cube(const BigInt& x) const { return this->multiply(x, this->square(x)); }

      /**
      * Return length of the modulus in bits
      */
      size_t modulus_bits() const { return m_modulus_bits; }

   private:
      Barrett_Reduction(const BigInt& m, BigInt mu, size_t mw);

      BigInt m_modulus;
      BigInt m_mu;
      size_t m_mod_words;
      size_t m_modulus_bits;
};

}  // namespace Botan

#endif
