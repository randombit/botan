/*
* Blinding for public key operations
* (C) 1999-2010,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_BLINDER_H_
#define BOTAN_BLINDER_H_

#include <botan/bigint.h>
#include <botan/internal/barrett.h>
#include <functional>

namespace Botan {

class RandomNumberGenerator;

/**
* Blinding Function Object.
*/
class Blinder final {
   public:
      /**
      * Normally blinding is performed by choosing a random starting point (plus
      * its inverse, of a form appropriate to the algorithm being blinded), and
      * then choosing new blinding operands by successive squaring of both
      * values. This is much faster than computing a new starting point but
      * introduces some possible corelation
      *
      * To avoid possible leakage problems in long-running processes, the blinder
      * periodically reinitializes the sequence. This value specifies how often
      * a new sequence should be started.
      *
      * If set to zero, reinitialization is disabled
      */
      static constexpr size_t ReinitInterval = 64;

      /**
      * Blind a value.
      *
      * The blinding nonce k is freshly generated after ReinitInterval
      * calls to blind().
      *
      * ReinitInterval = 0 means a fresh nonce is only generated once.
      * On every other call, the next nonce is derived via modular squaring.
      *
      * @param x value to blind
      * @return blinded value
      */
      BigInt blind(const BigInt& x) const;

      /**
      * Unblind a value.
      * @param x value to unblind
      * @return unblinded value
      */
      BigInt unblind(const BigInt& x) const;

      /**
      * @param reducer precomputed Barrett reduction for the modulus
      * @param rng the RNG to use for generating the nonce
      * @param fwd_func a function that calculates the modular
      * exponentiation of the public exponent and the given value (the nonce)
      * @param inv_func a function that calculates the modular inverse
      * of the given value (the nonce)
      *
      * @note Lifetime: The rng and reducer arguments are captured by
      * reference and must live as long as the Blinder does
      */
      Blinder(const Barrett_Reduction& reducer,
              RandomNumberGenerator& rng,
              std::function<BigInt(const BigInt&)> fwd_func,
              std::function<BigInt(const BigInt&)> inv_func);

      Blinder(const Blinder&) = delete;

      Blinder& operator=(const Blinder&) = delete;

      RandomNumberGenerator& rng() const { return m_rng; }

   private:
      BigInt blinding_nonce() const;

      const Barrett_Reduction& m_reducer;
      RandomNumberGenerator& m_rng;
      std::function<BigInt(const BigInt&)> m_fwd_fn;
      std::function<BigInt(const BigInt&)> m_inv_fn;
      size_t m_modulus_bits = 0;

      mutable BigInt m_e, m_d;
      mutable size_t m_counter = 0;
};

}  // namespace Botan

#endif
