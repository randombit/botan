/*
* Blinding for public key operations
* (C) 1999-2010,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_BLINDER_H_
#define BOTAN_BLINDER_H_

#include <botan/bigint.h>
#include <botan/reducer.h>
#include <functional>

namespace Botan {

class RandomNumberGenerator;

/**
* Blinding Function Object.
*/
class Blinder final {
   public:
      /**
      * Blind a value.
      * The blinding nonce k is freshly generated after
      * BOTAN_BLINDING_REINIT_INTERVAL calls to blind().
      * BOTAN_BLINDING_REINIT_INTERVAL = 0 means a fresh
      * nonce is only generated once. On every other call,
      * an updated nonce is used for blinding: k' = k*k mod n.
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
      Blinder(const Modular_Reducer& reducer,
              RandomNumberGenerator& rng,
              std::function<BigInt(const BigInt&)> fwd_func,
              std::function<BigInt(const BigInt&)> inv_func);

      Blinder(const Blinder&) = delete;

      Blinder& operator=(const Blinder&) = delete;

      RandomNumberGenerator& rng() const { return m_rng; }

   private:
      BigInt blinding_nonce() const;

      const Modular_Reducer& m_reducer;
      RandomNumberGenerator& m_rng;
      std::function<BigInt(const BigInt&)> m_fwd_fn;
      std::function<BigInt(const BigInt&)> m_inv_fn;
      size_t m_modulus_bits = 0;

      mutable BigInt m_e, m_d;
      mutable size_t m_counter = 0;
};

}  // namespace Botan

#endif
