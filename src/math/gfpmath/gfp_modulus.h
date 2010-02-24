/*
* Modulus and related data for a specific implementation of GF(p)
*
* (C) 2008 Martin Doering, Christoph Ludwig, Falko Strenzke
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_GFP_MODULUS_H__
#define BOTAN_GFP_MODULUS_H__

#include <botan/bigint.h>

namespace Botan {

class GFpElement;

/**
* This class represents a GFpElement modulus including the modulus
* related values necessary for the montgomery multiplication.
*/
class BOTAN_DLL GFpModulus
   {
   public:

      /**
      * Construct a GF(P)-Modulus from a BigInt
      */
      GFpModulus(const BigInt& p)
         : m_p(p),
           m_p_dash(),
           m_r(),
           m_r_inv()
         {}

      // GFpModulus(const GFpModulus& other) = default;
      // GFpModulus& operator=(const GFpModulus& other) = default;

      /**
      * Tells whether the precomputations necessary for the use of the
      * montgomery multiplication have yet been established.
      * @result true if the precomputated value are already available.
      */
      bool has_precomputations() const
         {
         return(!m_p_dash.is_zero() && !m_r.is_zero() && !m_r_inv.is_zero());
         }

      /**
      * Swaps this with another GFpModulus, does not throw.
      * @param other the GFpModulus to swap *this with.
      */
      void swap(GFpModulus& other)
         {
         std::swap(m_p, other.m_p);
         std::swap(m_p_dash, other.m_p_dash);
         std::swap(m_r, other.m_r);
         std::swap(m_r_inv, other.m_r_inv);
         }

      /**
      * Tells whether the modulus of *this is equal to the argument.
      * @param mod the modulus to compare this with
      * @result true if the modulus of *this and the argument are equal.
      */
      bool p_equal_to(const BigInt& mod) const
         {
         return (m_p == mod);
         }

      /**
      * Return the modulus of this GFpModulus.
      * @result the modulus of *this.
      */
      const BigInt& get_p() const
         {
         return m_p;
         }

      /**
      * returns the montgomery multiplication related value r.
      * Warning: will be zero if precomputations have not yet been
      * performed!
      * @result r
      */
      const BigInt& get_r() const
         {
         return m_r;
         }

      /**
      * returns the montgomery multiplication related value r^{-1}.
      * Warning: will be zero if precomputations have not yet been
      * performed!
      * @result r^{-1}
      */
      const BigInt& get_r_inv() const
         {
         return m_r_inv;
         }

      /**
      * returns the montgomery multiplication related value p'.
      * Warning: will be zero if precomputations have not yet been
      * performed!
      * @result p'
      */
      const BigInt& get_p_dash() const
         {
         return m_p_dash;
         }

      void reset_values(const BigInt& new_p_dash,
                        const BigInt& new_r,
                        const BigInt& new_r_inv)
         {
         m_p_dash = new_p_dash;
         m_r = new_r;
         m_r_inv = new_r_inv;
         }

   private:
      BigInt m_p; // the modulus itself
      BigInt m_p_dash;
      BigInt m_r;
      BigInt m_r_inv;
   };

}

#endif
