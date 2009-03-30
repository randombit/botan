/******
 * Modulus and related data for a specific
 * implementation of  GF(p) (header file)
 *
 * (C) 2008 Martin Döring
 *          doering@cdc.informatik.tu-darmstadt.de
 *          Christoph Ludwig
 *          ludwig@fh-worms.de
 *          Falko Strenzke
 *          strenzke@flexsecure.de
 ******/

#ifndef BOTAN_GFP_MODULUS_H__
#define BOTAN_GFP_MODULUS_H__

#include <botan/bigint.h>

namespace Botan
{

class BOTAN_DLL GFpElement;
/**
* This class represents a GFpElement modulus including the modulus related
* values necessary for the montgomery multiplication.
*
* Distributed under the terms of the Botan license
*/
class BOTAN_DLL GFpModulus
   {
      friend class GFpElement;
   private:
      BigInt m_p; // the modulus itself
      mutable BigInt m_p_dash;
      mutable BigInt m_r;
      mutable BigInt m_r_inv;
   public:

      /**
      * Construct a GF(P)-Modulus from a BigInt
      */
      GFpModulus(BigInt p)
         : m_p(p),
           m_p_dash(),
           m_r(),
           m_r_inv()
         {}

      /**
      * Tells whether the precomputations necessary for the use of the
      * montgomery multiplication have yet been established.
      * @result true if the precomputated value are already available.
      */
      inline bool has_precomputations() const
         {
         return(!m_p_dash.is_zero() && !m_r.is_zero() && !m_r_inv.is_zero());
         }

      /**
      * Swaps this with another GFpModulus, does not throw.
      * @param other the GFpModulus to swap *this with.
      */
      inline void swap(GFpModulus& other)
         {
         m_p.swap(other.m_p);
         m_p_dash.swap(other.m_p_dash);
         m_r.swap(other.m_r);
         m_r_inv.swap(other.m_r_inv);
         }

      /**
      * Tells whether the modulus of *this is equal to the argument.
      * @param mod the modulus to compare this with
      * @result true if the modulus of *this and the argument are equal.
      */
      inline bool p_equal_to(const BigInt& mod) const
         {
         return (m_p == mod);
         }

      /**
      * Return the modulus of this GFpModulus.
      * @result the modulus of *this.
      */
      inline const BigInt& get_p() const
         {
         return m_p;
         }

      /**
      * returns the montgomery multiplication related value r.
      * Warning: will be zero if precomputations have not yet been
      * performed!
      * @result r
      */
      inline const BigInt& get_r() const
         {
         return m_r;
         }

      /**
      * returns the montgomery multiplication related value r^{-1}.
      * Warning: will be zero if precomputations have not yet been
      * performed!
      * @result r^{-1}
      */
      inline const BigInt& get_r_inv() const
         {
         return m_r_inv;
         }

      /**
      * returns the montgomery multiplication related value p'.
      * Warning: will be zero if precomputations have not yet been
      * performed!
      * @result p'
      */
      inline const BigInt& get_p_dash() const
         {
         return m_p_dash;
         }
      // default cp-ctor, op= are fine
   };

}

#endif

