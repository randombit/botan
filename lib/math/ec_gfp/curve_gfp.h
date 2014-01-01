/*
* Elliptic curves over GF(p)
*
* (C) 2007 Martin Doering, Christoph Ludwig, Falko Strenzke
*     2010-2011,2012 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_GFP_CURVE_H__
#define BOTAN_GFP_CURVE_H__

#include <botan/numthry.h>

namespace Botan {

/**
* This class represents an elliptic curve over GF(p)
*/
class BOTAN_DLL CurveGFp
   {
   public:

      /**
      * Create an uninitialized CurveGFp
      */
      CurveGFp() {}

      /**
      * Construct the elliptic curve E: y^2 = x^3 + ax + b over GF(p)
      * @param p prime number of the field
      * @param a first coefficient
      * @param b second coefficient
      */
      CurveGFp(const BigInt& p, const BigInt& a, const BigInt& b) :
         m_p(p),
         m_a(a),
         m_b(b),
         m_p_words(m_p.sig_words()),
         m_p_dash(monty_inverse(m_p.word_at(0)))
         {
         const BigInt r = BigInt::power_of_2(m_p_words * BOTAN_MP_WORD_BITS);

         m_r2  = (r * r) % p;
         m_a_r = (a * r) % p;
         m_b_r = (b * r) % p;
         }

      CurveGFp(const CurveGFp&) = default;

      CurveGFp& operator=(const CurveGFp&) = default;

      /**
      * @return curve coefficient a
      */
      const BigInt& get_a() const { return m_a; }

      /**
      * @return curve coefficient b
      */
      const BigInt& get_b() const { return m_b; }

      /**
      * Get prime modulus of the field of the curve
      * @return prime modulus of the field of the curve
      */
      const BigInt& get_p() const { return m_p; }

      /**
      * @return Montgomery parameter r^2 % p
      */
      const BigInt& get_r2() const { return m_r2; }

      /**
      * @return a * r mod p
      */
      const BigInt& get_a_r() const { return m_a_r; }

      /**
      * @return b * r mod p
      */
      const BigInt& get_b_r() const { return m_b_r; }

      /**
      * @return Montgomery parameter p-dash
      */
      word get_p_dash() const { return m_p_dash; }

      /**
      * @return p.sig_words()
      */
      size_t get_p_words() const { return m_p_words; }

      /**
      * swaps the states of *this and other, does not throw
      * @param other curve to swap values with
      */
      void swap(CurveGFp& other)
         {
         std::swap(m_p, other.m_p);

         std::swap(m_a, other.m_a);
         std::swap(m_b, other.m_b);

         std::swap(m_a_r, other.m_a_r);
         std::swap(m_b_r, other.m_b_r);

         std::swap(m_p_words, other.m_p_words);

         std::swap(m_r2, other.m_r2);
         std::swap(m_p_dash, other.m_p_dash);
         }

      /**
      * Equality operator
      * @param other curve to compare with
      * @return true iff this is the same curve as other
      */
      bool operator==(const CurveGFp& other) const
         {
         return (m_p == other.m_p &&
                 m_a == other.m_a &&
                 m_b == other.m_b);
         }

   private:
      // Curve parameters
      BigInt m_p, m_a, m_b;

      size_t m_p_words; // cache of m_p.sig_words()

      // Montgomery parameters
      BigInt m_r2, m_a_r, m_b_r;
      word m_p_dash;
   };

/**
* Equality operator
* @param lhs a curve
* @param rhs a curve
* @return true iff lhs is not the same as rhs
*/
inline bool operator!=(const CurveGFp& lhs, const CurveGFp& rhs)
   {
   return !(lhs == rhs);
   }

}

namespace std {

template<> inline
void swap<Botan::CurveGFp>(Botan::CurveGFp& curve1,
                           Botan::CurveGFp& curve2)
   {
   curve1.swap(curve2);
   }

} // namespace std

#endif
