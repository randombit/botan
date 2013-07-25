/*
* Elliptic curves over GF(p)
*
* (C) 2007 Martin Doering, Christoph Ludwig, Falko Strenzke
*     2010-2011 Jack Lloyd
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
      CurveGFp() : p_words(0), p_dash(0) {}

      /**
      * Construct the elliptic curve E: y^2 = x^3 + ax + b over GF(p)
      * @param p prime number of the field
      * @param a first coefficient
      * @param b second coefficient
      */
      CurveGFp(const BigInt& p, const BigInt& a, const BigInt& b) :
         p(p), a(a), b(b), p_words(p.sig_words())
         {
         BigInt r(BigInt::Power2, p_words * BOTAN_MP_WORD_BITS);

         p_dash = (((r * inverse_mod(r, p)) - 1) / p).word_at(0);

         r2  = (r * r) % p;
         a_r = (a * r) % p;
         b_r = (b * r) % p;
         }

      // CurveGFp(const CurveGFp& other) = default;
      // CurveGFp& operator=(const CurveGFp& other) = default;

      /**
      * @return curve coefficient a
      */
      const BigInt& get_a() const { return a; }

      /**
      * @return curve coefficient b
      */
      const BigInt& get_b() const { return b; }

      /**
      * Get prime modulus of the field of the curve
      * @return prime modulus of the field of the curve
      */
      const BigInt& get_p() const { return p; }

      /**
      * @return Montgomery parameter r^2 % p
      */
      const BigInt& get_r2() const { return r2; }

      /**
      * @return a * r mod p
      */
      const BigInt& get_a_r() const { return a_r; }

      /**
      * @return b * r mod p
      */
      const BigInt& get_b_r() const { return b_r; }

      /**
      * @return Montgomery parameter p-dash
      */
      word get_p_dash() const { return p_dash; }

      /**
      * @return p.sig_words()
      */
      size_t get_p_words() const { return p_words; }

      /**
      * swaps the states of *this and other, does not throw
      * @param other curve to swap values with
      */
      void swap(CurveGFp& other)
         {
         std::swap(p, other.p);

         std::swap(a, other.a);
         std::swap(b, other.b);

         std::swap(a_r, other.a_r);
         std::swap(b_r, other.b_r);

         std::swap(p_words, other.p_words);

         std::swap(r2, other.r2);
         std::swap(p_dash, other.p_dash);
         }

      /**
      * Equality operator
      * @param other curve to compare with
      * @return true iff this is the same curve as other
      */
      bool operator==(const CurveGFp& other) const
         {
         /*
         Relies on choice of R, but that is fixed by constructor based
         on size of p
         */
         return (p == other.p && a_r == other.a_r && b_r == other.b_r);
         }

   private:
      // Curve parameters
      BigInt p, a, b;

      size_t p_words; // cache of p.sig_words()

      // Montgomery parameters
      BigInt r2, a_r, b_r;
      word p_dash;
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
