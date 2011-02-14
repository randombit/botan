/*
* Elliptic curves over GF(p)
*
* (C) 2007 Martin Doering, Christoph Ludwig, Falko Strenzke
*     2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_GFP_CURVE_H__
#define BOTAN_GFP_CURVE_H__

#include <botan/numthry.h>
#include <botan/reducer.h>

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
         p(p), a(a), b(b), reducer_p(p)
         {
         r = 1;
         r <<= p.sig_words() * BOTAN_MP_WORD_BITS;

         r_inv = inverse_mod(r, p);

         p_dash = (((r * r_inv) - 1) / p).word_at(0);

         a_r = reducer_p.multiply(a, r);

         p_words = p.sig_words();
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
      * @return Montgomery parameter r
      */
      const BigInt& get_r() const { return r; }

      /**
      * @return Montgomery parameter r^-1
      */
      const BigInt& get_r_inv() const { return r_inv; }

      /**
      * @return a * r mod p
      */
      const BigInt& get_a_r() const { return a_r; }

      /**
      * @return Montgomery parameter p-dash
      */
      word get_p_dash() const { return p_dash; }

      /**
      * @return p.sig_words()
      */
      size_t get_p_words() const { return p_words; }

      /**
      * @return modular reducer for p
      */
      const Modular_Reducer& mod_p() const { return reducer_p; }

      /**
      * swaps the states of *this and other, does not throw
      * @param other curve to swap values with
      */
      void swap(CurveGFp& other)
         {
         std::swap(a, other.a);
         std::swap(b, other.b);
         std::swap(p, other.p);
         std::swap(reducer_p, other.reducer_p);

         std::swap(r, other.r);
         std::swap(r_inv, other.r_inv);
         std::swap(p_dash, other.p_dash);
         }

      /**
      * Equality operator
      * @param other curve to compare with
      * @return true iff this is the same curve as other
      */
      bool operator==(const CurveGFp& other) const
         {
         return (p == other.p && a == other.a && b == other.b);
         }

   private:
      // Curve parameters
      BigInt p, a, b;

      size_t p_words; // cache of p.sig_words()

      // Montgomery parameters
      BigInt r, r_inv, a_r;
      word p_dash;

      Modular_Reducer reducer_p;
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
