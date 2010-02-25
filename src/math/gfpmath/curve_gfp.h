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
      * Construct the elliptic curve E: y^2 = x^3 + ax + b over GF(p)
      * @param p prime number of the field
      * @param a first coefficient
      * @param b second coefficient
      */
      CurveGFp(const BigInt& p, const BigInt& a, const BigInt& b) :
         p(p), a(a), b(b), reducer_p(p) {}

      // CurveGFp(const CurveGFp& other) = default;
      // CurveGFp& operator=(const CurveGFp& other) = default;

      /**
      * Get coefficient a
      * @result coefficient a
      */
      const BigInt& get_a() const { return a; }

      /**
      * Get coefficient b
      * @result coefficient b
      */
      const BigInt& get_b() const { return b; }

      /**
      * Get prime modulus of the field of the curve
      * @result prime modulus of the field of the curve
      */
      const BigInt& get_p() const { return p; }

      const Modular_Reducer& mod_p() const { return reducer_p; }

      /**
      * swaps the states of *this and other, does not throw
      * @param other The curve to swap values with
      */
      void swap(CurveGFp& other)
         {
         std::swap(a, other.a);
         std::swap(b, other.b);
         std::swap(p, other.p);
         }

      bool operator==(const CurveGFp& other) const
         {
         return (p == other.p && a == other.a && b == other.b);
         }

   private:
      BigInt p, a, b;
      Modular_Reducer reducer_p;
   };

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
