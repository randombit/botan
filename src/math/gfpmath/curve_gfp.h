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

#include <botan/gfp_element.h>
#include <iosfwd>

namespace Botan {

/**
* This class represents an elliptic curve over GF(p)
*/
class BOTAN_DLL CurveGFp
   {
   public:

      /**
      * Construct the elliptic curve E: y^2 = x^3 + ax + b over GF(p)
      * @param a first coefficient
      * @param b second coefficient
      * @param p prime number of the field
      */
      CurveGFp(const GFpElement& a, const GFpElement& b,
               const BigInt& p);

      // CurveGFp(const CurveGFp& other) = default;
      // CurveGFp& operator=(const CurveGFp& other) = default;

      // getters

      /**
      * Get coefficient a
      * @result coefficient a
      */
      const GFpElement& get_a() const { return mA; }

      /**
      * Get coefficient b
      * @result coefficient b
      */
      const GFpElement& get_b() const { return mB; }

      /**
      * Get the GFpElement coefficient a  transformed
      * to its m-residue. This can be used for efficency reasons: the curve
      * stores the transformed version after the first invocation of this
      * function.
      * @result the coefficient a, transformed to its m-residue
      */
      const GFpElement& get_mres_a() const { return mres_a; }

      /**
      * Get the GFpElement coefficient b transformed
      * to its m-residue. This can be used for efficency reasons: the curve
      * stores the transformed version after the first invocation of this
      * function.
      * @result the coefficient b, transformed to its m-residue
      */
      const GFpElement& get_mres_b() const { return mres_b; }

      /**
      * Get the GFpElement 1  transformed
      * to its m-residue. This can be used for efficency reasons: the curve
      * stores the transformed version after the first invocation of this
      * function.
      * @result the GFpElement 1, transformed to its m-residue
      */
      const GFpElement& get_mres_one() { return mres_one; }

      /**
      * Get prime modulus of the field of the curve
      * @result prime modulus of the field of the curve
      */
      const BigInt& get_p() const { return modulus.get_p(); }

      /**
      * swaps the states of *this and other, does not throw
      * @param other The curve to swap values with
      */
      void swap(CurveGFp& other);

   private:
      GFpModulus modulus;
      GFpElement mA;
      GFpElement mB;
      GFpElement mres_a, mres_b, mres_one;
   };

// relational operators
bool operator==(const CurveGFp& lhs, const CurveGFp& rhs);

inline bool operator!=(const CurveGFp& lhs, const CurveGFp& rhs)
   {
   return !(lhs == rhs);
   }

// io operators
std::ostream& operator<<(std::ostream& output, const CurveGFp& elem);

// swaps the states of curve1 and curve2, does not throw!
// cf. Meyers, Item 25
inline
void swap(CurveGFp& curve1, CurveGFp& curve2)
   {
   curve1.swap(curve2);
   }

} // namespace Botan


namespace std {

// swaps the states of curve1 and curve2, does not throw!
// cf. Meyers, Item 25
template<> inline
void swap<Botan::CurveGFp>(Botan::CurveGFp& curve1,
                           Botan::CurveGFp& curve2)
   {
   curve1.swap(curve2);
   }

} // namespace std

#endif
