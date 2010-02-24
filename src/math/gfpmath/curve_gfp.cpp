/*
* Elliptic curves over GF(p)
*
* (C) 2007 Martin Doering, Christoph Ludwig, Falko Strenzke
*     2008-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/curve_gfp.h>
#include <botan/bigint.h>
#include <assert.h>
#include <ostream>

namespace Botan {

CurveGFp::CurveGFp(const GFpElement& a, const GFpElement& b,
                   const BigInt& p) :
   modulus(p), mA(a), mB(b)
   {
   if(p != mA.get_p() || p != mB.get_p())
      throw Invalid_Argument("could not construct curve: moduli of arguments differ");
   }

// swaps the states of *this and other, does not throw
void CurveGFp::swap(CurveGFp& other)
   {
   std::swap(mA, other.mA);
   std::swap(mB, other.mB);
   std::swap(modulus, other.modulus);
   }

bool operator==(const CurveGFp& lhs, const CurveGFp& rhs)
   {
   return (lhs.get_p() == rhs.get_p() &&
           lhs.get_a() == rhs.get_a() &&
           lhs.get_b() == rhs.get_b());
   }

std::ostream& operator<<(std::ostream& output, const CurveGFp& elem)
   {
   return output << "y^2 = x^3 + (" << elem.get_a() << ")x + (" << elem.get_b() << ")";
   }

}
