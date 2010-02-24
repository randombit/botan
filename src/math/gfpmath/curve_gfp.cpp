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
   modulus(p), mA(a), mB(b),
   mres_a(mA), mres_b(mB), mres_one(p, 1)
   {
   if(p != mA.get_p() || p != mB.get_p())
      throw Invalid_Argument("could not construct curve: moduli of arguments differ");

   mres_a.turn_on_sp_red_mul();
   mres_a.get_mres();

   mres_b.turn_on_sp_red_mul();
   mres_b.get_mres();

   mres_one.turn_on_sp_red_mul();
   mres_one.get_mres();
   }

// swaps the states of *this and other, does not throw
void CurveGFp::swap(CurveGFp& other)
   {
   std::swap(mA, other.mA);
   std::swap(mB, other.mB);
   std::swap(modulus, other.modulus);
   std::swap(mres_a, other.mres_a);
   std::swap(mres_b, other.mres_b);
   std::swap(mres_one, other.mres_one);
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
