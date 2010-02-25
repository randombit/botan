/*
* Arithmetic for point groups of elliptic curves over GF(p)
*
* (C) 2007 Martin Doering, Christoph Ludwig, Falko Strenzke
*     2008-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/point_gfp.h>
#include <botan/numthry.h>

namespace Botan {

namespace {

BigInt decompress_point(bool yMod2,
                        const BigInt& x,
                        const CurveGFp& curve)
   {
   BigInt xpow3 = x * x * x;

   BigInt g = curve.get_a().get_value() * x;
   g += xpow3;
   g += curve.get_b().get_value();
   g = g % curve.get_p();

   BigInt z = ressol(g, curve.get_p());

   if(z < 0)
      throw Illegal_Point("error during decompression");

   if(z.get_bit(0) != yMod2)
      z = curve.get_p() - z;

   return z;
   }

}

// construct the point at infinity or a random point
PointGFp::PointGFp(const CurveGFp& curve) :
   mC(curve),
   mX(curve.get_p(), 0),
   mY(curve.get_p(), 1),
   mZ(curve.get_p(), 0)
   {
   }

// construct a point given its jacobian projective coordinates
PointGFp::PointGFp(const CurveGFp& curve, const GFpElement& x,
                   const GFpElement& y, const GFpElement& z) :
   mC(curve),
   mX(x),
   mY(y),
   mZ(z)
   {
   }

PointGFp::PointGFp(const CurveGFp& curve,
                   const BigInt& x,
                   const BigInt& y) :
   mC(curve),
   mX(curve.get_p(),x),
   mY(curve.get_p(),y),
   mZ(curve.get_p(),1)
   {
   }

// arithmetic operators
PointGFp& PointGFp::operator+=(const PointGFp& rhs)
   {
   if(is_zero())
      {
      *this = rhs;
      return *this;
      }
   if(rhs.is_zero())
      {
      return *this;
      }

   GFpElement U1 = mX;
   GFpElement S1 = mY;

   GFpElement rhs_z2 = rhs.mZ * rhs.mZ;
   U1 *= rhs_z2;
   S1 *= rhs_z2 * rhs.mZ;

   GFpElement U2 = rhs.mX;
   GFpElement S2 = rhs.mY;

   GFpElement lhs_z2 = mZ * mZ;
   U2 *= lhs_z2;
   S2 *= lhs_z2 * mZ;

   GFpElement H(U2 - U1);
   GFpElement r(S2 - S1);

   if(H.is_zero())
      {
      if(r.is_zero())
         {
         mult2_in_place();
         return *this;
         }

      *this = PointGFp(mC); // setting myself to zero
      return *this;
      }

   U2 = H * H;

   S2 = U2 * H;

   U2 *= U1;

   GFpElement x(r*r - S2 - (U2+U2));

   GFpElement z(S1 * S2);

   GFpElement y(r * (U2-x) - z);

   z = (mZ * rhs.mZ) * H;

   mX = x;
   mY = y;
   mZ = z;

   return *this;
   }

PointGFp& PointGFp::operator-=(const PointGFp& rhs)
   {
   PointGFp minus_rhs = PointGFp(rhs).negate();

   if(is_zero())
      *this = minus_rhs;
   else
      *this += minus_rhs;

   return *this;
   }

PointGFp& PointGFp::operator*=(const BigInt& scalar)
   {
   PointGFp H(this->mC); // create as zero
   PointGFp P(*this);
   BigInt m(scalar);

   if(m < BigInt(0))
      {
      m.flip_sign();
      P.negate();
      }

   // Move upwards
   if(P.is_zero() || (m == BigInt(0)))
      {
      *this = H;
      return *this;
      }

   // FIXME: *this != P if m was -1 !
   if(m == BigInt(1)) //*this == P already
      return *this;

   const int l = m.bits() - 1;
   for(int i = l; i >= 0; --i)
      {
      H.mult2_in_place();
      if(m.get_bit(i))
         H += P;
      }

   if(!H.is_zero()) // cannot convert if H == O
      *this = H.get_z_to_one();
   else
      *this = H;

   return *this;
   }

PointGFp& PointGFp::negate()
   {
   if(!is_zero())
      mY.negate();

   return *this;
   }

// *this *= 2
PointGFp& PointGFp::mult2_in_place()
   {
   if(is_zero())
      return *this;
   else if(mY.is_zero())
      {
      *this = PointGFp(mC); // setting myself to zero
      return *this;
      }

   GFpElement Y_squared = mY*mY;

   GFpElement S = mX * Y_squared;

   GFpElement x = S + S;

   S = x + x;

   GFpElement a_z4 = mC.get_a();

   GFpElement z2 = mZ * mZ;
   a_z4 *= z2;
   a_z4 *= z2;

   GFpElement y(mX * mX);

   GFpElement M(y + y + y + a_z4);

   x = M * M - (S+S);

   y = Y_squared * Y_squared;

   GFpElement U(y + y);

   GFpElement z = U + U;

   U = z + z;

   y = M * (S - x) - U;

   z = mY * mZ;

   z = z + z;

   mX = x;
   mY = y;
   mZ = z;

   return *this;
   }

/**
* returns a point equivalent to *this but were
* Z has value one, i.e. x and y correspond to
* their values in affine coordinates
*/
PointGFp PointGFp::get_z_to_one()
   {
   return PointGFp(*this).set_z_to_one();
   }

/**
* changes the representation of *this so that
* Z has value one, i.e. x and y correspond to
* their values in affine coordinates.
* returns *this.
*/
const PointGFp& PointGFp::set_z_to_one()
   {
   if(mZ.is_zero())
      throw Illegal_Transformation("cannot convert Z to one");

   if(mZ.get_value() != 1)
      {
      // Converts to affine coordinates
      GFpElement z = inverse(mZ);
      GFpElement z2 = z * z;
      z *= z2;
      GFpElement x = mX * z2;
      GFpElement y = mY * z;
      mZ = GFpElement(mC.get_p(), BigInt(1));
      mX = x;
      mY = y;
      }

   return *this;
   }

BigInt PointGFp::get_affine_x() const
   {
   if(is_zero())
      throw Illegal_Transformation("cannot convert to affine");

   GFpElement z2 = mZ * mZ;
   z2.inverse_in_place();
   z2 *= mX;

   return z2.get_value();
   }

BigInt PointGFp::get_affine_y() const
   {
   if(is_zero())
      throw Illegal_Transformation("cannot convert to affine");

   GFpElement z3 = mZ * mZ * mZ;
   z3.inverse_in_place();
   z3 *= mY;

   return z3.get_value();
   }

// Is this the point at infinity?
bool PointGFp::is_zero() const
   {
   return(mX.is_zero() && mZ.is_zero());
   }

void PointGFp::check_invariants() const
   {
   /*
   Is the point still on the curve?? (If everything is correct, the
   point is always on its curve; then the function will return
   silently. If Oskar managed to corrupt this object's state, then it
   will throw an exception.)
   */

   if(is_zero())
      return;

   const GFpElement y2 = mY * mY;
   const GFpElement x3 = mX * mX * mX;

   if(mZ.get_value() == BigInt(1))
      {
      GFpElement ax = mC.get_a() * mX;
      if(y2 != (x3 + ax + mC.get_b()))
         throw Illegal_Point();
      }

   GFpElement Zpow2 = mZ * mZ;
   GFpElement Zpow3 = Zpow2 * mZ;
   GFpElement AZpow4 = Zpow3 * mZ * mC.get_a();
   const GFpElement aXZ4 = AZpow4 * mX;
   const GFpElement bZ6 = mC.get_b() * Zpow3 * Zpow3;

   if(y2 != (x3 + aXZ4 + bZ6))
      throw Illegal_Point();
   }

// swaps the states of *this and other, does not throw!
void PointGFp::swap(PointGFp& other)
   {
   mC.swap(other.mC);
   mX.swap(other.mX);
   mY.swap(other.mY);
   mZ.swap(other.mZ);
   }

bool PointGFp::operator==(const PointGFp& other) const
   {
   if(get_curve() != other.get_curve())
      return false;

   return (mX == other.mX && mY == other.mY && mZ == other.mZ);
   }

// arithmetic operators
PointGFp operator+(const PointGFp& lhs, PointGFp const& rhs)
   {
   PointGFp tmp(lhs);
   return tmp += rhs;
   }

PointGFp operator-(const PointGFp& lhs, PointGFp const& rhs)
   {
   PointGFp tmp(lhs);
   return tmp -= rhs;
   }

PointGFp operator-(const PointGFp& lhs)
   {
   return PointGFp(lhs).negate();
   }

PointGFp operator*(const BigInt& scalar, const PointGFp& point)
   {
   PointGFp result(point);
   return result *= scalar;
   }

PointGFp operator*(const PointGFp& point, const BigInt& scalar)
   {
   PointGFp result(point);
   return result *= scalar;
   }

// encoding and decoding
SecureVector<byte> EC2OSP(const PointGFp& point, byte format)
   {
   if(format == PointGFp::UNCOMPRESSED)
      return encode_uncompressed(point);
   else if(format == PointGFp::COMPRESSED)
      return encode_compressed(point);
   else if(format == PointGFp::HYBRID)
      return encode_hybrid(point);
   else
      throw Invalid_Argument("illegal point encoding format specification");
   }

SecureVector<byte> encode_compressed(const PointGFp& point)
   {
   if(point.is_zero())
      {
      SecureVector<byte> result (1);
      result[0] = 0;
      return result;
      }

   u32bit l = point.get_curve().get_p().bits();
   int dummy = l & 7;
   if(dummy != 0)
      {
      l += 8 - dummy;
      }
   l /= 8;
   SecureVector<byte> result (l+1);
   result[0] = 2;
   BigInt x = point.get_affine_x();
   SecureVector<byte> bX = BigInt::encode_1363(x, l);
   result.copy(1, bX.begin(), bX.size());
   BigInt y = point.get_affine_y();
   if(y.get_bit(0))
      {
      result[0] |= 1;
      }
   return result;
   }

SecureVector<byte> encode_uncompressed(const PointGFp& point)
   {
   if(point.is_zero())
      {
      SecureVector<byte> result (1);
      result[0] = 0;
      return result;
      }
   u32bit l = point.get_curve().get_p().bits();
   int dummy = l & 7;
   if(dummy != 0)
      {
      l += 8 - dummy;
      }
   l /= 8;
   SecureVector<byte> result (2*l+1);
   result[0] = 4;
   BigInt x = point.get_affine_x();
   BigInt y = point.get_affine_y();
   SecureVector<byte> bX = BigInt::encode_1363(x, l);
   SecureVector<byte> bY = BigInt::encode_1363(y, l);
   result.copy(1, bX.begin(), l);
   result.copy(l+1, bY.begin(), l);
   return result;

   }

SecureVector<byte> encode_hybrid(const PointGFp& point)
   {
   if(point.is_zero())
      {
      SecureVector<byte> result (1);
      result[0] = 0;
      return result;
      }
   u32bit l = point.get_curve().get_p().bits();
   int dummy = l & 7;
   if(dummy != 0)
      {
      l += 8 - dummy;
      }
   l /= 8;
   SecureVector<byte> result (2*l+1);
   result[0] = 6;
   BigInt x = point.get_affine_x();
   BigInt y = point.get_affine_y();
   SecureVector<byte> bX = BigInt::encode_1363(x, l);
   SecureVector<byte> bY = BigInt::encode_1363(y, l);
   result.copy(1, bX.begin(), bX.size());
   result.copy(l+1, bY.begin(), bY.size());
   if(y.get_bit(0))
      {
      result[0] |= 1;
      }
   return result;
   }

PointGFp OS2ECP(const MemoryRegion<byte>& os, const CurveGFp& curve)
   {
   if(os.size() == 1 && os[0] == 0)
      return PointGFp(curve); // return zero

   const byte pc = os[0];

   BigInt x, y;

   if(pc == 2 || pc == 3)
      {
      //compressed form
      x = BigInt::decode(&os[1], os.size() - 1);

      bool yMod2 = ((pc & 0x01) == 1);
      y = decompress_point(yMod2, x, curve);
      }
   else if(pc == 4)
      {
      // uncompressed form
      u32bit l = (os.size() - 1) / 2;

      x = BigInt::decode(&os[1], l);
      y = BigInt::decode(&os[l+1], l);
      }
   else if(pc == 6 || pc == 7)
      {
      // hybrid form
      u32bit l = (os.size() - 1) / 2;

      x = BigInt::decode(&os[1], l);
      y = BigInt::decode(&os[l+1], l);

      bool yMod2 = ((pc & 0x01) == 1);

      if(decompress_point(yMod2, x, curve) != y)
         throw Illegal_Point("OS2ECP: Decoding error in hybrid format");
      }
   else
      throw Invalid_Argument("OS2ECP: Unknown format type");

   PointGFp result(curve, x, y);
   result.check_invariants();
   return result;
   }

PointGFp create_random_point(RandomNumberGenerator& rng,
                             const CurveGFp& curve)
   {
   const BigInt& p = curve.get_p();

   while(true)
      {
      BigInt r(rng, p.bits());

      GFpElement x = GFpElement(p, r);
      GFpElement x3 = x * x * x;

      GFpElement y = (curve.get_a() * x) + (x3 * curve.get_b());

      if(ressol(y.get_value(), p) > 0)
         return PointGFp(curve, x.get_value(), y.get_value());
      }
   }

} // namespace Botan
