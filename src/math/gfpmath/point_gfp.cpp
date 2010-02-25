/*
* Arithmetic for point groups of elliptic curves over GF(p)
*
* (C) 2007 Martin Doering, Christoph Ludwig, Falko Strenzke
*     2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/point_gfp.h>
#include <botan/numthry.h>

namespace Botan {

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
                   const GFpElement& x,
                   const GFpElement& y) :
   mC(curve),
   mX(x),
   mY(y),
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
      {
      *this = minus_rhs;
      }
   else
      {
      *this += minus_rhs;
      }
   return *this;
   }

PointGFp& PointGFp::operator*=(const BigInt& scalar)
   {
   // use montgomery mult. in this operation

   PointGFp H(this->mC); // create as zero
   PointGFp P(*this);
   BigInt m(scalar);

   if(m < BigInt(0))
      {
      m = -m;
      P.negate();
      }

   if(P.is_zero() || (m == BigInt(0)))
      {
      *this = H;
      return *this;
      }

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

GFpElement PointGFp::get_affine_x() const
   {
   if(is_zero())
      throw Illegal_Transformation("cannot convert to affine");

   GFpElement z2 = mZ * mZ;
   return mX * z2.inverse_in_place();
   }

GFpElement PointGFp::get_affine_y() const
   {
   if(is_zero())
      throw Illegal_Transformation("cannot convert to affine");

   GFpElement z3 = mZ * mZ * mZ;
   return mY * z3.inverse_in_place();
   }

// Is this the point at infinity?
bool PointGFp::is_zero() const
   {
   return(mX.is_zero() && mZ.is_zero());
   //NOTE: the calls to GFpElement::is_zero() instead of getting the value and
   // and comparing it are import because they do not provoke backtransformations
   // to the ordinary residue.
   }

// Is the point still on the curve??
// (If everything is correct, the point is always on its curve; then the
// function will return silently. If Oskar managed to corrupt this object's state,
// then it will throw an exception.)

void PointGFp::check_invariants() const
   {
   if(is_zero())
      {
      return;
      }
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
   SecureVector<byte> result;
   if(format == PointGFp::UNCOMPRESSED)
      {
      result = encode_uncompressed(point);
      }
   else if(format == PointGFp::COMPRESSED)
      {
      result = encode_compressed(point);

      }
   else if(format == PointGFp::HYBRID)
      {
      result = encode_hybrid(point);
      }
   else
      {
      throw Invalid_Argument("illegal point encoding format specification");
      }
   return result;
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
   BigInt x = point.get_affine_x().get_value();
   SecureVector<byte> bX = BigInt::encode_1363(x, l);
   result.copy(1, bX.begin(), bX.size());
   BigInt y = point.get_affine_y().get_value();
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
   BigInt x = point.get_affine_x().get_value();
   BigInt y = point.get_affine_y().get_value();
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
   BigInt x = point.get_affine_x().get_value();
   BigInt y = point.get_affine_y().get_value();
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

PointGFp OS2ECP(MemoryRegion<byte> const& os, const CurveGFp& curve)
   {
   if(os.size() == 1 && os[0] == 0)
      {
      return PointGFp(curve); // return zero
      }
   SecureVector<byte> bX;
   SecureVector<byte> bY;

   GFpElement x(1,0);
   GFpElement y(1,0);
   GFpElement z(1,0);

   const byte pc = os[0];
   BigInt bi_dec_x;
   BigInt bi_dec_y;
   switch (pc)
      {
      case 2:
      case 3:
         //compressed form
         bX = SecureVector<byte>(os.size() - 1);
         bX.copy(os.begin()+1, os.size()-1);

         bi_dec_x = BigInt::decode(bX, bX.size());
         x = GFpElement(curve.get_p(), bi_dec_x);
         bool yMod2;
         yMod2 = (pc & 1) == 1;
         y = PointGFp::decompress(yMod2, x, curve);
         break;
      case 4:
         // uncompressed form
         int l;
         l = (os.size() -1)/2;
         bX = SecureVector<byte>(l);
         bY = SecureVector<byte>(l);
         bX.copy(os.begin()+1, l);
         bY.copy(os.begin()+1+l, l);
         bi_dec_x = BigInt::decode(bX.begin(), bX.size());

         bi_dec_y = BigInt::decode(bY.begin(),bY.size());
         x = GFpElement(curve.get_p(), bi_dec_x);
         y = GFpElement(curve.get_p(), bi_dec_y);
         break;

      case 6:
      case 7:
         //hybrid form
         l = (os.size() - 1)/2;
         bX = SecureVector<byte>(l);
         bY = SecureVector<byte>(l);
         bX.copy(os.begin() + 1, l);
         bY.copy(os.begin()+1+l, l);
         yMod2 = (pc & 0x01) == 1;
         if(!(PointGFp::decompress(yMod2, x, curve) == y))
            {
            throw Illegal_Point("error during decoding hybrid format");
            }
         break;
      default:
         throw Invalid_Argument("encountered illegal format specification while decoding point");
      }

   PointGFp result(curve, x, y);
   result.check_invariants();
   //assert((result.get_jac_proj_x().is_trf_to_mres() && result.get_jac_proj_x().is_use_montgm()) || !result.get_jac_proj_x().is_trf_to_mres());
   //assert((result.get_jac_proj_y().is_trf_to_mres() && result.get_jac_proj_y().is_use_montgm()) || !result.get_jac_proj_y().is_trf_to_mres());
   //assert((result.get_jac_proj_z().is_trf_to_mres() && result.get_jac_proj_z().is_use_montgm()) || !result.get_jac_proj_z().is_trf_to_mres());
   return result;
   }

GFpElement PointGFp::decompress(bool yMod2, const GFpElement& x,
                                const CurveGFp& curve)
   {
   BigInt xVal = x.get_value();
   BigInt xpow3 = xVal * xVal * xVal;
   BigInt g = curve.get_a().get_value() * xVal;
   g += xpow3;
   g += curve.get_b().get_value();
   g = g%curve.get_p();
   BigInt z = ressol(g, curve.get_p());

   if(z < 0)
      throw Illegal_Point("error during decompression");

   bool zMod2 = z.get_bit(0);
   if((zMod2 && ! yMod2) || (!zMod2 && yMod2))
      {
      z = curve.get_p() - z;
      }
   return GFpElement(curve.get_p(),z);
   }

PointGFp create_random_point(RandomNumberGenerator& rng,
                             const CurveGFp& curve)
   {

   // create a random point
   GFpElement mX(1,1);
   GFpElement mY(1,1);
   GFpElement mZ(1,1);
   GFpElement minusOne(curve.get_p(), BigInt(BigInt::Negative,1));
   mY = minusOne;
   GFpElement y2(1,1);
   GFpElement x(1,1);

   while (mY == minusOne)
      {
      BigInt value(rng, curve.get_p().bits());
      mX = GFpElement(curve.get_p(),value);
      y2 = curve.get_a() * mX;
      x = mX * mX;
      x *= mX;
      y2 += (x + curve.get_b());

      value = ressol(y2.get_value(), curve.get_p());

      if(value < 0)
         mY = minusOne;
      else
         mY = GFpElement(curve.get_p(), value);
      }

   return PointGFp(curve, mX, mY);
   }

} // namespace Botan
