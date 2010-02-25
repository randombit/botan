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
   curve(curve),
   coord_x(0),
   coord_y(1),
   coord_z(0)
   {
   }

// construct a point given its jacobian projective coordinates
PointGFp::PointGFp(const CurveGFp& curve,
                   const BigInt& x,
                   const BigInt& y,
                   const BigInt& z) :
   curve(curve),
   coord_x(x),
   coord_y(y),
   coord_z(z)
   {
   }

PointGFp::PointGFp(const CurveGFp& curve,
                   const BigInt& x,
                   const BigInt& y) :
   curve(curve),
   coord_x(x),
   coord_y(y),
   coord_z(1)
   {
   }

// arithmetic operators
PointGFp& PointGFp::operator+=(const PointGFp& rhs)
   {
   if(rhs.is_zero())
      return *this;

   if(is_zero())
      {
      *this = rhs;
      return *this;
      }

   GFpElement U1 = point_x();
   GFpElement S1 = point_y();

   GFpElement rhs_z2 = rhs.point_z() * rhs.point_z();
   U1 *= rhs_z2;
   S1 *= rhs_z2 * rhs.point_z();

   GFpElement U2 = rhs.point_x();
   GFpElement S2 = rhs.point_y();

   GFpElement lhs_z2 = point_z() * point_z();
   U2 *= lhs_z2;
   S2 *= lhs_z2 * point_z();

   GFpElement H(U2 - U1);
   GFpElement r(S2 - S1);

   if(H.is_zero())
      {
      if(r.is_zero())
         {
         mult2_in_place();
         return *this;
         }

      *this = PointGFp(curve); // setting myself to zero
      return *this;
      }

   U2 = H * H;

   S2 = U2 * H;

   U2 *= U1;

   GFpElement x(r*r - S2 - (U2+U2));

   GFpElement z(S1 * S2);

   GFpElement y(r * (U2-x) - z);

   z = (point_z() * rhs.point_z()) * H;

   coord_x = x.get_value();
   coord_y = y.get_value();
   coord_z = z.get_value();

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
   PointGFp H(this->curve); // create as zero
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
      coord_y = curve.get_p() - coord_y;

   return *this;
   }

// *this *= 2
PointGFp& PointGFp::mult2_in_place()
   {
   if(is_zero())
      return *this;
   else if(coord_y.is_zero())
      {
      *this = PointGFp(curve); // setting myself to zero
      return *this;
      }

   GFpElement Y_squared = point_y()*point_y();

   GFpElement S = point_x() * Y_squared;

   GFpElement x = S + S;

   S = x + x;

   GFpElement a_z4 = curve.get_a();

   GFpElement z2 = point_z() * point_z();
   a_z4 *= z2;
   a_z4 *= z2;

   GFpElement y(point_x() * point_x());

   GFpElement M(y + y + y + a_z4);

   x = M * M - (S+S);

   y = Y_squared * Y_squared;

   GFpElement U(y + y);

   GFpElement z = U + U;

   U = z + z;

   y = M * (S - x) - U;

   z = point_y() * point_z();

   z = z + z;

   coord_x = x.get_value();
   coord_y = y.get_value();
   coord_z = z.get_value();

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
   if(coord_z.is_zero())
      throw Illegal_Transformation("cannot convert Z to one");

   if(coord_z != 1)
      {
      // Converts to affine coordinates
      GFpElement z = inverse(point_z());
      GFpElement z2 = z * z;
      z *= z2;
      GFpElement x = point_x() * z2;
      GFpElement y = point_y() * z;

      coord_x = x.get_value();
      coord_y = y.get_value();
      coord_z = 1;
      }

   return *this;
   }

BigInt PointGFp::get_affine_x() const
   {
   if(is_zero())
      throw Illegal_Transformation("cannot convert to affine");

   GFpElement z2 = point_z() * point_z();
   z2.inverse_in_place();
   z2 *= point_x();

   return z2.get_value();
   }

BigInt PointGFp::get_affine_y() const
   {
   if(is_zero())
      throw Illegal_Transformation("cannot convert to affine");

   GFpElement z3 = point_z() * point_z() * point_z();
   z3.inverse_in_place();
   z3 *= point_y();

   return z3.get_value();
   }

// Is this the point at infinity?
bool PointGFp::is_zero() const
   {
   return(coord_x.is_zero() && coord_z.is_zero());
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

   const GFpElement y2 = point_y() * point_y();
   const GFpElement x3 = point_x() * point_x() * point_x();

   if(coord_z == BigInt(1))
      {
      GFpElement ax = curve.get_a() * point_x();
      if(y2 != (x3 + ax + curve.get_b()))
         throw Illegal_Point();
      }

   GFpElement Zpow2 = point_z() * point_z();
   GFpElement Zpow3 = Zpow2 * point_z();
   GFpElement AZpow4 = Zpow3 * point_z() * curve.get_a();
   const GFpElement aXZ4 = AZpow4 * point_x();
   const GFpElement bZ6 = curve.get_b() * Zpow3 * Zpow3;

   if(y2 != (x3 + aXZ4 + bZ6))
      throw Illegal_Point();
   }

// swaps the states of *this and other, does not throw!
void PointGFp::swap(PointGFp& other)
   {
   curve.swap(other.curve);
   coord_x.swap(other.coord_x);
   coord_y.swap(other.coord_y);
   coord_z.swap(other.coord_z);
   }

bool PointGFp::operator==(const PointGFp& other) const
   {
   if(get_curve() != other.get_curve())
      return false;

   return (coord_x == other.coord_x &&
           coord_y == other.coord_y &&
           coord_z == other.coord_z);
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
   if(point.is_zero())
      return SecureVector<byte>(1); // single 0 byte

   const u32bit p_bytes = point.get_curve().get_p().bytes();

   BigInt x = point.get_affine_x();
   BigInt y = point.get_affine_y();

   SecureVector<byte> bX = BigInt::encode_1363(x, p_bytes);
   SecureVector<byte> bY = BigInt::encode_1363(y, p_bytes);

   if(format == PointGFp::UNCOMPRESSED)
      {
      SecureVector<byte> result(2*p_bytes+1);
      result[0] = 4;

      result.copy(1, bX.begin(), p_bytes);
      result.copy(p_bytes+1, bY.begin(), p_bytes);
      return result;
      }
   else if(format == PointGFp::COMPRESSED)
      {
      SecureVector<byte> result(p_bytes+1);
      result[0] = 2;

      result.copy(1, bX.begin(), bX.size());

      if(y.get_bit(0))
         result[0] |= 1;

      return result;
      }
   else if(format == PointGFp::HYBRID)
      {
      SecureVector<byte> result(2*p_bytes+1);
      result[0] = 6;

      result.copy(1, bX.begin(), bX.size());
      result.copy(p_bytes+1, bY.begin(), bY.size());

      if(y.get_bit(0))
         result[0] |= 1;

      return result;
      }
   else
      throw Invalid_Argument("illegal point encoding format specification");
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
