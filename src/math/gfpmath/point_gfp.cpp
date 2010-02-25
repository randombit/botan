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

   BigInt g = curve.get_a() * x;
   g += xpow3;
   g += curve.get_b();
   g = g % curve.get_p();

   BigInt z = ressol(g, curve.get_p());

   if(z < 0)
      throw Illegal_Point("error during decompression");

   if(z.get_bit(0) != yMod2)
      z = curve.get_p() - z;

   return z;
   }

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

   const Modular_Reducer& mod_p = curve.mod_p();

   BigInt rhs_z2 = mod_p.square(rhs.coord_z);
   BigInt U1 = mod_p.multiply(coord_x, rhs_z2);
   BigInt S1 = mod_p.multiply(coord_y, mod_p.multiply(rhs.coord_z, rhs_z2));

   BigInt lhs_z2 = mod_p.square(coord_z);
   BigInt U2 = mod_p.multiply(rhs.coord_x, lhs_z2);
   BigInt S2 = mod_p.multiply(rhs.coord_y, mod_p.multiply(coord_z, lhs_z2));

   BigInt H = mod_p.reduce(U2 - U1);
   BigInt r = mod_p.reduce(S2 - S1);

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

   U2 = mod_p.square(H);

   S2 = mod_p.multiply(U2, H);

   U2 = mod_p.multiply(U1, U2);

   BigInt x = mod_p.reduce(mod_p.square(r) - S2 - mod_p.multiply(2, U2));
   BigInt y = mod_p.reduce(mod_p.multiply(r, (U2-x)) - mod_p.multiply(S1, S2));
   BigInt z = mod_p.multiply(mod_p.multiply(coord_z, rhs.coord_z), H);

   coord_x = x;
   coord_y = y;
   coord_z = z;

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
   if(scalar.abs() <= 2) // special cases for small values
      {
      u32bit value = scalar.abs().to_u32bit();

      if(value == 0)
         *this = PointGFp(curve); // set to zero point
      else if(value == 1)
         {
         if(scalar.is_negative())
            this->negate();
         }
      else if(value == 2)
         {
         this->mult2_in_place();
         if(scalar.is_negative())
            this->negate();
         }

      return *this;
      }

   PointGFp H(this->curve); // create as zero
   PointGFp P(*this);

   if(scalar.is_negative())
      P.negate();

   for(int i = scalar.bits() - 1; i >= 0; --i)
      {
      H.mult2_in_place();
      if(scalar.get_bit(i))
         H += P;
      }

   if(!H.is_zero()) // cannot convert if H == O
      {
      /**
      * Convert H to an equivalent point with z == 1, thus x and y
      * correspond to their affine coordinates
      */
      if(H.coord_z != 1)
         {
         const Modular_Reducer& mod_p = curve.mod_p();

         BigInt z_inv = inverse_mod(H.coord_z, curve.get_p());

         BigInt z_inv_2 = mod_p.square(z_inv);

         H.coord_x = mod_p.multiply(H.coord_x, z_inv_2);
         H.coord_y = mod_p.multiply(H.coord_y, mod_p.multiply(z_inv, z_inv_2));
         H.coord_z = 1;
         }
      }

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
void PointGFp::mult2_in_place()
   {
   if(is_zero())
      return;
   else if(coord_y.is_zero())
      {
      *this = PointGFp(curve); // setting myself to zero
      return;
      }

   const Modular_Reducer& mod_p = curve.mod_p();

   BigInt y_2 = mod_p.square(coord_y);

   BigInt S = mod_p.multiply(4, mod_p.multiply(coord_x, y_2));

   BigInt a_z4 = mod_p.multiply(curve.get_a(),
                                mod_p.square(mod_p.square(coord_z)));

   BigInt M = mod_p.reduce(a_z4 + 3 * mod_p.square(coord_x));

   BigInt x = mod_p.reduce(mod_p.square(M) - mod_p.multiply(2, S));

   BigInt y = mod_p.square(y_2);

   BigInt z = mod_p.multiply(2, mod_p.reduce(y + y));

   BigInt U = mod_p.reduce(z + z);

   y = mod_p.reduce(mod_p.multiply(M, S - x) - U);

   z = mod_p.multiply(2, mod_p.multiply(coord_y, coord_z));

   coord_x = x;
   coord_y = y;
   coord_z = z;
   }

BigInt PointGFp::get_affine_x() const
   {
   if(is_zero())
      throw Illegal_Transformation("cannot convert to affine");

   const Modular_Reducer& mod_p = curve.mod_p();

   BigInt z2 = mod_p.square(coord_z);
   return mod_p.multiply(coord_x, inverse_mod(z2, curve.get_p()));
   }

BigInt PointGFp::get_affine_y() const
   {
   if(is_zero())
      throw Illegal_Transformation("cannot convert to affine");

   const Modular_Reducer& mod_p = curve.mod_p();

   BigInt z3 = mod_p.cube(coord_z);
   return mod_p.multiply(coord_y, inverse_mod(z3, curve.get_p()));
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

   const Modular_Reducer& mod_p = curve.mod_p();

   BigInt y2 = mod_p.square(coord_y);
   BigInt x3 = mod_p.cube(coord_x);

   BigInt ax = mod_p.multiply(coord_x, curve.get_a());

   if(coord_z == 1)
      {
      if(mod_p.reduce(x3 + ax + curve.get_b()) != y2)
         throw Illegal_Point("Invalid ECP point: y^2 != x^3 + a*x + b");
      }

   BigInt z2 = mod_p.square(coord_z);
   BigInt z3 = mod_p.multiply(coord_z, z2);

   BigInt ax_z4 = mod_p.multiply(mod_p.multiply(z3, coord_z), ax);

   BigInt b_z6 = mod_p.multiply(curve.get_b(), mod_p.square(z3));

   if(y2 != mod_p.reduce(x3 + ax_z4 + b_z6))
      throw Illegal_Point("Invalid ECP point: y^2 != x^3 + a*x*z^4 + b*z^6");
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
   return (coord_x == other.coord_x &&
           coord_y == other.coord_y &&
           coord_z == other.coord_z &&
           get_curve() == other.get_curve());
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

}
