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
#include <botan/mp_asm.h>
#include <botan/mp_asmi.h>
#include <botan/mp_core.h>

namespace Botan {

PointGFp::PointGFp(const CurveGFp& curve) :
   curve(curve),
   coord_x(0),
   coord_y(curve.get_r()),
   coord_z(0)
   {
   }

PointGFp::PointGFp(const CurveGFp& curve, const BigInt& x, const BigInt& y) :
   curve(curve)
   {
   const Modular_Reducer& mod_p = curve.mod_p();

   coord_x = mod_p.multiply(curve.get_r(), x);
   coord_y = mod_p.multiply(curve.get_r(), y);
   coord_z = curve.get_r();
   }

BigInt PointGFp::monty_mult(const BigInt& a, const BigInt& b)
   {
   if(a.is_zero() || b.is_zero())
      return 0;

   const BigInt& p = curve.get_p();
   const u32bit p_size = p.sig_words();

   const word p_dash = curve.get_p_dash();

   SecureVector<word> t;
   t.grow_to(2*p_size+1);

   if(a > 0 && b > 0 && a < p && b < p)
      {
      bigint_simple_mul(t, a.data(), a.sig_words(), b.data(), b.sig_words());
      }
   else
      {
      const Modular_Reducer& mod_p = curve.mod_p();

      BigInt a2 = mod_p.reduce(a);
      BigInt b2 = mod_p.reduce(b);

      bigint_simple_mul(t, a2.data(), a2.sig_words(), b2.data(), b2.sig_words());
      }

   BigInt result;
   std::swap(result.get_reg(), t);
   bigint_monty_redc(result.get_reg(), result.size(), p.data(), p_size, p_dash);
   result >>= p_size*BOTAN_MP_WORD_BITS;

   return result;
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

   BigInt rhs_z2 = monty_mult(rhs.coord_z, rhs.coord_z);
   BigInt U1 = monty_mult(coord_x, rhs_z2);
   BigInt S1 = monty_mult(coord_y, monty_mult(rhs.coord_z, rhs_z2));

   BigInt lhs_z2 = monty_mult(coord_z, coord_z);
   BigInt U2 = monty_mult(rhs.coord_x, lhs_z2);
   BigInt S2 = monty_mult(rhs.coord_y, monty_mult(coord_z, lhs_z2));

   BigInt H = mod_p.reduce(U2 - U1);

   BigInt r = mod_p.reduce(S2 - S1);

   if(H.is_zero())
      {
      if(r.is_zero())
         {
         mult2();
         return *this;
         }

      *this = PointGFp(curve); // setting myself to zero
      return *this;
      }

   U2 = monty_mult(H, H);

   S2 = monty_mult(U2, H);

   U2 = monty_mult(U1, U2);

   BigInt x = mod_p.reduce(monty_mult(r, r) - S2 - U2*2);

   U2 -= x;
   if(U2.is_negative())
      U2 += curve.get_p();

   BigInt y = monty_mult(r, U2) - monty_mult(S1, S2);
   if(y.is_negative())
      y += curve.get_p();

   BigInt z = monty_mult(monty_mult(coord_z, rhs.coord_z), H);

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
         this->mult2();
         if(scalar.is_negative())
            this->negate();
         }

      return *this;
      }

   PointGFp H(this->curve); // create as zero
   PointGFp P(*this);

   if(scalar.is_negative())
      P.negate();

   u32bit scalar_bits = scalar.bits();

   PointGFp P2 = P * 2;
   PointGFp P3 = P2 + P;

   for(u32bit i = 0; i < scalar_bits - 1; i += 2)
      {
      u32bit twobits = scalar.get_substring(scalar_bits - i - 2, 2);

      H.mult2();
      H.mult2();

      if(twobits == 3)
         H += P3;
      else if(twobits == 2)
         H += P2;
      else if(twobits == 1)
         H += P;
      }

   if(scalar_bits % 2)
      {
      H.mult2();
      if(scalar.get_bit(0))
         H += P;
      }

   *this = H;
   return *this;
   }

// *this *= 2
void PointGFp::mult2()
   {
   if(is_zero())
      return;
   else if(coord_y.is_zero())
      {
      *this = PointGFp(curve); // setting myself to zero
      return;
      }

   const Modular_Reducer& mod_p = curve.mod_p();

   BigInt y_2 = monty_mult(coord_y, coord_y);

   BigInt S = mod_p.reduce(4 * monty_mult(coord_x, y_2));

   BigInt z4 = monty_mult(coord_z, coord_z);
   z4 = monty_mult(z4, z4);

   BigInt a_z4 = monty_mult(curve.get_a_r(), z4);

   BigInt M = mod_p.reduce(a_z4 + 3 * monty_mult(coord_x, coord_x));

   BigInt x = mod_p.reduce(monty_mult(M, M) - 2*S);

   BigInt U = mod_p.reduce(monty_mult(y_2, y_2) << 3);

   BigInt y = monty_mult(M, S - x) - U;

   if(y.is_negative())
      y += curve.get_p();

   BigInt z = 2 * monty_mult(coord_y, coord_z);
   if(z >= curve.get_p())
      z -= curve.get_p();

   coord_x = x;
   coord_y = y;
   coord_z = z;
   }

BigInt PointGFp::get_affine_x() const
   {
   if(is_zero())
      throw Illegal_Transformation("Cannot convert zero point to affine");

   const Modular_Reducer& mod_p = curve.mod_p();

   BigInt x = mod_p.multiply(curve.get_r_inv(), coord_x);
   BigInt z = mod_p.multiply(curve.get_r_inv(), coord_z);

   BigInt z2 = mod_p.square(z);
   return mod_p.multiply(x, inverse_mod(z2, curve.get_p()));
   }

BigInt PointGFp::get_affine_y() const
   {
   if(is_zero())
      throw Illegal_Transformation("Cannot convert zero point to affine");

   const Modular_Reducer& mod_p = curve.mod_p();

   BigInt y = mod_p.multiply(curve.get_r_inv(), coord_y);
   BigInt z = mod_p.multiply(curve.get_r_inv(), coord_z);

   BigInt z3 = mod_p.cube(z);
   return mod_p.multiply(y, inverse_mod(z3, curve.get_p()));
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

   BigInt x = mod_p.multiply(curve.get_r_inv(), coord_x);
   BigInt y = mod_p.multiply(curve.get_r_inv(), coord_y);
   BigInt z = mod_p.multiply(curve.get_r_inv(), coord_z);

   BigInt y2 = mod_p.square(y);
   BigInt x3 = mod_p.cube(x);

   BigInt ax = mod_p.multiply(x, curve.get_a());

   if(z == 1)
      {
      if(mod_p.reduce(x3 + ax + curve.get_b()) != y2)
         throw Illegal_Point("Invalid ECP point: y^2 != x^3 + a*x + b");
      }

   BigInt z2 = mod_p.square(z);
   BigInt z3 = mod_p.multiply(z, z2);

   BigInt ax_z4 = mod_p.multiply(mod_p.multiply(z3, z), ax);

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
   if(get_curve() != other.get_curve())
      return false;

   // If this is zero, only equal if other is also zero
   if(is_zero())
      return other.is_zero();

   return (get_affine_x() == other.get_affine_x() &&
           get_affine_y() == other.get_affine_y());
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

PointGFp OS2ECP(const byte data[], u32bit data_len,
                const CurveGFp& curve)
   {
   if(data_len <= 1)
      return PointGFp(curve); // return zero

   const byte pc = data[0];

   BigInt x, y;

   if(pc == 2 || pc == 3)
      {
      //compressed form
      x = BigInt::decode(&data[1], data_len - 1);

      bool yMod2 = ((pc & 0x01) == 1);
      y = decompress_point(yMod2, x, curve);
      }
   else if(pc == 4)
      {
      const u32bit l = (data_len - 1) / 2;

      // uncompressed form
      x = BigInt::decode(&data[1], l);
      y = BigInt::decode(&data[l+1], l);
      }
   else if(pc == 6 || pc == 7)
      {
      const u32bit l = (data_len - 1) / 2;

      // hybrid form
      x = BigInt::decode(&data[1], l);
      y = BigInt::decode(&data[l+1], l);

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
