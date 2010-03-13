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

namespace Botan {

namespace {

void inner_montg_mult_sos(word result[],
                          const word a_bar[], const word b_bar[],
                          const word n[],
                          const word n_dash[], u32bit s)
   {
   SecureVector<word> t;
   t.grow_to(2*s+1);

   // t = a_bar * b_bar
   for (u32bit i=0; i<s; i++)
      {
      word C = 0;
      word S = 0;
      for (u32bit j=0; j<s; j++)
         {
         // we use:
         // word word_madd3(word a, word b, word c, word d, word* carry)
         // returns a * b + c + d and resets the carry (not using it as input)

         S = word_madd3(a_bar[j], b_bar[i], t[i+j], &C);
         t[i+j] = S;
         }
      t[i+s] = C;
      }

   // ???
   for (u32bit i=0; i<s; i++)
      {
      // word word_madd2(word a, word b, word c, word* carry)
      // returns a * b + c, resets the carry

      word C = 0;
      word zero = 0;
      word m = word_madd2(t[i], n_dash[0], &zero);

      for (u32bit j=0; j<s; j++)
         {
         word S = word_madd3(m, n[j], t[i+j], &C);
         t[i+j] = S;
         }

      //// mp_mulop.cpp:
      ////word bigint_mul_add_words(word z[], const word x[], u32bit x_size, word y)
      u32bit cnt = 0;
      while (C > 0)
         {
         // we need not worry here about C > 1, because the other operand is zero

         word tmp = t[i+s+cnt] + C;
         C = (tmp < t[i+s+cnt]);
         t[i+s+cnt] = tmp;
         cnt++;
         }
      }

   // u = t
   SecureVector<word> u;
   u.grow_to(s+1);
   for (u32bit j=0; j<s+1; j++)
      {
      u[j] = t[j+s];
      }

   // t = u - n
   word B = 0;
   word D = 0;
   for (u32bit i=0; i<s; i++)
      {
      D = word_sub(u[i], n[i], &B);
      t[i] = D;
      }
   D = word_sub(u[s], 0, &B);
   t[s] = D;

   // if t >= 0 (B == 0 -> no borrow), return t
   if(B == 0)
      {
      for (u32bit i=0; i<s; i++)
         {
         result[i] = t[i];
         }
      }
   else // else return u
      {
      for (u32bit i=0; i<s; i++)
         {
         result[i] = u[i];
         }
      }
   }

void compute_montgomery_params(const BigInt& prime,
                               BigInt& r,
                               BigInt& r_inv,
                               BigInt& p_dash)
   {
   if(!prime.is_odd())
      throw Internal_Error("PointGFp: Only operates with odd primes");

   r = 1;
   r <<= prime.sig_words() * BOTAN_MP_WORD_BITS;

   r_inv = inverse_mod(r, prime);

   p_dash = ((r * r_inv) - 1) / prime;
   }

}

PointGFp::PointGFp(const CurveGFp& curve) :
   curve(curve), coord_x(0), coord_y(1), coord_z(0)
   {
   compute_montgomery_params(curve.get_p(), r, r_inv, p_dash);
   }

PointGFp::PointGFp(const CurveGFp& curve, const BigInt& x, const BigInt& y) :
   curve(curve), coord_x(x), coord_y(y), coord_z(1)
   {
   compute_montgomery_params(curve.get_p(), r, r_inv, p_dash);
   }

BigInt PointGFp::monty_mult(const BigInt& a, const BigInt& b)
   {
   BigInt result = 0;

   if(a.is_zero() || b.is_zero())
      return result;

   const BigInt& p = curve.get_p();
   const u32bit s = p.sig_words();

   result.grow_to(s);

   if(a.size() >= s && b.size() >= s)
      {
      inner_montg_mult_sos(result.get_reg(), a.data(), b.data(),
                           p.data(), p_dash.data(), s);
      }
   else
      {
      BigInt a2 = a;
      BigInt b2 = b;
      a2.grow_to(s);
      b2.grow_to(s);
      inner_montg_mult_sos(result.get_reg(), a2.data(), b2.data(),
                           p.data(), p_dash.data(), s);
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
         mult2();
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

   for(int i = scalar.bits() - 1; i >= 0; --i)
      {
      H.mult2();
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

   BigInt y_2 = mod_p.square(coord_y);

   BigInt S = mod_p.multiply(4, mod_p.multiply(coord_x, y_2));

   BigInt a_z4 = mod_p.multiply(curve.get_a(),
                                mod_p.square(mod_p.square(coord_z)));

   BigInt M = mod_p.reduce(a_z4 + 3 * mod_p.square(coord_x));

   BigInt x = mod_p.reduce(mod_p.square(M) - mod_p.multiply(2, S));

   BigInt U = mod_p.multiply(8, mod_p.square(y_2));

   BigInt y = mod_p.reduce(mod_p.multiply(M, S - x) - U);

   BigInt z = mod_p.multiply(2, mod_p.multiply(coord_y, coord_z));

   coord_x = x;
   coord_y = y;
   coord_z = z;
   }

BigInt PointGFp::get_affine_x() const
   {
   if(is_zero())
      throw Illegal_Transformation("Cannot convert zero point to affine");

   const Modular_Reducer& mod_p = curve.mod_p();

   BigInt z2 = mod_p.square(coord_z);
   return mod_p.multiply(coord_x, inverse_mod(z2, curve.get_p()));
   }

BigInt PointGFp::get_affine_y() const
   {
   if(is_zero())
      throw Illegal_Transformation("Cannot convert zero point to affine");

   const Modular_Reducer& mod_p = curve.mod_p();

   BigInt z3 = mod_p.cube(coord_z);
   return mod_p.multiply(coord_y, inverse_mod(z3, curve.get_p()));
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
