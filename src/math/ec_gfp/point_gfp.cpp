/*
* Point arithmetic on elliptic curves over GF(p)
*
* (C) 2007 Martin Doering, Christoph Ludwig, Falko Strenzke
*     2008-2011 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/point_gfp.h>
#include <botan/numthry.h>
#include <botan/reducer.h>
#include <botan/internal/mp_core.h>

namespace Botan {

PointGFp::PointGFp(const CurveGFp& curve) :
   curve(curve), ws(2 * (curve.get_p_words() + 2))
   {
   coord_x = 0;
   coord_y = monty_mult(1, curve.get_r2());
   coord_z = 0;
   }

PointGFp::PointGFp(const CurveGFp& curve, const BigInt& x, const BigInt& y) :
   curve(curve), ws(2 * (curve.get_p_words() + 2))
   {
   coord_x = monty_mult(x, curve.get_r2());
   coord_y = monty_mult(y, curve.get_r2());
   coord_z = monty_mult(1, curve.get_r2());
   }

// Montgomery multiplication
void PointGFp::monty_mult(BigInt& z, const BigInt& x, const BigInt& y) const
   {
   //assert(&z != &x && &z != &y);

   if(x.is_zero() || y.is_zero())
      {
      z = 0;
      return;
      }

   const BigInt& p = curve.get_p();
   const size_t p_size = curve.get_p_words();
   const word p_dash = curve.get_p_dash();

   SecureVector<word>& z_reg = z.get_reg();
   z_reg.resize(2*p_size+1);
   zeroise(z_reg);

   bigint_monty_mul(&z_reg[0], z_reg.size(),
                    x.data(), x.size(), x.sig_words(),
                    y.data(), y.size(), y.sig_words(),
                    p.data(), p_size, p_dash,
                    &ws[0]);
   }

// Montgomery squaring
void PointGFp::monty_sqr(BigInt& z, const BigInt& x) const
   {
   //assert(&z != &x);

   if(x.is_zero())
      {
      z = 0;
      return;
      }

   const BigInt& p = curve.get_p();
   const size_t p_size = curve.get_p_words();
   const word p_dash = curve.get_p_dash();

   SecureVector<word>& z_reg = z.get_reg();
   z_reg.resize(2*p_size+1);
   zeroise(z_reg);

   bigint_monty_sqr(&z_reg[0], z_reg.size(),
                    x.data(), x.size(), x.sig_words(),
                    p.data(), p_size, p_dash,
                    &ws[0]);
   }

// Point addition
void PointGFp::add(const PointGFp& rhs, std::vector<BigInt>& ws_bn)
   {
   if(is_zero())
      {
      coord_x = rhs.coord_x;
      coord_y = rhs.coord_y;
      coord_z = rhs.coord_z;
      return;
      }
   else if(rhs.is_zero())
      return;

   const BigInt& p = curve.get_p();

   BigInt& rhs_z2 = ws_bn[0];
   BigInt& U1 = ws_bn[1];
   BigInt& S1 = ws_bn[2];

   BigInt& lhs_z2 = ws_bn[3];
   BigInt& U2 = ws_bn[4];
   BigInt& S2 = ws_bn[5];

   BigInt& H = ws_bn[6];
   BigInt& r = ws_bn[7];

   monty_sqr(rhs_z2, rhs.coord_z);
   monty_mult(U1, coord_x, rhs_z2);
   monty_mult(S1, coord_y, monty_mult(rhs.coord_z, rhs_z2));

   monty_sqr(lhs_z2, coord_z);
   monty_mult(U2, rhs.coord_x, lhs_z2);
   monty_mult(S2, rhs.coord_y, monty_mult(coord_z, lhs_z2));

   H = U2;
   H -= U1;
   if(H.is_negative())
      H += p;

   r = S2;
   r -= S1;
   if(r.is_negative())
      r += p;

   if(H.is_zero())
      {
      if(r.is_zero())
         {
         mult2(ws_bn);
         return;
         }

      *this = PointGFp(curve); // setting myself to zero
      return;
      }

   monty_sqr(U2, H);

   monty_mult(S2, U2, H);

   U2 = monty_mult(U1, U2);

   monty_sqr(coord_x, r);
   coord_x -= S2;
   coord_x -= (U2 << 1);
   while(coord_x.is_negative())
      coord_x += p;

   U2 -= coord_x;
   if(U2.is_negative())
      U2 += p;

   monty_mult(coord_y, r, U2);
   coord_y -= monty_mult(S1, S2);
   if(coord_y.is_negative())
      coord_y += p;

   monty_mult(coord_z, monty_mult(coord_z, rhs.coord_z), H);
   }

// *this *= 2
void PointGFp::mult2(std::vector<BigInt>& ws_bn)
   {
   if(is_zero())
      return;
   else if(coord_y.is_zero())
      {
      *this = PointGFp(curve); // setting myself to zero
      return;
      }

   const BigInt& p = curve.get_p();

   BigInt& y_2 = ws_bn[0];
   BigInt& S = ws_bn[1];
   BigInt& z4 = ws_bn[2];
   BigInt& a_z4 = ws_bn[3];
   BigInt& M = ws_bn[4];
   BigInt& U = ws_bn[5];
   BigInt& x = ws_bn[6];
   BigInt& y = ws_bn[7];
   BigInt& z = ws_bn[8];

   monty_sqr(y_2, coord_y);

   monty_mult(S, coord_x, y_2);
   S <<= 2; // * 4
   while(S >= p)
      S -= p;

   monty_sqr(z4, monty_sqr(coord_z));
   monty_mult(a_z4, curve.get_a_r(), z4);

   M = 3 * monty_sqr(coord_x);
   M += a_z4;
   while(M >= p)
      M -= p;

   monty_sqr(x, M);
   x -= (S << 1);
   while(x.is_negative())
      x += p;

   monty_sqr(U, y_2);
   U <<= 3;
   while(U >= p)
      U -= p;

   S -= x;
   while(S.is_negative())
      S += p;

   monty_mult(y, M, S);
   y -= U;
   if(y.is_negative())
      y += p;

   monty_mult(z, coord_y, coord_z);
   z <<= 1;
   if(z >= p)
      z -= p;

   coord_x = x;
   coord_y = y;
   coord_z = z;
   }

// arithmetic operators
PointGFp& PointGFp::operator+=(const PointGFp& rhs)
   {
   std::vector<BigInt> ws(9);
   add(rhs, ws);
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
   *this = scalar * *this;
   return *this;
   }

PointGFp multi_exponentiate(const PointGFp& p1, const BigInt& z1,
                            const PointGFp& p2, const BigInt& z2)
   {
   const PointGFp p3 = p1 + p2;

   PointGFp H(p1.curve); // create as zero
   size_t bits_left = std::max(z1.bits(), z2.bits());

   std::vector<BigInt> ws(9);

   while(bits_left)
      {
      H.mult2(ws);

      const bool z1_b = z1.get_bit(bits_left - 1);
      const bool z2_b = z2.get_bit(bits_left - 1);

      if(z1_b == true && z2_b == true)
         H.add(p3, ws);
      else if(z1_b)
         H.add(p1, ws);
      else if(z2_b)
         H.add(p2, ws);

      --bits_left;
      }

   if(z1.is_negative() != z2.is_negative())
      H.negate();

   return H;
   }

PointGFp operator*(const BigInt& scalar, const PointGFp& point)
   {
   const CurveGFp& curve = point.get_curve();

   if(scalar.is_zero())
      return PointGFp(curve); // zero point

   std::vector<BigInt> ws(9);

   if(scalar.abs() <= 2) // special cases for small values
      {
      byte value = scalar.abs().byte_at(0);

      PointGFp result = point;

      if(value == 2)
         result.mult2(ws);

      if(scalar.is_negative())
         result.negate();

      return result;
      }

   const size_t scalar_bits = scalar.bits();

#if 0

   PointGFp x1 = PointGFp(curve);
   PointGFp x2 = point;

   size_t bits_left = scalar_bits;

   // Montgomery Ladder
   while(bits_left)
      {
      const bool bit_set = scalar.get_bit(bits_left - 1);

      if(bit_set)
         {
         x1.add(x2, ws);
         x2.mult2(ws);
         }
      else
         {
         x2.add(x1, ws);
         x1.mult2(ws);
         }

      --bits_left;
      }

   if(scalar.is_negative())
      x1.negate();

   return x1;

#else
   const size_t window_size = 4;

   std::vector<PointGFp> Ps(1 << window_size);
   Ps[0] = PointGFp(curve);
   Ps[1] = point;

   for(size_t i = 2; i != Ps.size(); ++i)
      {
      Ps[i] = Ps[i-1];
      Ps[i].add(point, ws);
      }

   PointGFp H(curve); // create as zero
   size_t bits_left = scalar_bits;

   while(bits_left >= window_size)
      {
      for(size_t i = 0; i != window_size; ++i)
         H.mult2(ws);

      const u32bit nibble = scalar.get_substring(bits_left - window_size,
                                                 window_size);

      H.add(Ps[nibble], ws);

      bits_left -= window_size;
      }

   while(bits_left)
      {
      H.mult2(ws);
      if(scalar.get_bit(bits_left-1))
         H.add(point, ws);

      --bits_left;
      }

   if(scalar.is_negative())
      H.negate();

   return H;
#endif
   }

BigInt PointGFp::get_affine_x() const
   {
   if(is_zero())
      throw Illegal_Transformation("Cannot convert zero point to affine");

   const BigInt& r2 = curve.get_r2();

   BigInt z2 = monty_sqr(coord_z);
   z2 = inverse_mod(z2, curve.get_p());

   z2 = monty_mult(z2, r2);
   return monty_mult(coord_x, z2);
   }

BigInt PointGFp::get_affine_y() const
   {
   if(is_zero())
      throw Illegal_Transformation("Cannot convert zero point to affine");

   const BigInt& r2 = curve.get_r2();

   BigInt z3 = monty_mult(coord_z, monty_sqr(coord_z));
   z3 = inverse_mod(z3, curve.get_p());
   z3 = monty_mult(z3, r2);
   return monty_mult(coord_y, z3);
   }

bool PointGFp::on_the_curve() const
   {
   /*
   Is the point still on the curve?? (If everything is correct, the
   point is always on its curve; then the function will return true.
   If somehow the state is corrupted, which suggests a fault attack
   (or internal computational error), then return false.
   */

   if(is_zero())
      return true;

   BigInt y2 = monty_mult(monty_sqr(coord_y), 1);
   BigInt x3 = monty_mult(coord_x, monty_sqr(coord_x));

   BigInt ax = monty_mult(coord_x, curve.get_a_r());

   const BigInt& b_r = curve.get_b_r();

   BigInt z2 = monty_sqr(coord_z);

   if(coord_z == z2) // Is z equal to 1 (in Montgomery form)?
      {
      if(y2 != monty_mult(x3 + ax + b_r, 1))
         return false;
      }

   BigInt z3 = monty_mult(coord_z, z2);

   BigInt ax_z4 = monty_mult(ax, monty_sqr(z2));

   BigInt b_z6 = monty_mult(b_r, monty_sqr(z3));

   if(y2 != monty_mult(x3 + ax_z4 + b_z6, 1))
      return false;

   return true;
   }

// swaps the states of *this and other, does not throw!
void PointGFp::swap(PointGFp& other)
   {
   curve.swap(other.curve);
   coord_x.swap(other.coord_x);
   coord_y.swap(other.coord_y);
   coord_z.swap(other.coord_z);
   ws.swap(other.ws);
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

   const size_t p_bytes = point.get_curve().get_p().bytes();

   BigInt x = point.get_affine_x();
   BigInt y = point.get_affine_y();

   SecureVector<byte> bX = BigInt::encode_1363(x, p_bytes);
   SecureVector<byte> bY = BigInt::encode_1363(y, p_bytes);

   if(format == PointGFp::UNCOMPRESSED)
      {
      SecureVector<byte> result;
      result.push_back(0x04);

      result += bX;
      result += bY;

      return result;
      }
   else if(format == PointGFp::COMPRESSED)
      {
      SecureVector<byte> result;
      result.push_back(0x02 | static_cast<byte>(y.get_bit(0)));

      result += bX;

      return result;
      }
   else if(format == PointGFp::HYBRID)
      {
      SecureVector<byte> result;
      result.push_back(0x06 | static_cast<byte>(y.get_bit(0)));

      result += bX;
      result += bY;

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

PointGFp OS2ECP(const byte data[], size_t data_len,
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

      const bool y_mod_2 = ((pc & 0x01) == 1);
      y = decompress_point(y_mod_2, x, curve);
      }
   else if(pc == 4)
      {
      const size_t l = (data_len - 1) / 2;

      // uncompressed form
      x = BigInt::decode(&data[1], l);
      y = BigInt::decode(&data[l+1], l);
      }
   else if(pc == 6 || pc == 7)
      {
      const size_t l = (data_len - 1) / 2;

      // hybrid form
      x = BigInt::decode(&data[1], l);
      y = BigInt::decode(&data[l+1], l);

      const bool y_mod_2 = ((pc & 0x01) == 1);

      if(decompress_point(y_mod_2, x, curve) != y)
         throw Illegal_Point("OS2ECP: Decoding error in hybrid format");
      }
   else
      throw Invalid_Argument("OS2ECP: Unknown format type");

   PointGFp result(curve, x, y);

   if(!result.on_the_curve())
      throw Illegal_Point("OS2ECP: Decoded point was not on the curve");

   return result;
   }

}
