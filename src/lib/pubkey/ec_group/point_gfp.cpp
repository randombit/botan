/*
* Point arithmetic on elliptic curves over GF(p)
*
* (C) 2007 Martin Doering, Christoph Ludwig, Falko Strenzke
*     2008-2011,2012,2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/point_gfp.h>
#include <botan/numthry.h>
#include <botan/rng.h>
#include <botan/internal/rounding.h>

namespace Botan {

PointGFp::PointGFp(const CurveGFp& curve) :
   m_curve(curve),
   m_coord_x(0),
   m_coord_y(1),
   m_coord_z(0)
   {
   secure_vector<word> monty_ws;
   m_curve.to_rep(m_coord_x, monty_ws);
   m_curve.to_rep(m_coord_y, monty_ws);
   m_curve.to_rep(m_coord_z, monty_ws);
   }

PointGFp::PointGFp(const CurveGFp& curve, const BigInt& x, const BigInt& y) :
   m_curve(curve),
   m_coord_x(x),
   m_coord_y(y),
   m_coord_z(1)
   {
   if(x <= 0 || x >= curve.get_p())
      throw Invalid_Argument("Invalid PointGFp affine x");
   if(y <= 0 || y >= curve.get_p())
      throw Invalid_Argument("Invalid PointGFp affine y");

   secure_vector<word> monty_ws;
   m_curve.to_rep(m_coord_x, monty_ws);
   m_curve.to_rep(m_coord_y, monty_ws);
   m_curve.to_rep(m_coord_z, monty_ws);
   }

void PointGFp::randomize_repr(RandomNumberGenerator& rng)
   {
   if(BOTAN_POINTGFP_RANDOMIZE_BLINDING_BITS > 1)
      {
      BigInt mask;
      while(mask.is_zero())
         mask.randomize(rng, BOTAN_POINTGFP_RANDOMIZE_BLINDING_BITS, false);

      secure_vector<word> monty_ws;

      m_curve.to_rep(mask, monty_ws);
      const BigInt mask2 = m_curve.mul_to_tmp(mask, mask, monty_ws);
      const BigInt mask3 = m_curve.mul_to_tmp(mask2, mask, monty_ws);

      m_coord_x = m_curve.mul_to_tmp(m_coord_x, mask2, monty_ws);
      m_coord_y = m_curve.mul_to_tmp(m_coord_y, mask3, monty_ws);
      m_coord_z = m_curve.mul_to_tmp(m_coord_z, mask, monty_ws);
      }
   }

void PointGFp::add_affine(const PointGFp& rhs, std::vector<BigInt>& ws_bn)
   {
   if(rhs.is_zero())
      return;

   if(is_zero())
      {
      m_coord_x = rhs.m_coord_x;
      m_coord_y = rhs.m_coord_y;
      m_coord_z = rhs.m_coord_z;
      return;
      }

   //BOTAN_ASSERT(rhs.is_affine(), "PointGFp::add_affine requires arg be affine point");

   /*
   https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-1998-cmo-2
   simplified with Z2 = 1
   */

   const BigInt& p = m_curve.get_p();

   const size_t cap_size = 2*m_curve.get_p_words() + 2;

   BOTAN_ASSERT(ws_bn.size() >= WORKSPACE_SIZE, "Expected size for PointGFp::add workspace");

   for(size_t i = 0; i != ws_bn.size(); ++i)
      ws_bn[i].ensure_capacity(cap_size);

   secure_vector<word>& ws = ws_bn[0].get_word_vector();

   BigInt& T0 = ws_bn[1];
   BigInt& T1 = ws_bn[2];
   BigInt& T2 = ws_bn[3];
   BigInt& T3 = ws_bn[4];
   BigInt& T4 = ws_bn[5];

   /*
   https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-1998-cmo-2
   */

   m_curve.sqr(T3, m_coord_z, ws); // z1^2
   m_curve.mul(T4, rhs.m_coord_x, T3, ws); // x2*z1^2

   m_curve.mul(T2, m_coord_z, T3, ws); // z1^3
   m_curve.mul(T0, rhs.m_coord_y, T2, ws); // y2*z1^3

   T4 -= m_coord_x; // x2*z1^2 - x1*z2^2
   if(T4.is_negative())
      T4 += p;

   T0 -= m_coord_y;
   if(T0.is_negative())
      T0 += p;

   if(T4.is_zero())
      {
      if(T0.is_zero())
         {
         mult2(ws_bn);
         return;
         }

      // setting to zero:
      m_coord_x = 0;
      m_coord_y = 1;
      m_coord_z = 0;
      return;
      }

   m_curve.sqr(T2, T4, ws);

   m_curve.mul(T3, m_coord_x, T2, ws);

   m_curve.mul(T1, T2, T4, ws);

   m_curve.sqr(m_coord_x, T0, ws);
   m_coord_x -= T1;
   m_coord_x -= T3;
   m_coord_x -= T3;
   while(m_coord_x.is_negative())
      m_coord_x += p;

   T3 -= m_coord_x;
   if(T3.is_negative())
      T3 += p;

   T2 = m_coord_y;
   m_curve.mul(m_coord_y, T0, T3, ws);
   m_curve.mul(T3, T2, T1, ws);
   m_coord_y -= T3;
   if(m_coord_y.is_negative())
      m_coord_y += p;

   T3 = m_coord_z;
   m_curve.mul(m_coord_z, T3, T4, ws);
   }

// Point addition
void PointGFp::add(const PointGFp& rhs, std::vector<BigInt>& ws_bn)
   {
   if(rhs.is_zero())
      return;

   if(is_zero())
      {
      m_coord_x = rhs.m_coord_x;
      m_coord_y = rhs.m_coord_y;
      m_coord_z = rhs.m_coord_z;
      return;
      }

   const BigInt& p = m_curve.get_p();

   const size_t cap_size = 2*m_curve.get_p_words() + 2;

   BOTAN_ASSERT(ws_bn.size() >= WORKSPACE_SIZE, "Expected size for PointGFp::add workspace");

   for(size_t i = 0; i != ws_bn.size(); ++i)
      ws_bn[i].ensure_capacity(cap_size);

   secure_vector<word>& ws = ws_bn[0].get_word_vector();

   BigInt& T0 = ws_bn[1];
   BigInt& T1 = ws_bn[2];
   BigInt& T2 = ws_bn[3];
   BigInt& T3 = ws_bn[4];
   BigInt& T4 = ws_bn[5];
   BigInt& T5 = ws_bn[6];

   /*
   https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-1998-cmo-2
   */

   m_curve.sqr(T0, rhs.m_coord_z, ws); // z2^2
   m_curve.mul(T1, m_coord_x, T0, ws); // x1*z2^2
   m_curve.mul(T3, rhs.m_coord_z, T0, ws); // z2^3
   m_curve.mul(T2, m_coord_y, T3, ws); // y1*z2^3

   m_curve.sqr(T3, m_coord_z, ws); // z1^2
   m_curve.mul(T4, rhs.m_coord_x, T3, ws); // x2*z1^2

   m_curve.mul(T5, m_coord_z, T3, ws); // z1^3
   m_curve.mul(T0, rhs.m_coord_y, T5, ws); // y2*z1^3

   T4 -= T1; // x2*z1^2 - x1*z2^2
   if(T4.is_negative())
      T4 += p;

   T3 = T0;
   T3 -= T2;
   if(T3.is_negative())
      T3 += p;

   if(T4.is_zero())
      {
      if(T3.is_zero())
         {
         mult2(ws_bn);
         return;
         }

      // setting to zero:
      m_coord_x = 0;
      m_coord_y = 1;
      m_coord_z = 0;
      return;
      }

   m_curve.sqr(T5, T4, ws);

   m_curve.mul(T0, T1, T5, ws);

   m_curve.mul(T1, T5, T4, ws);

   m_curve.sqr(m_coord_x, T3, ws);
   m_coord_x -= T1;
   m_coord_x -= T0;
   m_coord_x -= T0;
   while(m_coord_x.is_negative())
      m_coord_x += p;

   T0 -= m_coord_x;
   if(T0.is_negative())
      T0 += p;

   m_curve.mul(m_coord_y, T3, T0, ws);
   m_curve.mul(T0, T2, T1, ws);
   m_coord_y -= T0;
   if(m_coord_y.is_negative())
      m_coord_y += p;

   m_curve.mul(T0, m_coord_z, rhs.m_coord_z, ws);
   m_curve.mul(m_coord_z, T0, T4, ws);
   }

// *this *= 2
void PointGFp::mult2(std::vector<BigInt>& ws_bn)
   {
   if(is_zero())
      return;

   if(m_coord_y.is_zero())
      {
      *this = PointGFp(m_curve); // setting myself to zero
      return;
      }

   /*
   https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-1986-cc
   */

   const size_t cap_size = 2*m_curve.get_p_words() + 2;

   BOTAN_ASSERT(ws_bn.size() >= WORKSPACE_SIZE, "Expected size for PointGFp::add workspace");
   for(size_t i = 0; i != ws_bn.size(); ++i)
      ws_bn[i].ensure_capacity(cap_size);

   const BigInt& p = m_curve.get_p();

   secure_vector<word>& ws = ws_bn[0].get_word_vector();
   BigInt& T0 = ws_bn[1];
   BigInt& T1 = ws_bn[2];
   BigInt& T2 = ws_bn[6];
   BigInt& T3 = ws_bn[4];
   BigInt& T4 = ws_bn[5];

   m_curve.sqr(T0, m_coord_y, ws);

   m_curve.mul(T1, m_coord_x, T0, ws);
   T1 <<= 2; // * 4
   T1.reduce_below(p, T3.get_word_vector());

   m_curve.sqr(T3, m_coord_z, ws); // z^2
   m_curve.sqr(T4, T3, ws); // z^4
   m_curve.mul(T3, m_curve.get_a_rep(), T4, ws);

   m_curve.sqr(T4, m_coord_x, ws);
   T4 *= 3;
   T4 += T3;
   T4.reduce_below(p, T3.get_word_vector());

   m_curve.sqr(T2, T4, ws);
   T2 -= T1;
   T2 -= T1;
   while(T2.is_negative())
      T2 += p;
   m_coord_x = T2;

   m_curve.sqr(T3, T0, ws);
   T3 <<= 3;
   T3.reduce_below(p, T0.get_word_vector());

   T1 -= T2;
   while(T1.is_negative())
      T1 += p;

   m_curve.mul(T0, T4, T1, ws);
   T0 -= T3;
   if(T0.is_negative())
      T0 += p;

   m_curve.mul(T2, m_coord_y, m_coord_z, ws);
   T2 <<= 1;
   T2.reduce_below(p, T3.get_word_vector());

   m_coord_y = T0;
   m_coord_z = T2;
   }

// arithmetic operators
PointGFp& PointGFp::operator+=(const PointGFp& rhs)
   {
   std::vector<BigInt> ws(PointGFp::WORKSPACE_SIZE);
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

PointGFp multi_exponentiate(const PointGFp& x, const BigInt& z1,
                            const PointGFp& y, const BigInt& z2)
   {
   const size_t z_bits = round_up(std::max(z1.bits(), z2.bits()), 2);

   std::vector<BigInt> ws(PointGFp::WORKSPACE_SIZE);

   PointGFp x2 = x;
   x2.mult2(ws);

   const PointGFp x3(x2.plus(x, ws));

   PointGFp y2 = y;
   y2.mult2(ws);

   const PointGFp y3(y2.plus(y, ws));

   const PointGFp M[16] = {
      x.zero(),        // 0000
      x,               // 0001
      x2,              // 0010
      x3,              // 0011
      y,               // 0100
      y.plus(x, ws),   // 0101
      y.plus(x2, ws),  // 0110
      y.plus(x3, ws),  // 0111
      y2,              // 1000
      y2.plus(x, ws),  // 1001
      y2.plus(x2, ws), // 1010
      y2.plus(x3, ws), // 1011
      y3,              // 1100
      y3.plus(x, ws),  // 1101
      y3.plus(x2, ws), // 1110
      y3.plus(x3, ws), // 1111
   };

   PointGFp H = x.zero();

   for(size_t i = 0; i != z_bits; i += 2)
      {
      if(i > 0)
         {
         H.mult2(ws);
         H.mult2(ws);
         }

      const uint8_t z1_b = z1.get_substring(z_bits - i - 2, 2);
      const uint8_t z2_b = z2.get_substring(z_bits - i - 2, 2);

      const uint8_t z12 = (4*z2_b) + z1_b;

      H.add(M[z12], ws);
      }

   if(z1.is_negative() != z2.is_negative())
      H.negate();

   return H;
   }

PointGFp operator*(const BigInt& scalar, const PointGFp& point)
   {
   //BOTAN_ASSERT(point.on_the_curve(), "Input is on the curve");

   const size_t scalar_bits = scalar.bits();

   std::vector<BigInt> ws(PointGFp::WORKSPACE_SIZE);

   PointGFp R[2] = { point.zero(), point };

   for(size_t i = scalar_bits; i > 0; i--)
      {
      const size_t b = scalar.get_bit(i - 1);
      R[b ^ 1].add(R[b], ws);
      R[b].mult2(ws);
      }

   if(scalar.is_negative())
      R[0].negate();

   //BOTAN_ASSERT(R[0].on_the_curve(), "Output is on the curve");

   return R[0];
   }

void PointGFp::force_affine()
   {
   if(is_zero())
      throw Invalid_State("Cannot convert zero ECC point to affine");

   secure_vector<word> ws;
   BigInt z2 = m_curve.sqr_to_tmp(m_coord_z, ws);
   BigInt z3 = m_curve.mul_to_tmp(m_coord_z, z2, ws);

   const BigInt z5 = m_curve.mul_to_tmp(z2, z3, ws);
   const BigInt z5_inv = m_curve.invert_element(z5, ws);
   const BigInt z2_inv = m_curve.mul_to_tmp(z5_inv, z3, ws);
   const BigInt z3_inv = m_curve.mul_to_tmp(z5_inv, z2, ws);

   m_coord_x = m_curve.mul_to_tmp(m_coord_x, z2_inv, ws);
   m_coord_y = m_curve.mul_to_tmp(m_coord_y, z3_inv, ws);
   m_coord_z = 1;
   m_curve.to_rep(m_coord_z, ws);
   }

bool PointGFp::is_affine() const
   {
   return m_curve.is_one(m_coord_z);
   }

BigInt PointGFp::get_affine_x() const
   {
   if(is_zero())
      throw Illegal_Transformation("Cannot convert zero point to affine");

   secure_vector<word> monty_ws;

   if(is_affine())
      return m_curve.from_rep(m_coord_x, monty_ws);

   const BigInt z2 = m_curve.sqr_to_tmp(m_coord_z, monty_ws);
   const BigInt z2_inv = m_curve.invert_element(z2, monty_ws);

   BigInt r;
   m_curve.mul(r, m_coord_x, z2_inv, monty_ws);
   m_curve.from_rep(r, monty_ws);
   return r;
   }

BigInt PointGFp::get_affine_y() const
   {
   if(is_zero())
      throw Illegal_Transformation("Cannot convert zero point to affine");

   secure_vector<word> monty_ws;

   if(is_affine())
      return m_curve.from_rep(m_coord_y, monty_ws);

   const BigInt z2 = m_curve.sqr_to_tmp(m_coord_z, monty_ws);
   const BigInt z3 = m_curve.mul_to_tmp(m_coord_z, z2, monty_ws);
   const BigInt z3_inv = m_curve.invert_element(z3, monty_ws);

   BigInt r;
   m_curve.mul(r, m_coord_y, z3_inv, monty_ws);
   m_curve.from_rep(r, monty_ws);
   return r;
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

   secure_vector<word> monty_ws;

   const BigInt y2 = m_curve.from_rep(m_curve.sqr_to_tmp(m_coord_y, monty_ws), monty_ws);
   const BigInt x3 = m_curve.mul_to_tmp(m_coord_x, m_curve.sqr_to_tmp(m_coord_x, monty_ws), monty_ws);
   const BigInt ax = m_curve.mul_to_tmp(m_coord_x, m_curve.get_a_rep(), monty_ws);
   const BigInt z2 = m_curve.sqr_to_tmp(m_coord_z, monty_ws);

   if(m_coord_z == z2) // Is z equal to 1 (in Montgomery form)?
      {
      if(y2 != m_curve.from_rep(x3 + ax + m_curve.get_b_rep(), monty_ws))
         return false;
      }

   const BigInt z3 = m_curve.mul_to_tmp(m_coord_z, z2, monty_ws);
   const BigInt ax_z4 = m_curve.mul_to_tmp(ax, m_curve.sqr_to_tmp(z2, monty_ws), monty_ws);
   const BigInt b_z6 = m_curve.mul_to_tmp(m_curve.get_b_rep(), m_curve.sqr_to_tmp(z3, monty_ws), monty_ws);

   if(y2 != m_curve.from_rep(x3 + ax_z4 + b_z6, monty_ws))
      return false;

   return true;
   }

// swaps the states of *this and other, does not throw!
void PointGFp::swap(PointGFp& other)
   {
   m_curve.swap(other.m_curve);
   m_coord_x.swap(other.m_coord_x);
   m_coord_y.swap(other.m_coord_y);
   m_coord_z.swap(other.m_coord_z);
   }

bool PointGFp::operator==(const PointGFp& other) const
   {
   if(m_curve != other.m_curve)
      return false;

   // If this is zero, only equal if other is also zero
   if(is_zero())
      return other.is_zero();

   return (get_affine_x() == other.get_affine_x() &&
           get_affine_y() == other.get_affine_y());
   }

// encoding and decoding
secure_vector<uint8_t> EC2OSP(const PointGFp& point, uint8_t format)
   {
   if(point.is_zero())
      return secure_vector<uint8_t>(1); // single 0 byte

   const size_t p_bytes = point.get_curve().get_p().bytes();

   BigInt x = point.get_affine_x();
   BigInt y = point.get_affine_y();

   secure_vector<uint8_t> bX = BigInt::encode_1363(x, p_bytes);
   secure_vector<uint8_t> bY = BigInt::encode_1363(y, p_bytes);

   if(format == PointGFp::UNCOMPRESSED)
      {
      secure_vector<uint8_t> result;
      result.push_back(0x04);

      result += bX;
      result += bY;

      return result;
      }
   else if(format == PointGFp::COMPRESSED)
      {
      secure_vector<uint8_t> result;
      result.push_back(0x02 | static_cast<uint8_t>(y.get_bit(0)));

      result += bX;

      return result;
      }
   else if(format == PointGFp::HYBRID)
      {
      secure_vector<uint8_t> result;
      result.push_back(0x06 | static_cast<uint8_t>(y.get_bit(0)));

      result += bX;
      result += bY;

      return result;
      }
   else
      throw Invalid_Argument("EC2OSP illegal point encoding");
   }

namespace {

BigInt decompress_point(bool yMod2,
                        const BigInt& x,
                        const BigInt& curve_p,
                        const BigInt& curve_a,
                        const BigInt& curve_b)
   {
   BigInt xpow3 = x * x * x;

   BigInt g = curve_a * x;
   g += xpow3;
   g += curve_b;
   g = g % curve_p;

   BigInt z = ressol(g, curve_p);

   if(z < 0)
      throw Illegal_Point("error during EC point decompression");

   if(z.get_bit(0) != yMod2)
      z = curve_p - z;

   return z;
   }

}

PointGFp OS2ECP(const uint8_t data[], size_t data_len,
                const CurveGFp& curve)
   {
   // Should we really be doing this?
   if(data_len <= 1)
      return PointGFp(curve); // return zero

   std::pair<BigInt, BigInt> xy = OS2ECP(data, data_len, curve.get_p(), curve.get_a(), curve.get_b());

   PointGFp point(curve, xy.first, xy.second);

   if(!point.on_the_curve())
      throw Illegal_Point("OS2ECP: Decoded point was not on the curve");

   return point;
   }

std::pair<BigInt, BigInt> OS2ECP(const uint8_t data[], size_t data_len,
                                 const BigInt& curve_p,
                                 const BigInt& curve_a,
                                 const BigInt& curve_b)
   {
   if(data_len <= 1)
      throw Decoding_Error("OS2ECP invalid point");

   const uint8_t pc = data[0];

   BigInt x, y;

   if(pc == 2 || pc == 3)
      {
      //compressed form
      x = BigInt::decode(&data[1], data_len - 1);

      const bool y_mod_2 = ((pc & 0x01) == 1);
      y = decompress_point(y_mod_2, x, curve_p, curve_a, curve_b);
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

      if(decompress_point(y_mod_2, x, curve_p, curve_a, curve_b) != y)
         throw Illegal_Point("OS2ECP: Decoding error in hybrid format");
      }
   else
      throw Invalid_Argument("OS2ECP: Unknown format type " + std::to_string(pc));

   return std::make_pair(x, y);
   }

}
