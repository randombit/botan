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
      const BigInt mask2 = m_curve.mul(mask, mask, monty_ws);
      const BigInt mask3 = m_curve.mul(mask2, mask, monty_ws);

      m_coord_x = m_curve.mul(m_coord_x, mask2, monty_ws);
      m_coord_y = m_curve.mul(m_coord_y, mask3, monty_ws);
      m_coord_z = m_curve.mul(m_coord_z, mask, monty_ws);
      }
   }

// Point addition
void PointGFp::add(const PointGFp& rhs, std::vector<BigInt>& ws_bn)
   {
   if(is_zero())
      {
      m_coord_x = rhs.m_coord_x;
      m_coord_y = rhs.m_coord_y;
      m_coord_z = rhs.m_coord_z;
      return;
      }
   else if(rhs.is_zero())
      return;

   const BigInt& p = m_curve.get_p();

   BigInt& rhs_z2 = ws_bn[0];
   BigInt& U1 = ws_bn[1];
   BigInt& S1 = ws_bn[2];

   BigInt& lhs_z2 = ws_bn[3];
   BigInt& U2 = ws_bn[4];
   BigInt& S2 = ws_bn[5];

   BigInt& H = ws_bn[6];
   BigInt& r = ws_bn[7];

   secure_vector<word>& monty_ws = ws_bn[8].get_word_vector();

   /*
   https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-1998-cmo-2
   */

   m_curve.sqr(rhs_z2, rhs.m_coord_z, monty_ws);
   m_curve.mul(U1, m_coord_x, rhs_z2, monty_ws);
   m_curve.mul(S1, m_coord_y,
               m_curve.mul(rhs.m_coord_z, rhs_z2, monty_ws),
               monty_ws);

   m_curve.sqr(lhs_z2, m_coord_z, monty_ws);
   m_curve.mul(U2, rhs.m_coord_x, lhs_z2, monty_ws);
   m_curve.mul(S2, rhs.m_coord_y,
               m_curve.mul(m_coord_z, lhs_z2, monty_ws),
               monty_ws);

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

      // setting to zero:
      m_coord_x = 0;
      m_coord_y = 1;
      m_coord_z = 0;
      return;
      }

   m_curve.sqr(U2, H, monty_ws);

   m_curve.mul(S2, U2, H, monty_ws);

   U2 = m_curve.mul(U1, U2, monty_ws);

   m_curve.sqr(m_coord_x, r, monty_ws);
   m_coord_x -= S2;
   m_coord_x -= (U2 << 1);
   while(m_coord_x.is_negative())
      m_coord_x += p;

   U2 -= m_coord_x;
   if(U2.is_negative())
      U2 += p;

   m_curve.mul(m_coord_y, r, U2, monty_ws);
   m_coord_y -= m_curve.mul(S1, S2, monty_ws);
   if(m_coord_y.is_negative())
      m_coord_y += p;

   m_curve.mul(m_coord_z,
               m_curve.mul(m_coord_z, rhs.m_coord_z, monty_ws),
               H, monty_ws);
   }

// *this *= 2
void PointGFp::mult2(std::vector<BigInt>& ws_bn)
   {
   if(is_zero())
      return;
   else if(m_coord_y.is_zero())
      {
      *this = PointGFp(m_curve); // setting myself to zero
      return;
      }

   /*
   https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-1986-cc
   */

   const BigInt& p = m_curve.get_p();

   BigInt& y_2 = ws_bn[0];
   BigInt& S = ws_bn[1];
   BigInt& z4 = ws_bn[2];
   BigInt& a_z4 = ws_bn[3];
   BigInt& M = ws_bn[4];
   BigInt& U = ws_bn[5];
   BigInt& x = ws_bn[6];
   BigInt& y = ws_bn[7];
   BigInt& z = ws_bn[8];

   secure_vector<word>& monty_ws = ws_bn[9].get_word_vector();

   m_curve.sqr(y_2, m_coord_y, monty_ws);

   m_curve.mul(S, m_coord_x, y_2, monty_ws);
   S <<= 2; // * 4
   while(S >= p)
      S -= p;

   m_curve.sqr(z4, m_curve.sqr(m_coord_z, monty_ws), monty_ws);
   m_curve.mul(a_z4, m_curve.get_a_rep(), z4, monty_ws);

   M = m_curve.sqr(m_coord_x, monty_ws);
   M *= 3;
   M += a_z4;
   while(M >= p)
      M -= p;

   m_curve.sqr(x, M, monty_ws);
   x -= (S << 1);
   while(x.is_negative())
      x += p;

   m_curve.sqr(U, y_2, monty_ws);
   U <<= 3;
   while(U >= p)
      U -= p;

   S -= x;
   while(S.is_negative())
      S += p;

   m_curve.mul(y, M, S, monty_ws);
   y -= U;
   if(y.is_negative())
      y += p;

   m_curve.mul(z, m_coord_y, m_coord_z, monty_ws);
   z <<= 1;
   if(z >= p)
      z -= p;

   m_coord_x = x;
   m_coord_y = y;
   m_coord_z = z;
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

PointGFp multi_exponentiate(const PointGFp& p1, const BigInt& z1,
                            const PointGFp& p2, const BigInt& z2)
   {
   const PointGFp p3 = p1 + p2;

   PointGFp H = p1.zero();
   size_t bits_left = std::max(z1.bits(), z2.bits());

   std::vector<BigInt> ws(PointGFp::WORKSPACE_SIZE);

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

BigInt PointGFp::get_affine_x() const
   {
   if(is_zero())
      throw Illegal_Transformation("Cannot convert zero point to affine");

   secure_vector<word> monty_ws;
   BigInt z2 = m_curve.sqr(m_coord_z, monty_ws);
   m_curve.from_rep(z2, monty_ws);
   z2 = inverse_mod(z2, m_curve.get_p());

   return m_curve.mul(z2, m_coord_x, monty_ws);
   }

BigInt PointGFp::get_affine_y() const
   {
   if(is_zero())
      throw Illegal_Transformation("Cannot convert zero point to affine");

   secure_vector<word> monty_ws;
   BigInt z3 = m_curve.mul(m_coord_z, m_curve.sqr(m_coord_z, monty_ws), monty_ws);
   z3 = inverse_mod(z3, m_curve.get_p());
   m_curve.to_rep(z3, monty_ws);

   return m_curve.mul(z3, m_coord_y, monty_ws);
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

   const BigInt y2 = m_curve.from_rep(m_curve.sqr(m_coord_y, monty_ws), monty_ws);
   const BigInt x3 = m_curve.mul(m_coord_x, m_curve.sqr(m_coord_x, monty_ws), monty_ws);
   const BigInt ax = m_curve.mul(m_coord_x, m_curve.get_a_rep(), monty_ws);
   const BigInt z2 = m_curve.sqr(m_coord_z, monty_ws);

   if(m_coord_z == z2) // Is z equal to 1 (in Montgomery form)?
      {
      if(y2 != m_curve.from_rep(x3 + ax + m_curve.get_b_rep(), monty_ws))
         return false;
      }

   const BigInt z3 = m_curve.mul(m_coord_z, z2, monty_ws);
   const BigInt ax_z4 = m_curve.mul(ax, m_curve.sqr(z2, monty_ws), monty_ws);
   const BigInt b_z6 = m_curve.mul(m_curve.get_b_rep(), m_curve.sqr(z3, monty_ws), monty_ws);

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
