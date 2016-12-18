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
#include <botan/loadstor.h>
#include <botan/internal/rounding.h>

namespace Botan {


PointGFp::PointGFp(const CurveGFp& curve) :
   m_curve(curve),
   m_coord_x(0),
   m_coord_y(1),
   m_coord_z(0)
   {
   m_curve.to_rep(m_coord_x, m_monty_ws);
   m_curve.to_rep(m_coord_y, m_monty_ws);
   m_curve.to_rep(m_coord_z, m_monty_ws);
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

   m_curve.to_rep(m_coord_x, m_monty_ws);
   m_curve.to_rep(m_coord_y, m_monty_ws);
   m_curve.to_rep(m_coord_z, m_monty_ws);
   }

void PointGFp::randomize_repr(RandomNumberGenerator& rng)
   {
   if(BOTAN_POINTGFP_RANDOMIZE_BLINDING_BITS > 1)
      {
      BigInt mask;
      while(mask.is_zero())
         mask.randomize(rng, BOTAN_POINTGFP_RANDOMIZE_BLINDING_BITS, false);

      m_curve.to_rep(mask, m_monty_ws);
      const BigInt mask2 = curve_mult(mask, mask);
      const BigInt mask3 = curve_mult(mask2, mask);

      m_coord_x = curve_mult(m_coord_x, mask2);
      m_coord_y = curve_mult(m_coord_y, mask3);
      m_coord_z = curve_mult(m_coord_z, mask);
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

   /*
   http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-1998-cmo-2
   */

   curve_sqr(rhs_z2, rhs.m_coord_z);
   curve_mult(U1, m_coord_x, rhs_z2);
   curve_mult(S1, m_coord_y, curve_mult(rhs.m_coord_z, rhs_z2));

   curve_sqr(lhs_z2, m_coord_z);
   curve_mult(U2, rhs.m_coord_x, lhs_z2);
   curve_mult(S2, rhs.m_coord_y, curve_mult(m_coord_z, lhs_z2));

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

   curve_sqr(U2, H);

   curve_mult(S2, U2, H);

   U2 = curve_mult(U1, U2);

   curve_sqr(m_coord_x, r);
   m_coord_x -= S2;
   m_coord_x -= (U2 << 1);
   while(m_coord_x.is_negative())
      m_coord_x += p;

   U2 -= m_coord_x;
   if(U2.is_negative())
      U2 += p;

   curve_mult(m_coord_y, r, U2);
   m_coord_y -= curve_mult(S1, S2);
   if(m_coord_y.is_negative())
      m_coord_y += p;

   curve_mult(m_coord_z, curve_mult(m_coord_z, rhs.m_coord_z), H);
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
   http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-1986-cc
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

   curve_sqr(y_2, m_coord_y);

   curve_mult(S, m_coord_x, y_2);
   S <<= 2; // * 4
   while(S >= p)
      S -= p;

   curve_sqr(z4, curve_sqr(m_coord_z));
   curve_mult(a_z4, m_curve.get_a_rep(), z4);

   M = curve_sqr(m_coord_x);
   M *= 3;
   M += a_z4;
   while(M >= p)
      M -= p;

   curve_sqr(x, M);
   x -= (S << 1);
   while(x.is_negative())
      x += p;

   curve_sqr(U, y_2);
   U <<= 3;
   while(U >= p)
      U -= p;

   S -= x;
   while(S.is_negative())
      S += p;

   curve_mult(y, M, S);
   y -= U;
   if(y.is_negative())
      y += p;

   curve_mult(z, m_coord_y, m_coord_z);
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

   PointGFp H(p1.get_curve()); // create as zero
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
   //BOTAN_ASSERT(point.on_the_curve(), "Input is on the curve");

   const CurveGFp& curve = point.get_curve();

   const size_t scalar_bits = scalar.bits();

   std::vector<BigInt> ws(9);

   PointGFp R[2] = { PointGFp(curve), point };

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

Blinded_Point_Multiply::Blinded_Point_Multiply(const PointGFp& base, const BigInt& order, size_t h) :
   m_h(h > 0 ? h : 4), m_order(order), m_ws(9)
   {
   // Upper bound is a sanity check rather than hard limit
   if(m_h < 1 || m_h > 8)
      throw Invalid_Argument("Blinded_Point_Multiply invalid h param");

   const CurveGFp& curve = base.get_curve();

#if BOTAN_POINTGFP_BLINDED_MULTIPLY_USE_MONTGOMERY_LADDER

   const PointGFp inv = -base;

   m_U.resize(6*m_h + 3);

   m_U[3*m_h+0] = inv;
   m_U[3*m_h+1] = PointGFp::zero_of(curve);
   m_U[3*m_h+2] = base;

   for(size_t i = 1; i <= 3 * m_h + 1; ++i)
      {
      m_U[3*m_h+1+i] = m_U[3*m_h+i];
      m_U[3*m_h+1+i].add(base, m_ws);

      m_U[3*m_h+1-i] = m_U[3*m_h+2-i];
      m_U[3*m_h+1-i].add(inv, m_ws);
      }
#else
   m_U.resize(1 << m_h);
   m_U[0] = PointGFp::zero_of(curve);
   m_U[1] = base;

   for(size_t i = 2; i < m_U.size(); ++i)
      {
      m_U[i] = m_U[i-1];
      m_U[i].add(base, m_ws);
      }
#endif
   }

PointGFp Blinded_Point_Multiply::blinded_multiply(const BigInt& scalar_in,
                                                  RandomNumberGenerator& rng)
   {
   if(scalar_in.is_negative())
      throw Invalid_Argument("Blinded_Point_Multiply scalar must be positive");

#if BOTAN_POINTGFP_SCALAR_BLINDING_BITS > 0
   // Choose a small mask m and use k' = k + m*order (Coron's 1st countermeasure)
   const BigInt mask(rng, BOTAN_POINTGFP_SCALAR_BLINDING_BITS, false);
   const BigInt scalar = scalar_in + m_order * mask;
#else
   const BigInt& scalar = scalar_in;
#endif

   const size_t scalar_bits = scalar.bits();

   // Randomize each point representation (Coron's 3rd countermeasure)
   for(size_t i = 0; i != m_U.size(); ++i)
      m_U[i].randomize_repr(rng);

#if BOTAN_POINTGFP_BLINDED_MULTIPLY_USE_MONTGOMERY_LADDER
   PointGFp R = m_U.at(3*m_h + 2); // base point
   int32_t alpha = 0;

   R.randomize_repr(rng);

   /*
   Algorithm 7 from "Randomizing the Montgomery Powering Ladder"
   Duc-Phong Le, Chik How Tan and Michael Tunstall
   http://eprint.iacr.org/2015/657

   It takes a random walk through (a subset of) the set of addition
   chains that end in k.
   */
   for(size_t i = scalar_bits; i > 0; i--)
      {
      const int32_t ki = scalar.get_bit(i);

      // choose gamma from -h,...,h
      const int32_t gamma = static_cast<int32_t>((rng.next_byte() % (2*m_h))) - m_h;
      const int32_t l = gamma - 2*alpha + ki - (ki ^ 1);

      R.mult2(m_ws);
      R.add(m_U.at(3*m_h + 1 + l), m_ws);
      alpha = gamma;
      }

   const int32_t k0 = scalar.get_bit(0);
   R.add(m_U[3*m_h + 1 - alpha - (k0 ^ 1)], m_ws);

#else

   // N-bit windowing exponentiation:

   size_t windows = round_up(scalar_bits, m_h) / m_h;

   PointGFp R = m_U[0];

   if(windows > 0)
      {
      windows--;
      const uint32_t nibble = scalar.get_substring(windows*m_h, m_h);
      R.add(m_U[nibble], m_ws);

      /*
      Randomize after adding the first nibble as before the addition R
      is zero, and we cannot effectively randomize the point
      representation of the zero point.
      */
      R.randomize_repr(rng);

      while(windows)
         {
         for(size_t i = 0; i != m_h; ++i)
            R.mult2(m_ws);

         const uint32_t inner_nibble = scalar.get_substring((windows-1)*m_h, m_h);
         R.add(m_U[inner_nibble], m_ws);
         windows--;
         }
      }
#endif

   //BOTAN_ASSERT(R.on_the_curve(), "Output is on the curve");

   return R;
   }

BigInt PointGFp::get_affine_x() const
   {
   if(is_zero())
      throw Illegal_Transformation("Cannot convert zero point to affine");

   BigInt z2 = curve_sqr(m_coord_z);
   m_curve.from_rep(z2, m_monty_ws);
   z2 = inverse_mod(z2, m_curve.get_p());

   return curve_mult(z2, m_coord_x);
   }

BigInt PointGFp::get_affine_y() const
   {
   if(is_zero())
      throw Illegal_Transformation("Cannot convert zero point to affine");

   BigInt z3 = curve_mult(m_coord_z, curve_sqr(m_coord_z));
   z3 = inverse_mod(z3, m_curve.get_p());
   m_curve.to_rep(z3, m_monty_ws);

   return curve_mult(z3, m_coord_y);
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

   const BigInt y2 = m_curve.from_rep(curve_sqr(m_coord_y), m_monty_ws);
   const BigInt x3 = curve_mult(m_coord_x, curve_sqr(m_coord_x));
   const BigInt ax = curve_mult(m_coord_x, m_curve.get_a_rep());
   const BigInt z2 = curve_sqr(m_coord_z);

   if(m_coord_z == z2) // Is z equal to 1 (in Montgomery form)?
      {
      if(y2 != m_curve.from_rep(x3 + ax + m_curve.get_b_rep(), m_monty_ws))
         return false;
      }

   const BigInt z3 = curve_mult(m_coord_z, z2);
   const BigInt ax_z4 = curve_mult(ax, curve_sqr(z2));
   const BigInt b_z6 = curve_mult(m_curve.get_b_rep(), curve_sqr(z3));

   if(y2 != m_curve.from_rep(x3 + ax_z4 + b_z6, m_monty_ws))
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
   m_monty_ws.swap(other.m_monty_ws);
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
                        const CurveGFp& curve)
   {
   BigInt xpow3 = x * x * x;

   const BigInt& p = curve.get_p();

   BigInt g = curve.get_a() * x;
   g += xpow3;
   g += curve.get_b();
   g = g % p;

   BigInt z = ressol(g, p);

   if(z < 0)
      throw Illegal_Point("error during EC point decompression");

   if(z.get_bit(0) != yMod2)
      z = p - z;

   return z;
   }

}

PointGFp OS2ECP(const uint8_t data[], size_t data_len,
                const CurveGFp& curve)
   {
   if(data_len <= 1)
      return PointGFp(curve); // return zero

   const uint8_t pc = data[0];

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
      throw Invalid_Argument("OS2ECP: Unknown format type " + std::to_string(pc));

   PointGFp result(curve, x, y);

   if(!result.on_the_curve())
      throw Illegal_Point("OS2ECP: Decoded point was not on the curve");

   return result;
   }

}
