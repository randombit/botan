/*
* Point arithmetic on elliptic curves over GF(p)
*
* (C) 2007 Martin Doering, Christoph Ludwig, Falko Strenzke
*     2008-2011,2012,2014,2015,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ec_point.h>

#include <botan/numthry.h>
#include <botan/rng.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/stl_util.h>

namespace Botan {

EC_Point::EC_Point(const CurveGFp& curve) : m_curve(curve), m_coord_x(0), m_coord_y(curve.get_1_rep()), m_coord_z(0) {
   // Assumes Montgomery rep of zero is zero
}

EC_Point::EC_Point(const CurveGFp& curve, const BigInt& x, const BigInt& y) :
      m_curve(curve), m_coord_x(x), m_coord_y(y), m_coord_z(m_curve.get_1_rep()) {
   if(x < 0 || x >= curve.get_p()) {
      throw Invalid_Argument("Invalid EC_Point affine x");
   }
   if(y < 0 || y >= curve.get_p()) {
      throw Invalid_Argument("Invalid EC_Point affine y");
   }

   secure_vector<word> monty_ws(m_curve.get_ws_size());
   m_curve.to_rep(m_coord_x, monty_ws);
   m_curve.to_rep(m_coord_y, monty_ws);
}

void EC_Point::randomize_repr(RandomNumberGenerator& rng) {
   secure_vector<word> ws(m_curve.get_ws_size());
   randomize_repr(rng, ws);
}

void EC_Point::randomize_repr(RandomNumberGenerator& rng, secure_vector<word>& ws) {
   const BigInt mask = BigInt::random_integer(rng, 2, m_curve.get_p());

   /*
   * No reason to convert this to Montgomery representation first,
   * just pretend the random mask was chosen as Redc(mask) and the
   * random mask we generated above is in the Montgomery
   * representation.
   * //m_curve.to_rep(mask, ws);
   */
   const BigInt mask2 = m_curve.sqr_to_tmp(mask, ws);
   const BigInt mask3 = m_curve.mul_to_tmp(mask2, mask, ws);

   m_coord_x = m_curve.mul_to_tmp(m_coord_x, mask2, ws);
   m_coord_y = m_curve.mul_to_tmp(m_coord_y, mask3, ws);
   m_coord_z = m_curve.mul_to_tmp(m_coord_z, mask, ws);
}

namespace {

inline void resize_ws(std::vector<BigInt>& ws_bn, size_t cap_size) {
   BOTAN_ASSERT(ws_bn.size() >= EC_Point::WORKSPACE_SIZE, "Expected size for EC_Point workspace");

   for(auto& ws : ws_bn) {
      if(ws.size() < cap_size) {
         ws.get_word_vector().resize(cap_size);
      }
   }
}

}  // namespace

void EC_Point::add_affine(
   const word x_words[], size_t x_size, const word y_words[], size_t y_size, std::vector<BigInt>& ws_bn) {
   if((CT::all_zeros(x_words, x_size) & CT::all_zeros(y_words, y_size)).as_bool()) {
      return;
   }

   if(is_zero()) {
      m_coord_x.set_words(x_words, x_size);
      m_coord_y.set_words(y_words, y_size);
      m_coord_z = m_curve.get_1_rep();
      return;
   }

   resize_ws(ws_bn, m_curve.get_ws_size());

   secure_vector<word>& ws = ws_bn[0].get_word_vector();
   secure_vector<word>& sub_ws = ws_bn[1].get_word_vector();

   BigInt& T0 = ws_bn[2];
   BigInt& T1 = ws_bn[3];
   BigInt& T2 = ws_bn[4];
   BigInt& T3 = ws_bn[5];
   BigInt& T4 = ws_bn[6];

   /*
   https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-1998-cmo-2
   simplified with Z2 = 1
   */

   const BigInt& p = m_curve.get_p();

   m_curve.sqr(T3, m_coord_z, ws);            // z1^2
   m_curve.mul(T4, x_words, x_size, T3, ws);  // x2*z1^2

   m_curve.mul(T2, m_coord_z, T3, ws);        // z1^3
   m_curve.mul(T0, y_words, y_size, T2, ws);  // y2*z1^3

   T4.mod_sub(m_coord_x, p, sub_ws);  // x2*z1^2 - x1*z2^2

   T0.mod_sub(m_coord_y, p, sub_ws);

   if(T4.is_zero()) {
      if(T0.is_zero()) {
         mult2(ws_bn);
         return;
      }

      // setting to zero:
      m_coord_x.clear();
      m_coord_y = m_curve.get_1_rep();
      m_coord_z.clear();
      return;
   }

   m_curve.sqr(T2, T4, ws);

   m_curve.mul(T3, m_coord_x, T2, ws);

   m_curve.mul(T1, T2, T4, ws);

   m_curve.sqr(m_coord_x, T0, ws);
   m_coord_x.mod_sub(T1, p, sub_ws);

   m_coord_x.mod_sub(T3, p, sub_ws);
   m_coord_x.mod_sub(T3, p, sub_ws);

   T3.mod_sub(m_coord_x, p, sub_ws);

   m_curve.mul(T2, T0, T3, ws);
   m_curve.mul(T0, m_coord_y, T1, ws);
   T2.mod_sub(T0, p, sub_ws);
   m_coord_y.swap(T2);

   m_curve.mul(T0, m_coord_z, T4, ws);
   m_coord_z.swap(T0);
}

void EC_Point::add(const word x_words[],
                   size_t x_size,
                   const word y_words[],
                   size_t y_size,
                   const word z_words[],
                   size_t z_size,
                   std::vector<BigInt>& ws_bn) {
   if((CT::all_zeros(x_words, x_size) & CT::all_zeros(z_words, z_size)).as_bool()) {
      return;
   }

   if(is_zero()) {
      m_coord_x.set_words(x_words, x_size);
      m_coord_y.set_words(y_words, y_size);
      m_coord_z.set_words(z_words, z_size);
      return;
   }

   resize_ws(ws_bn, m_curve.get_ws_size());

   secure_vector<word>& ws = ws_bn[0].get_word_vector();
   secure_vector<word>& sub_ws = ws_bn[1].get_word_vector();

   BigInt& T0 = ws_bn[2];
   BigInt& T1 = ws_bn[3];
   BigInt& T2 = ws_bn[4];
   BigInt& T3 = ws_bn[5];
   BigInt& T4 = ws_bn[6];
   BigInt& T5 = ws_bn[7];

   /*
   https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-1998-cmo-2
   */

   const BigInt& p = m_curve.get_p();

   m_curve.sqr(T0, z_words, z_size, ws);      // z2^2
   m_curve.mul(T1, m_coord_x, T0, ws);        // x1*z2^2
   m_curve.mul(T3, z_words, z_size, T0, ws);  // z2^3
   m_curve.mul(T2, m_coord_y, T3, ws);        // y1*z2^3

   m_curve.sqr(T3, m_coord_z, ws);            // z1^2
   m_curve.mul(T4, x_words, x_size, T3, ws);  // x2*z1^2

   m_curve.mul(T5, m_coord_z, T3, ws);        // z1^3
   m_curve.mul(T0, y_words, y_size, T5, ws);  // y2*z1^3

   T4.mod_sub(T1, p, sub_ws);  // x2*z1^2 - x1*z2^2

   T0.mod_sub(T2, p, sub_ws);

   if(T4.is_zero()) {
      if(T0.is_zero()) {
         mult2(ws_bn);
         return;
      }

      // setting to zero:
      m_coord_x.clear();
      m_coord_y = m_curve.get_1_rep();
      m_coord_z.clear();
      return;
   }

   m_curve.sqr(T5, T4, ws);

   m_curve.mul(T3, T1, T5, ws);

   m_curve.mul(T1, T5, T4, ws);

   m_curve.sqr(m_coord_x, T0, ws);
   m_coord_x.mod_sub(T1, p, sub_ws);
   m_coord_x.mod_sub(T3, p, sub_ws);
   m_coord_x.mod_sub(T3, p, sub_ws);

   T3.mod_sub(m_coord_x, p, sub_ws);

   m_curve.mul(m_coord_y, T0, T3, ws);
   m_curve.mul(T3, T2, T1, ws);

   m_coord_y.mod_sub(T3, p, sub_ws);

   m_curve.mul(T3, z_words, z_size, m_coord_z, ws);
   m_curve.mul(m_coord_z, T3, T4, ws);
}

void EC_Point::mult2i(size_t iterations, std::vector<BigInt>& ws_bn) {
   if(iterations == 0) {
      return;
   }

   if(m_coord_y.is_zero()) {
      *this = EC_Point(m_curve);  // setting myself to zero
      return;
   }

   /*
   TODO we can save 2 squarings per iteration by computing
   a*Z^4 using values cached from previous iteration
   */
   for(size_t i = 0; i != iterations; ++i) {
      mult2(ws_bn);
   }
}

// *this *= 2
void EC_Point::mult2(std::vector<BigInt>& ws_bn) {
   if(is_zero()) {
      return;
   }

   if(m_coord_y.is_zero()) {
      *this = EC_Point(m_curve);  // setting myself to zero
      return;
   }

   resize_ws(ws_bn, m_curve.get_ws_size());

   secure_vector<word>& ws = ws_bn[0].get_word_vector();
   secure_vector<word>& sub_ws = ws_bn[1].get_word_vector();

   BigInt& T0 = ws_bn[2];
   BigInt& T1 = ws_bn[3];
   BigInt& T2 = ws_bn[4];
   BigInt& T3 = ws_bn[5];
   BigInt& T4 = ws_bn[6];

   /*
   https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-1986-cc
   */
   const BigInt& p = m_curve.get_p();

   m_curve.sqr(T0, m_coord_y, ws);

   m_curve.mul(T1, m_coord_x, T0, ws);
   T1.mod_mul(4, p, sub_ws);

   if(m_curve.a_is_zero()) {
      // if a == 0 then 3*x^2 + a*z^4 is just 3*x^2
      m_curve.sqr(T4, m_coord_x, ws);  // x^2
      T4.mod_mul(3, p, sub_ws);        // 3*x^2
   } else if(m_curve.a_is_minus_3()) {
      /*
      if a == -3 then
        3*x^2 + a*z^4 == 3*x^2 - 3*z^4 == 3*(x^2-z^4) == 3*(x-z^2)*(x+z^2)
      */
      m_curve.sqr(T3, m_coord_z, ws);  // z^2

      // (x-z^2)
      T2 = m_coord_x;
      T2.mod_sub(T3, p, sub_ws);

      // (x+z^2)
      T3.mod_add(m_coord_x, p, sub_ws);

      m_curve.mul(T4, T2, T3, ws);  // (x-z^2)*(x+z^2)

      T4.mod_mul(3, p, sub_ws);  // 3*(x-z^2)*(x+z^2)
   } else {
      m_curve.sqr(T3, m_coord_z, ws);                // z^2
      m_curve.sqr(T4, T3, ws);                       // z^4
      m_curve.mul(T3, m_curve.get_a_rep(), T4, ws);  // a*z^4

      m_curve.sqr(T4, m_coord_x, ws);  // x^2
      T4.mod_mul(3, p, sub_ws);
      T4.mod_add(T3, p, sub_ws);  // 3*x^2 + a*z^4
   }

   m_curve.sqr(T2, T4, ws);
   T2.mod_sub(T1, p, sub_ws);
   T2.mod_sub(T1, p, sub_ws);

   m_curve.sqr(T3, T0, ws);
   T3.mod_mul(8, p, sub_ws);

   T1.mod_sub(T2, p, sub_ws);

   m_curve.mul(T0, T4, T1, ws);
   T0.mod_sub(T3, p, sub_ws);

   m_coord_x.swap(T2);

   m_curve.mul(T2, m_coord_y, m_coord_z, ws);
   T2.mod_mul(2, p, sub_ws);

   m_coord_y.swap(T0);
   m_coord_z.swap(T2);
}

// arithmetic operators
EC_Point& EC_Point::operator+=(const EC_Point& rhs) {
   std::vector<BigInt> ws(EC_Point::WORKSPACE_SIZE);
   add(rhs, ws);
   return *this;
}

EC_Point& EC_Point::operator-=(const EC_Point& rhs) {
   EC_Point minus_rhs = EC_Point(rhs).negate();

   if(is_zero()) {
      *this = minus_rhs;
   } else {
      *this += minus_rhs;
   }

   return *this;
}

EC_Point& EC_Point::operator*=(const BigInt& scalar) {
   *this = scalar * *this;
   return *this;
}

EC_Point EC_Point::mul(const BigInt& scalar) const {
   const size_t scalar_bits = scalar.bits();

   std::vector<BigInt> ws(EC_Point::WORKSPACE_SIZE);

   EC_Point R[2] = {this->zero(), *this};

   for(size_t i = scalar_bits; i > 0; i--) {
      const size_t b = scalar.get_bit(i - 1);
      R[b ^ 1].add(R[b], ws);
      R[b].mult2(ws);
   }

   if(scalar.is_negative()) {
      R[0].negate();
   }

   BOTAN_DEBUG_ASSERT(R[0].on_the_curve());

   return R[0];
}

//static
void EC_Point::force_all_affine(std::span<EC_Point> points, secure_vector<word>& ws) {
   if(points.size() <= 1) {
      for(auto& point : points) {
         point.force_affine();
      }
      return;
   }

   for(auto& point : points) {
      if(point.is_zero()) {
         throw Invalid_State("Cannot convert zero ECC point to affine");
      }
   }

   /*
   For >= 2 points use Montgomery's trick

   See Algorithm 2.26 in "Guide to Elliptic Curve Cryptography"
   (Hankerson, Menezes, Vanstone)

   TODO is it really necessary to save all k points in c?
   */

   const CurveGFp& curve = points[0].m_curve;
   const BigInt& rep_1 = curve.get_1_rep();

   if(ws.size() < curve.get_ws_size()) {
      ws.resize(curve.get_ws_size());
   }

   std::vector<BigInt> c(points.size());
   c[0] = points[0].m_coord_z;

   for(size_t i = 1; i != points.size(); ++i) {
      curve.mul(c[i], c[i - 1], points[i].m_coord_z, ws);
   }

   BigInt s_inv = curve.invert_element(c[c.size() - 1], ws);

   BigInt z_inv, z2_inv, z3_inv;

   for(size_t i = points.size() - 1; i != 0; i--) {
      EC_Point& point = points[i];

      curve.mul(z_inv, s_inv, c[i - 1], ws);

      s_inv = curve.mul_to_tmp(s_inv, point.m_coord_z, ws);

      curve.sqr(z2_inv, z_inv, ws);
      curve.mul(z3_inv, z2_inv, z_inv, ws);
      point.m_coord_x = curve.mul_to_tmp(point.m_coord_x, z2_inv, ws);
      point.m_coord_y = curve.mul_to_tmp(point.m_coord_y, z3_inv, ws);
      point.m_coord_z = rep_1;
   }

   curve.sqr(z2_inv, s_inv, ws);
   curve.mul(z3_inv, z2_inv, s_inv, ws);
   points[0].m_coord_x = curve.mul_to_tmp(points[0].m_coord_x, z2_inv, ws);
   points[0].m_coord_y = curve.mul_to_tmp(points[0].m_coord_y, z3_inv, ws);
   points[0].m_coord_z = rep_1;
}

void EC_Point::force_affine() {
   if(is_zero()) {
      throw Invalid_State("Cannot convert zero ECC point to affine");
   }

   secure_vector<word> ws;

   const BigInt z_inv = m_curve.invert_element(m_coord_z, ws);
   const BigInt z2_inv = m_curve.sqr_to_tmp(z_inv, ws);
   const BigInt z3_inv = m_curve.mul_to_tmp(z_inv, z2_inv, ws);
   m_coord_x = m_curve.mul_to_tmp(m_coord_x, z2_inv, ws);
   m_coord_y = m_curve.mul_to_tmp(m_coord_y, z3_inv, ws);
   m_coord_z = m_curve.get_1_rep();
}

bool EC_Point::is_affine() const {
   return m_curve.is_one(m_coord_z);
}

secure_vector<uint8_t> EC_Point::x_bytes() const {
   const size_t p_bytes = m_curve.get_p_bytes();
   secure_vector<uint8_t> b(p_bytes);
   BigInt::encode_1363(b.data(), b.size(), this->get_affine_x());
   return b;
}

secure_vector<uint8_t> EC_Point::y_bytes() const {
   const size_t p_bytes = m_curve.get_p_bytes();
   secure_vector<uint8_t> b(p_bytes);
   BigInt::encode_1363(b.data(), b.size(), this->get_affine_y());
   return b;
}

secure_vector<uint8_t> EC_Point::xy_bytes() const {
   const size_t p_bytes = m_curve.get_p_bytes();
   secure_vector<uint8_t> b(2 * p_bytes);
   BigInt::encode_1363(&b[0], p_bytes, this->get_affine_x());
   BigInt::encode_1363(&b[p_bytes], p_bytes, this->get_affine_y());
   return b;
}

BigInt EC_Point::get_affine_x() const {
   if(is_zero()) {
      throw Invalid_State("Cannot convert zero point to affine");
   }

   secure_vector<word> monty_ws;

   if(is_affine()) {
      return m_curve.from_rep_to_tmp(m_coord_x, monty_ws);
   }

   BigInt z2 = m_curve.sqr_to_tmp(m_coord_z, monty_ws);
   z2 = m_curve.invert_element(z2, monty_ws);

   BigInt r;
   m_curve.mul(r, m_coord_x, z2, monty_ws);
   m_curve.from_rep(r, monty_ws);
   return r;
}

BigInt EC_Point::get_affine_y() const {
   if(is_zero()) {
      throw Invalid_State("Cannot convert zero point to affine");
   }

   secure_vector<word> monty_ws;

   if(is_affine()) {
      return m_curve.from_rep_to_tmp(m_coord_y, monty_ws);
   }

   const BigInt z2 = m_curve.sqr_to_tmp(m_coord_z, monty_ws);
   const BigInt z3 = m_curve.mul_to_tmp(m_coord_z, z2, monty_ws);
   const BigInt z3_inv = m_curve.invert_element(z3, monty_ws);

   BigInt r;
   m_curve.mul(r, m_coord_y, z3_inv, monty_ws);
   m_curve.from_rep(r, monty_ws);
   return r;
}

bool EC_Point::on_the_curve() const {
   /*
   Is the point still on the curve?? (If everything is correct, the
   point is always on its curve; then the function will return true.
   If somehow the state is corrupted, which suggests a fault attack
   (or internal computational error), then return false.
   */
   if(is_zero()) {
      return true;
   }

   secure_vector<word> monty_ws;

   const BigInt y2 = m_curve.from_rep_to_tmp(m_curve.sqr_to_tmp(m_coord_y, monty_ws), monty_ws);
   const BigInt x3 = m_curve.mul_to_tmp(m_coord_x, m_curve.sqr_to_tmp(m_coord_x, monty_ws), monty_ws);
   const BigInt ax = m_curve.mul_to_tmp(m_coord_x, m_curve.get_a_rep(), monty_ws);
   const BigInt z2 = m_curve.sqr_to_tmp(m_coord_z, monty_ws);

   if(m_coord_z == z2)  // Is z equal to 1 (in Montgomery form)?
   {
      if(y2 != m_curve.from_rep_to_tmp(x3 + ax + m_curve.get_b_rep(), monty_ws)) {
         return false;
      }
   }

   const BigInt z3 = m_curve.mul_to_tmp(m_coord_z, z2, monty_ws);
   const BigInt ax_z4 = m_curve.mul_to_tmp(ax, m_curve.sqr_to_tmp(z2, monty_ws), monty_ws);
   const BigInt b_z6 = m_curve.mul_to_tmp(m_curve.get_b_rep(), m_curve.sqr_to_tmp(z3, monty_ws), monty_ws);

   if(y2 != m_curve.from_rep_to_tmp(x3 + ax_z4 + b_z6, monty_ws)) {
      return false;
   }

   return true;
}

// swaps the states of *this and other
void EC_Point::swap(EC_Point& other) noexcept {
   m_curve.swap(other.m_curve);
   m_coord_x.swap(other.m_coord_x);
   m_coord_y.swap(other.m_coord_y);
   m_coord_z.swap(other.m_coord_z);
}

bool EC_Point::operator==(const EC_Point& other) const {
   if(m_curve != other.m_curve) {
      return false;
   }

   // If this is zero, only equal if other is also zero
   if(is_zero()) {
      return other.is_zero();
   }

   return (get_affine_x() == other.get_affine_x() && get_affine_y() == other.get_affine_y());
}

// encoding and decoding
std::vector<uint8_t> EC_Point::encode(EC_Point_Format format) const {
   if(is_zero()) {
      return std::vector<uint8_t>(1);  // single 0 byte
   }

   const size_t p_bytes = m_curve.get_p().bytes();

   const BigInt x = get_affine_x();
   const BigInt y = get_affine_y();

   const size_t parts = (format == EC_Point_Format::Compressed) ? 1 : 2;

   std::vector<uint8_t> result(1 + parts * p_bytes);
   BufferStuffer stuffer(result);

   if(format == EC_Point_Format::Uncompressed) {
      stuffer.append(0x04);
      x.serialize_to(stuffer.next(p_bytes));
      y.serialize_to(stuffer.next(p_bytes));
   } else if(format == EC_Point_Format::Compressed) {
      stuffer.append(0x02 | static_cast<uint8_t>(y.get_bit(0)));
      x.serialize_to(stuffer.next(p_bytes));
   } else if(format == EC_Point_Format::Hybrid) {
      stuffer.append(0x06 | static_cast<uint8_t>(y.get_bit(0)));
      x.serialize_to(stuffer.next(p_bytes));
      y.serialize_to(stuffer.next(p_bytes));
   } else {
      throw Invalid_Argument("EC2OSP illegal point encoding");
   }

   return result;
}

namespace {

BigInt decompress_point(
   bool yMod2, const BigInt& x, const BigInt& curve_p, const BigInt& curve_a, const BigInt& curve_b) {
   BigInt xpow3 = x * x * x;

   BigInt g = curve_a * x;
   g += xpow3;
   g += curve_b;
   g = g % curve_p;

   BigInt z = sqrt_modulo_prime(g, curve_p);

   if(z < 0) {
      throw Decoding_Error("Error during EC point decompression");
   }

   if(z.get_bit(0) != yMod2) {
      z = curve_p - z;
   }

   return z;
}

}  // namespace

EC_Point OS2ECP(const uint8_t data[], size_t data_len, const CurveGFp& curve) {
   // Should we really be doing this?
   if(data_len <= 1) {
      return EC_Point(curve);  // return zero
   }

   std::pair<BigInt, BigInt> xy = OS2ECP(data, data_len, curve.get_p(), curve.get_a(), curve.get_b());

   EC_Point point(curve, xy.first, xy.second);

   if(!point.on_the_curve()) {
      throw Decoding_Error("OS2ECP: Decoded point was not on the curve");
   }

   return point;
}

std::pair<BigInt, BigInt> OS2ECP(
   const uint8_t data[], size_t data_len, const BigInt& curve_p, const BigInt& curve_a, const BigInt& curve_b) {
   if(data_len <= 1) {
      throw Decoding_Error("OS2ECP invalid point");
   }

   const uint8_t pc = data[0];

   BigInt x, y;

   if(pc == 2 || pc == 3) {
      //compressed form
      x = BigInt::decode(&data[1], data_len - 1);

      const bool y_mod_2 = ((pc & 0x01) == 1);
      y = decompress_point(y_mod_2, x, curve_p, curve_a, curve_b);
   } else if(pc == 4) {
      const size_t l = (data_len - 1) / 2;

      // uncompressed form
      x = BigInt::decode(&data[1], l);
      y = BigInt::decode(&data[l + 1], l);
   } else if(pc == 6 || pc == 7) {
      const size_t l = (data_len - 1) / 2;

      // hybrid form
      x = BigInt::decode(&data[1], l);
      y = BigInt::decode(&data[l + 1], l);

      const bool y_mod_2 = ((pc & 0x01) == 1);

      if(decompress_point(y_mod_2, x, curve_p, curve_a, curve_b) != y) {
         throw Decoding_Error("OS2ECP: Decoding error in hybrid format");
      }
   } else {
      throw Invalid_Argument("OS2ECP: Unknown format type " + std::to_string(pc));
   }

   return std::make_pair(x, y);
}

EC_Point OS2ECP(std::span<const uint8_t> data, const CurveGFp& curve) {
   return OS2ECP(data.data(), data.size(), curve);
}

}  // namespace Botan
