/*
* Point arithmetic on elliptic curves over GF(p)
*
* (C) 2007 Martin Doering, Christoph Ludwig, Falko Strenzke
*     2008-2011,2012,2014,2015,2018,2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ec_point.h>

#include <botan/numthry.h>
#include <botan/rng.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/ec_inner_data.h>
#include <botan/internal/mod_inv.h>
#include <botan/internal/monty.h>
#include <botan/internal/mp_core.h>
#include <botan/internal/stl_util.h>

namespace Botan {

// The main reason CurveGFp has not been entirely removed already is
// because a few (deprecated) public APIs of EC_Point rely on them,
// thus until Botan4 we must continue to access the EC data via a type
// named CurveGFp

CurveGFp::CurveGFp(const EC_Group_Data* group) : m_group(group) {
   BOTAN_ASSERT_NONNULL(m_group);
}

const BigInt& CurveGFp::get_a() const {
   return this->group().a();
}

const BigInt& CurveGFp::get_b() const {
   return this->group().b();
}

const BigInt& CurveGFp::get_p() const {
   return this->group().p();
}

size_t CurveGFp::get_p_words() const {
   return this->group().p_words();
}

namespace {

void to_rep(const EC_Group_Data& group, BigInt& x, secure_vector<word>& ws) {
   group.monty().mul_by(x, group.monty().R2(), ws);
}

void from_rep(const EC_Group_Data& group, BigInt& z, secure_vector<word>& ws) {
   group.monty().redc_in_place(z, ws);
}

BigInt from_rep_to_tmp(const EC_Group_Data& group, const BigInt& x, secure_vector<word>& ws) {
   return group.monty().redc(x, ws);
}

void fe_mul(const EC_Group_Data& group, BigInt& z, const BigInt& x, const BigInt& y, secure_vector<word>& ws) {
   group.monty().mul(z, x, y, ws);
}

void fe_mul(
   const EC_Group_Data& group, BigInt& z, const word x_w[], size_t x_size, const BigInt& y, secure_vector<word>& ws) {
   group.monty().mul(z, y, std::span{x_w, x_size}, ws);
}

BigInt fe_mul(const EC_Group_Data& group, const BigInt& x, const BigInt& y, secure_vector<word>& ws) {
   return group.monty().mul(x, y, ws);
}

void fe_sqr(const EC_Group_Data& group, BigInt& z, const BigInt& x, secure_vector<word>& ws) {
   group.monty().sqr(z, x, ws);
}

void fe_sqr(const EC_Group_Data& group, BigInt& z, const word x_w[], size_t x_size, secure_vector<word>& ws) {
   group.monty().sqr(z, std::span{x_w, x_size}, ws);
}

BigInt fe_sqr(const EC_Group_Data& group, const BigInt& x, secure_vector<word>& ws) {
   return group.monty().sqr(x, ws);
}

BigInt invert_element(const EC_Group_Data& group, const BigInt& x, secure_vector<word>& ws) {
   return group.monty().mul(inverse_mod_public_prime(x, group.p()), group.monty().R3(), ws);
}

size_t monty_ws_size(const EC_Group_Data& group) {
   return 2 * group.p_words();
}

}  // namespace

EC_Point::EC_Point(const CurveGFp& curve) : m_curve(curve), m_x(0), m_y(curve.group().monty().R1()), m_z(0) {}

EC_Point EC_Point::zero() const {
   return EC_Point(m_curve);
}

EC_Point::EC_Point(const CurveGFp& curve, BigInt x, BigInt y) :
      m_curve(curve), m_x(std::move(x)), m_y(std::move(y)), m_z(m_curve.group().monty().R1()) {
   const auto& group = m_curve.group();

   if(m_x < 0 || m_x >= group.p()) {
      throw Invalid_Argument("Invalid EC_Point affine x");
   }
   if(m_y < 0 || m_y >= group.p()) {
      throw Invalid_Argument("Invalid EC_Point affine y");
   }

   secure_vector<word> monty_ws(monty_ws_size(group));

   to_rep(group, m_x, monty_ws);
   to_rep(group, m_y, monty_ws);
}

void EC_Point::randomize_repr(RandomNumberGenerator& rng) {
   const auto& group = m_curve.group();
   secure_vector<word> ws(monty_ws_size(group));
   randomize_repr(rng, ws);
}

void EC_Point::randomize_repr(RandomNumberGenerator& rng, secure_vector<word>& ws) {
   if(!rng.is_seeded()) {
      return;
   }

   const auto& group = m_curve.group();

   const BigInt mask = BigInt::random_integer(rng, 2, group.p());

   /*
   * No reason to convert this to Montgomery representation first,
   * just pretend the random mask was chosen as Redc(mask) and the
   * random mask we generated above is in the Montgomery
   * representation.
   */

   const BigInt mask2 = fe_sqr(group, mask, ws);
   const BigInt mask3 = fe_mul(group, mask2, mask, ws);

   m_x = fe_mul(group, m_x, mask2, ws);
   m_y = fe_mul(group, m_y, mask3, ws);
   m_z = fe_mul(group, m_z, mask, ws);
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

   const auto& group = m_curve.group();

   if(is_zero()) {
      m_x.set_words(x_words, x_size);
      m_y.set_words(y_words, y_size);
      m_z = group.monty().R1();
      return;
   }

   resize_ws(ws_bn, monty_ws_size(group));

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

   const BigInt& p = group.p();

   fe_sqr(group, T3, m_z, ws);                  // z1^2
   fe_mul(group, T4, x_words, x_size, T3, ws);  // x2*z1^2

   fe_mul(group, T2, m_z, T3, ws);              // z1^3
   fe_mul(group, T0, y_words, y_size, T2, ws);  // y2*z1^3

   T4.mod_sub(m_x, p, sub_ws);  // x2*z1^2 - x1*z2^2

   T0.mod_sub(m_y, p, sub_ws);

   if(T4.is_zero()) {
      if(T0.is_zero()) {
         mult2(ws_bn);
         return;
      }

      // setting to zero:
      m_x.clear();
      m_y = group.monty().R1();
      m_z.clear();
      return;
   }

   fe_sqr(group, T2, T4, ws);

   fe_mul(group, T3, m_x, T2, ws);

   fe_mul(group, T1, T2, T4, ws);

   fe_sqr(group, m_x, T0, ws);
   m_x.mod_sub(T1, p, sub_ws);

   m_x.mod_sub(T3, p, sub_ws);
   m_x.mod_sub(T3, p, sub_ws);

   T3.mod_sub(m_x, p, sub_ws);

   fe_mul(group, T2, T0, T3, ws);
   fe_mul(group, T0, m_y, T1, ws);
   T2.mod_sub(T0, p, sub_ws);
   m_y.swap(T2);

   fe_mul(group, T0, m_z, T4, ws);
   m_z.swap(T0);
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

   const auto& group = m_curve.group();

   if(is_zero()) {
      m_x.set_words(x_words, x_size);
      m_y.set_words(y_words, y_size);
      m_z.set_words(z_words, z_size);
      return;
   }

   resize_ws(ws_bn, monty_ws_size(group));

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

   const BigInt& p = group.p();

   fe_sqr(group, T0, z_words, z_size, ws);      // z2^2
   fe_mul(group, T1, m_x, T0, ws);              // x1*z2^2
   fe_mul(group, T3, z_words, z_size, T0, ws);  // z2^3
   fe_mul(group, T2, m_y, T3, ws);              // y1*z2^3

   fe_sqr(group, T3, m_z, ws);                  // z1^2
   fe_mul(group, T4, x_words, x_size, T3, ws);  // x2*z1^2

   fe_mul(group, T5, m_z, T3, ws);              // z1^3
   fe_mul(group, T0, y_words, y_size, T5, ws);  // y2*z1^3

   T4.mod_sub(T1, p, sub_ws);  // x2*z1^2 - x1*z2^2

   T0.mod_sub(T2, p, sub_ws);

   if(T4.is_zero()) {
      if(T0.is_zero()) {
         mult2(ws_bn);
         return;
      }

      // setting to zero:
      m_x.clear();
      m_y = group.monty().R1();
      m_z.clear();
      return;
   }

   fe_sqr(group, T5, T4, ws);

   fe_mul(group, T3, T1, T5, ws);

   fe_mul(group, T1, T5, T4, ws);

   fe_sqr(group, m_x, T0, ws);
   m_x.mod_sub(T1, p, sub_ws);
   m_x.mod_sub(T3, p, sub_ws);
   m_x.mod_sub(T3, p, sub_ws);

   T3.mod_sub(m_x, p, sub_ws);

   fe_mul(group, m_y, T0, T3, ws);
   fe_mul(group, T3, T2, T1, ws);

   m_y.mod_sub(T3, p, sub_ws);

   fe_mul(group, T3, z_words, z_size, m_z, ws);
   fe_mul(group, m_z, T3, T4, ws);
}

void EC_Point::mult2i(size_t iterations, std::vector<BigInt>& ws_bn) {
   if(iterations == 0) {
      return;
   }

   if(m_y.is_zero()) {
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

   const auto& group = m_curve.group();

   if(m_y.is_zero()) {
      *this = EC_Point(m_curve);  // setting myself to zero
      return;
   }

   resize_ws(ws_bn, monty_ws_size(group));

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
   const BigInt& p = group.p();

   fe_sqr(group, T0, m_y, ws);

   fe_mul(group, T1, m_x, T0, ws);
   T1.mod_mul(4, p, sub_ws);

   if(group.a_is_zero()) {
      // if a == 0 then 3*x^2 + a*z^4 is just 3*x^2
      fe_sqr(group, T4, m_x, ws);  // x^2
      T4.mod_mul(3, p, sub_ws);    // 3*x^2
   } else if(group.a_is_minus_3()) {
      /*
      if a == -3 then
        3*x^2 + a*z^4 == 3*x^2 - 3*z^4 == 3*(x^2-z^4) == 3*(x-z^2)*(x+z^2)
      */
      fe_sqr(group, T3, m_z, ws);  // z^2

      // (x-z^2)
      T2 = m_x;
      T2.mod_sub(T3, p, sub_ws);

      // (x+z^2)
      T3.mod_add(m_x, p, sub_ws);

      fe_mul(group, T4, T2, T3, ws);  // (x-z^2)*(x+z^2)

      T4.mod_mul(3, p, sub_ws);  // 3*(x-z^2)*(x+z^2)
   } else {
      fe_sqr(group, T3, m_z, ws);                  // z^2
      fe_sqr(group, T4, T3, ws);                   // z^4
      fe_mul(group, T3, group.monty_a(), T4, ws);  // a*z^4

      fe_sqr(group, T4, m_x, ws);  // x^2
      T4.mod_mul(3, p, sub_ws);
      T4.mod_add(T3, p, sub_ws);  // 3*x^2 + a*z^4
   }

   fe_sqr(group, T2, T4, ws);
   T2.mod_sub(T1, p, sub_ws);
   T2.mod_sub(T1, p, sub_ws);

   fe_sqr(group, T3, T0, ws);
   T3.mod_mul(8, p, sub_ws);

   T1.mod_sub(T2, p, sub_ws);

   fe_mul(group, T0, T4, T1, ws);
   T0.mod_sub(T3, p, sub_ws);

   m_x.swap(T2);

   fe_mul(group, T2, m_y, m_z, ws);
   T2.mod_mul(2, p, sub_ws);

   m_y.swap(T0);
   m_z.swap(T2);
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

   const auto& group = points[0].m_curve.group();
   const BigInt& rep_1 = group.monty().R1();

   if(ws.size() < monty_ws_size(group)) {
      ws.resize(monty_ws_size(group));
   }

   std::vector<BigInt> c(points.size());
   c[0] = points[0].m_z;

   for(size_t i = 1; i != points.size(); ++i) {
      fe_mul(group, c[i], c[i - 1], points[i].m_z, ws);
   }

   BigInt s_inv = invert_element(group, c[c.size() - 1], ws);

   BigInt z_inv, z2_inv, z3_inv;

   for(size_t i = points.size() - 1; i != 0; i--) {
      EC_Point& point = points[i];

      fe_mul(group, z_inv, s_inv, c[i - 1], ws);

      s_inv = fe_mul(group, s_inv, point.m_z, ws);

      fe_sqr(group, z2_inv, z_inv, ws);
      fe_mul(group, z3_inv, z2_inv, z_inv, ws);
      point.m_x = fe_mul(group, point.m_x, z2_inv, ws);
      point.m_y = fe_mul(group, point.m_y, z3_inv, ws);
      point.m_z = rep_1;
   }

   fe_sqr(group, z2_inv, s_inv, ws);
   fe_mul(group, z3_inv, z2_inv, s_inv, ws);
   points[0].m_x = fe_mul(group, points[0].m_x, z2_inv, ws);
   points[0].m_y = fe_mul(group, points[0].m_y, z3_inv, ws);
   points[0].m_z = rep_1;
}

void EC_Point::force_affine() {
   if(is_zero()) {
      throw Invalid_State("Cannot convert zero ECC point to affine");
   }

   secure_vector<word> ws;

   const auto& group = m_curve.group();

   const BigInt z_inv = invert_element(group, m_z, ws);
   const BigInt z2_inv = fe_sqr(group, z_inv, ws);
   const BigInt z3_inv = fe_mul(group, z_inv, z2_inv, ws);
   m_x = fe_mul(group, m_x, z2_inv, ws);
   m_y = fe_mul(group, m_y, z3_inv, ws);
   m_z = group.monty().R1();
}

bool EC_Point::is_affine() const {
   const auto& group = m_curve.group();
   return m_z == group.monty().R1();
}

secure_vector<uint8_t> EC_Point::x_bytes() const {
   const auto& group = m_curve.group();
   const size_t p_bytes = group.p_bytes();
   secure_vector<uint8_t> b(p_bytes);
   BigInt::encode_1363(b.data(), b.size(), this->get_affine_x());
   return b;
}

secure_vector<uint8_t> EC_Point::y_bytes() const {
   const auto& group = m_curve.group();
   const size_t p_bytes = group.p_bytes();
   secure_vector<uint8_t> b(p_bytes);
   BigInt::encode_1363(b.data(), b.size(), this->get_affine_y());
   return b;
}

secure_vector<uint8_t> EC_Point::xy_bytes() const {
   const auto& group = m_curve.group();
   const size_t p_bytes = group.p_bytes();
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

   const auto& group = m_curve.group();

   if(is_affine()) {
      return from_rep_to_tmp(group, m_x, monty_ws);
   }

   BigInt z2 = fe_sqr(group, m_z, monty_ws);
   z2 = invert_element(group, z2, monty_ws);

   BigInt r;
   fe_mul(group, r, m_x, z2, monty_ws);
   from_rep(group, r, monty_ws);
   return r;
}

BigInt EC_Point::get_affine_y() const {
   if(is_zero()) {
      throw Invalid_State("Cannot convert zero point to affine");
   }

   const auto& group = m_curve.group();
   secure_vector<word> monty_ws;

   if(is_affine()) {
      return from_rep_to_tmp(group, m_y, monty_ws);
   }

   const BigInt z2 = fe_sqr(group, m_z, monty_ws);
   const BigInt z3 = fe_mul(group, m_z, z2, monty_ws);
   const BigInt z3_inv = invert_element(group, z3, monty_ws);

   BigInt r;
   fe_mul(group, r, m_y, z3_inv, monty_ws);
   from_rep(group, r, monty_ws);
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

   const auto& group = m_curve.group();
   secure_vector<word> monty_ws;

   const BigInt y2 = from_rep_to_tmp(group, fe_sqr(group, m_y, monty_ws), monty_ws);
   const BigInt x3 = fe_mul(group, m_x, fe_sqr(group, m_x, monty_ws), monty_ws);
   const BigInt ax = fe_mul(group, m_x, group.monty_a(), monty_ws);
   const BigInt z2 = fe_sqr(group, m_z, monty_ws);

   const BigInt& monty_b = group.monty_b();

   // Is z equal to 1 (in Montgomery form)?
   if(m_z == z2) {
      if(y2 != from_rep_to_tmp(group, x3 + ax + monty_b, monty_ws)) {
         return false;
      }
   }

   const BigInt z3 = fe_mul(group, m_z, z2, monty_ws);
   const BigInt ax_z4 = fe_mul(group, ax, fe_sqr(group, z2, monty_ws), monty_ws);
   const BigInt b_z6 = fe_mul(group, monty_b, fe_sqr(group, z3, monty_ws), monty_ws);

   if(y2 != from_rep_to_tmp(group, x3 + ax_z4 + b_z6, monty_ws)) {
      return false;
   }

   return true;
}

bool EC_Point::_is_x_eq_to_v_mod_order(const BigInt& v) const {
   if(this->is_zero()) {
      return false;
   }

   const auto& group = m_curve.group();

   /*
   * The trick used below doesn't work for curves with cofactors
   */
   if(group.has_cofactor()) {
      return group.mod_order().reduce(this->get_affine_x()) == v;
   }

   /*
   * Note we're working with the projective coordinate directly here!
   * Nominally we're comparing v with the affine x coordinate.
   *
   * return group.mod_order(this->get_affine_x()) == v;
   *
   * However by instead projecting r to an identical z as the x
   * coordinate, we can compare without having to perform an
   * expensive inversion in the field.
   *
   * That is, given (x*z2) and r, instead of checking if
   *    (x*z2)*z2^-1 == r,
   * we check if
   *    (x*z2) == (r*z2)
   */
   secure_vector<word> ws;
   BigInt vr = v;
   to_rep(group, vr, ws);
   BigInt z2, v_z2;
   fe_sqr(group, z2, this->get_z(), ws);
   fe_mul(group, v_z2, vr, z2, ws);

   /*
   * Since (typically) the group order is slightly less than the size
   * of the field elements, its possible the signer had to reduce the
   * r component. If they did not reduce r, then this value is correct.
   *
   * Due to the Hasse bound, this case occurs almost always; the
   * probability that a reduction was actually required is
   * approximately 1 in 2^(n/2) where n is the bit length of the curve.
   */
   if(this->get_x() == v_z2) {
      return true;
   }

   if(group.order_is_less_than_p()) {
      vr = v + group.order();
      if(vr < group.p()) {
         to_rep(group, vr, ws);
         fe_mul(group, v_z2, vr, z2, ws);

         if(this->get_x() == v_z2) {
            return true;
         }
      }
   }

   // Reject:
   return false;
}

// swaps the states of *this and other
void EC_Point::swap(EC_Point& other) noexcept {
   m_curve.swap(other.m_curve);
   m_x.swap(other.m_x);
   m_y.swap(other.m_y);
   m_z.swap(other.m_z);
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

   const size_t p_bytes = m_curve.group().p_bytes();

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

BigInt decompress_point(bool y_mod_2, const BigInt& x, const BigInt& p, const BigInt& a, const BigInt& b) {
   const BigInt g = ((x * x + a) * x + b) % p;

   BigInt z = sqrt_modulo_prime(g, p);

   if(z < 0) {
      throw Decoding_Error("Error during EC point decompression");
   }

   if(z.get_bit(0) != y_mod_2) {
      z = p - z;
   }

   return z;
}

}  // namespace

EC_Point OS2ECP(std::span<const uint8_t> data, const CurveGFp& curve) {
   return OS2ECP(data.data(), data.size(), curve);
}

EC_Point OS2ECP(const uint8_t data[], size_t data_len, const CurveGFp& curve) {
   if(data_len == 1 && data[0] == 0) {
      // SEC1 standard representation of the point at infinity
      return EC_Point(curve);
   }

   const auto [g_x, g_y] = OS2ECP(data, data_len, curve.get_p(), curve.get_a(), curve.get_b());

   EC_Point point(curve, g_x, g_y);

   if(!point.on_the_curve()) {
      throw Decoding_Error("OS2ECP: Decoded point was not on the curve");
   }

   return point;
}

std::pair<BigInt, BigInt> OS2ECP(const uint8_t pt[], size_t pt_len, const BigInt& p, const BigInt& a, const BigInt& b) {
   if(pt_len <= 1) {
      throw Decoding_Error("OS2ECP invalid point encoding");
   }

   const uint8_t pc = pt[0];
   const size_t p_bytes = p.bytes();

   BigInt x, y;

   if(pc == 2 || pc == 3) {
      if(pt_len != 1 + p_bytes) {
         throw Decoding_Error("OS2ECP invalid point encoding");
      }
      x = BigInt::decode(&pt[1], pt_len - 1);

      const bool y_mod_2 = ((pc & 0x01) == 1);
      y = decompress_point(y_mod_2, x, p, a, b);
   } else if(pc == 4) {
      if(pt_len != 1 + 2 * p_bytes) {
         throw Decoding_Error("OS2ECP invalid point encoding");
      }

      x = BigInt::decode(&pt[1], p_bytes);
      y = BigInt::decode(&pt[p_bytes + 1], p_bytes);
   } else if(pc == 6 || pc == 7) {
      if(pt_len != 1 + 2 * p_bytes) {
         throw Decoding_Error("OS2ECP invalid point encoding");
      }

      x = BigInt::decode(&pt[1], p_bytes);
      y = BigInt::decode(&pt[p_bytes + 1], p_bytes);

      const bool y_mod_2 = ((pc & 0x01) == 1);

      if(decompress_point(y_mod_2, x, p, a, b) != y) {
         throw Decoding_Error("OS2ECP: Decoding error in hybrid format");
      }
   } else {
      throw Decoding_Error("OS2ECP: Unknown format type " + std::to_string(static_cast<int>(pc)));
   }

   if(x >= p || y >= p) {
      throw Decoding_Error("OS2ECP invalid point encoding");
   }

   return std::make_pair(x, y);
}

}  // namespace Botan
