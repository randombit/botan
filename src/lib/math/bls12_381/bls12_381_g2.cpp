/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/bls12_381.h>

#include <botan/internal/bls12_381_fields.h>
#include <botan/internal/bls12_381_point_mul.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/mp_core.h>
#include <algorithm>

namespace Botan::BLS12_381 {

namespace {

FieldElement2 fe2_load(const std::array<word, 2 * FieldElement::N>& w) {
   std::array<word, FieldElement::N> c0{};
   std::array<word, FieldElement::N> c1{};
   copy_mem(c0.data(), w.data(), c0.size());
   copy_mem(c1.data(), w.data() + c0.size(), c1.size());
   return FieldElement2::_unchecked_from_words(c0, c1);
}

std::array<word, 2 * FieldElement::N> fe2_store(const FieldElement2& v) {
   std::array<word, 2 * FieldElement::N> w{};
   copy_mem(w.data(), v.c0()._words().data(), FieldElement::N);
   copy_mem(w.data() + FieldElement::N, v.c1()._words().data(), FieldElement::N);
   return w;
}

// Standard generator coordinates, pre-converted into Montgomery form
constexpr auto G2_X = FieldElement2::_unchecked_from_words(
   hex_to_words<word>(
      "058191924350bcd76f67b7631863366b9894999d1a3caee9a1a893b53e2ae580b3f5fb2687b4961af5f28fa202940a10"),
   hex_to_words<word>(
      "11922a097360edf3c2b6ed0ef21585471b1ab6cc8541b3673bb17e18e2867806aaa0c59dbccd60c3a5a9c0759e23f606"));

constexpr auto G2_Y = FieldElement2::_unchecked_from_words(
   hex_to_words<word>(
      "0083fd8e7e80dae507d3a975f0ef25a2bbefb5e96e0d495fe7e6856caa0a635a597cfa1f5e369c5a4c730af860494c4a"),
   hex_to_words<word>(
      "0b2bc2a163de1bf2e7175850a43ccaed79495c4ec93da33a86adac6a3be4eba018aa270a2b1461dcadc0fc92df64b05d"));

// 1/(u+1)^((p-1)/3) and 1/(u+1)^((p-1)/2), for the psi endomorphism
constexpr auto G2_PSI_X = FieldElement2::_unchecked_from_words(
   hex_to_words<word>(
      "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
   hex_to_words<word>(
      "14e56d3f1564853a14e4f04fe2db9068a20d1b8c7e88102450880866309b7e2c2af322533285a5d5890dc9e4867545c3"));
constexpr auto G2_PSI_Y = FieldElement2::_unchecked_from_words(
   hex_to_words<word>(
      "0bd592fc7d825ec81d794e4fac7cf0b992ad2afd19103e18382844c88b6237324294213d86c181833e2f585da55c9ad1"),
   hex_to_words<word>(
      "0e2b7eedbbfd87d22da2596696cebc1dd1ca2087da74d4a72f088dd86b4ebef1dc17dec12a927e7c7bcfa7a25aa30fda"));

// The x coefficient of psi^2; the y coefficient is -1
constexpr auto G2_PSI2_X = FieldElement2::_unchecked_from_words(
   hex_to_words<word>(
      "18f020655463874103f97d6e83d050d28eb60ebe01bacb9e587042afd3851b955dab22461fcda5d2cd03c9e48671f071"),
   hex_to_words<word>(
      "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"));

inline FieldElement2 mul_by_3b(const FieldElement2& fe) {
   // b == 4*(u+1) so 3*b == 12*(u+1)
   const auto fe2 = fe + fe;
   const auto fe4 = fe2 + fe2;
   return (fe4 + fe4 + fe4).mul_by_nonresidue();
}

FieldElement2 g2_curve_b() {
   const auto four = FieldElement::from_u32(4);
   return FieldElement2(four, four);
}

}  // namespace

G2Affine::G2Affine(const FieldElement2& x, const FieldElement2& y, uint32_t infinity) :
      m_x(fe2_store(x)), m_y(fe2_store(y)), m_infinity(infinity) {}

//static
G2Affine G2Affine::identity() {
   return G2Affine(FieldElement2::zero(), FieldElement2::one(), 1);
}

//static
G2Affine G2Affine::generator() {
   return G2Affine(G2_X, G2_Y, 0);
}

FieldElement2 G2Affine::_x() const {
   return fe2_load(m_x);
}

FieldElement2 G2Affine::_y() const {
   return fe2_load(m_y);
}

bool G2Affine::is_identity() const {
   return m_infinity != 0;
}

//static
std::optional<G2Affine> G2Affine::deserialize(std::span<const uint8_t> bytes) {
   if(bytes.size() != G2Affine::BYTES) {
      return {};
   }

   const uint8_t flags = bytes[0];

   // Only the compressed encoding is supported
   if((flags & 0x80) != 0x80) {
      return {};
   }

   const bool is_infinity = (flags & 0x40) == 0x40;
   const bool y_is_largest = (flags & 0x20) == 0x20;

   std::array<uint8_t, G2Affine::BYTES> x_bytes{};
   copy_mem(x_bytes.data(), bytes.data(), bytes.size());
   x_bytes[0] &= 0x1F;

   if(is_infinity) {
      // The identity is encoded as the infinity flag with all other bits zero
      if(y_is_largest || !CT::all_zeros(x_bytes.data(), x_bytes.size()).as_bool()) {
         return {};
      }
      return G2Affine::identity();
   }

   const auto x = FieldElement2::deserialize(x_bytes);
   if(!x) {
      return {};
   }

   const auto y2 = x->square() * (*x) + g2_curve_b();
   auto y = y2.sqrt();
   if(!y) {
      return {};
   }

   // Choose either y or -y depending on the sign flag
   const auto flip = (y->_is_lexicographically_largest() != CT::Choice::from_int(static_cast<word>(flags & 0x20)));
   y->_conditional_assign(flip, y->negate());

   G2Affine pt(*x, *y, 0);

   // Fast subgroup check (https://eprint.iacr.org/2021/1130 section 4):
   // P is in the prime order subgroup iff psi(P) == [z]P, where psi is
   // the untwist-Frobenius-twist endomorphism
   const auto z_p = PointMul<G2Projective>::mul_by_z_abs(G2Projective::from_affine(pt)).negate();

   const auto psi_x = x->conjugate() * G2_PSI_X;
   const auto psi_y = y->conjugate() * G2_PSI_Y;

   // Compare the projective [z]P with the affine psi(P)
   const auto z_p_z = fe2_load(z_p.m_z);
   const auto x_eq = (fe2_load(z_p.m_x) == psi_x * z_p_z);
   const auto y_eq = (fe2_load(z_p.m_y) == psi_y * z_p_z);
   if(!(x_eq && y_eq).as_bool()) {
      return {};
   }

   return pt;
}

std::array<uint8_t, G2Affine::BYTES> G2Affine::serialize() const {
   auto bytes = fe2_load(m_x).serialize();

   // Set the compressed point indicator bit
   bytes[0] |= 0x80;

   const auto identity = CT::Choice::from_int(m_infinity);

   // If the identity element, set the identity bit
   bytes[0] |= (identity.into_bitmask<uint8_t>() & 0x40);

   // If y is the larger choice *and* not the point at identity, set the large-y bit
   const auto large_y = fe2_load(m_y)._is_lexicographically_largest();
   bytes[0] |= ((!identity && large_y).into_bitmask<uint8_t>() & 0x20);

   return bytes;
}

G2Projective::G2Projective(const FieldElement2& x, const FieldElement2& y, const FieldElement2& z) :
      m_x(fe2_store(x)), m_y(fe2_store(y)), m_z(fe2_store(z)) {}

G2Projective::G2Projective() : m_x({}), m_y(fe2_store(FieldElement2::one())), m_z({}) {}

//static
G2Projective G2Projective::from_affine(const G2Affine& affine) {
   // z == 0 if the identity element or 1 otherwise
   auto z = FieldElement2::one();
   z._conditional_assign(CT::Choice::from_int(affine.m_infinity), FieldElement2::zero());
   return G2Projective(affine._x(), affine._y(), z);
}

//static
G2Projective G2Projective::_unchecked_from_affine_coords(const FieldElement2& x, const FieldElement2& y) {
   return G2Projective(x, y, FieldElement2::one());
}

//static
G2Projective G2Projective::generator() {
   return G2Projective(G2_X, G2_Y, FieldElement2::one());
}

G2Affine G2Projective::to_affine() const {
   const auto z = fe2_load(m_z);
   const auto zinv = z.invert();
   const auto inf = z.is_zero();

   // Canonicalize the identity to (0, 1); otherwise a round trip
   // through from_affine would produce the invalid triple (0, 0, 0),
   // which acts as an absorbing element of the addition formulas
   auto y = fe2_load(m_y) * zinv;
   y._conditional_assign(inf, FieldElement2::one());

   return G2Affine(fe2_load(m_x) * zinv, y, inf.into_bitmask<uint32_t>() & 1);
}

//static
std::vector<G2Affine> G2Projective::to_affine_batch(std::span<const G2Projective> points) {
   const size_t n = points.size();

   std::vector<G2Affine> affine;
   affine.reserve(n);

   if(n == 0) {
      return affine;
   }

   /*
   Batch inversion of the z coordinates using Montgomery's trick, with a
   single field inversion plus 3*(n-1) multiplications.

   See Algorithm 2.26 in "Guide to Elliptic Curve Cryptography"
   (Hankerson, Menezes, Vanstone)

   An identity element (z == 0) would zero the running product, so
   identity z's are replaced by one, and the affine identity is instead
   assigned at the end; this handles identities in constant time, rather
   than leaking their presence by falling back to serial conversion.
   */

   auto masked_z = [](const G2Projective& pt) {
      auto z = fe2_load(pt.m_z);
      z._conditional_assign(z.is_zero(), FieldElement2::one());
      return z;
   };

   auto affine_from = [](const G2Projective& pt, const FieldElement2& z_inv) {
      const auto inf = fe2_load(pt.m_z).is_zero();

      auto x = fe2_load(pt.m_x) * z_inv;
      auto y = fe2_load(pt.m_y) * z_inv;

      // Canonicalize the identity to (0, 1), as in to_affine
      x._conditional_assign(inf, FieldElement2::zero());
      y._conditional_assign(inf, FieldElement2::one());

      return G2Affine(x, y, inf.into_bitmask<uint32_t>() & 1);
   };

   std::vector<FieldElement2> prefix;
   prefix.reserve(n);

   prefix.push_back(masked_z(points[0]));
   for(size_t i = 1; i != n; ++i) {
      prefix.push_back(prefix[i - 1] * masked_z(points[i]));
   }

   auto inv = prefix[n - 1].invert();

   for(size_t i = n; i > 1; --i) {
      const auto& pt = points[i - 1];
      affine.push_back(affine_from(pt, inv * prefix[i - 2]));
      inv = inv * masked_z(pt);
   }
   affine.push_back(affine_from(points[0], inv));

   std::reverse(affine.begin(), affine.end());

   return affine;
}

G2Projective G2Projective::negate() const {
   return G2Projective(fe2_load(m_x), fe2_load(m_y).negate(), fe2_load(m_z));
}

bool G2Projective::is_identity() const {
   return CT::all_zeros(m_z.data(), m_z.size()).as_bool();
}

G2Projective G2Projective::dbl() const {
   // Algorithm 9, https://eprint.iacr.org/2015/1060.pdf

   const auto x = fe2_load(m_x);
   const auto y = fe2_load(m_y);
   const auto z = fe2_load(m_z);

   auto t0 = y.square();
   auto z3 = t0 + t0;
   z3 = z3 + z3;
   z3 = z3 + z3;
   auto t1 = y * z;
   auto t2 = z.square();
   t2 = mul_by_3b(t2);
   auto x3 = t2 * z3;
   auto y3 = t0 + t2;
   z3 = t1 * z3;
   t1 = t2 + t2;
   t2 = t1 + t2;
   t0 = t0 - t2;
   y3 = t0 * y3;
   y3 = x3 + y3;
   t1 = x * y;
   x3 = t0 * t1;
   x3 = x3 + x3;

   return G2Projective(x3, y3, z3);
}

G2Projective G2Projective::add(const G2Projective& other) const {
   // Algorithm 7, https://eprint.iacr.org/2015/1060.pdf

   const auto x1 = fe2_load(m_x);
   const auto y1 = fe2_load(m_y);
   const auto z1 = fe2_load(m_z);
   const auto x2 = fe2_load(other.m_x);
   const auto y2 = fe2_load(other.m_y);
   const auto z2 = fe2_load(other.m_z);

   auto t0 = x1 * x2;
   auto t1 = y1 * y2;
   auto t2 = z1 * z2;
   auto t3 = x1 + y1;
   auto t4 = x2 + y2;
   t3 = t3 * t4;
   t4 = t0 + t1;
   t3 = t3 - t4;
   t4 = y1 + z1;
   auto x3 = y2 + z2;
   t4 = t4 * x3;
   x3 = t1 + t2;
   t4 = t4 - x3;
   x3 = x1 + z1;
   auto y3 = x2 + z2;
   x3 = x3 * y3;
   y3 = t0 + t2;
   y3 = x3 - y3;
   x3 = t0 + t0;
   t0 = x3 + t0;
   t2 = mul_by_3b(t2);
   auto z3 = t1 + t2;
   t1 = t1 - t2;
   y3 = mul_by_3b(y3);
   x3 = t4 * y3;
   t2 = t3 * t1;
   x3 = t2 - x3;
   y3 = y3 * t0;
   t1 = t1 * z3;
   y3 = t1 + y3;
   t0 = t0 * t3;
   z3 = z3 * t4;
   z3 = z3 + t0;

   return G2Projective(x3, y3, z3);
}

G2Projective G2Projective::add_mixed(const G2Affine& other) const {
   // Algorithm 8, https://eprint.iacr.org/2015/1060.pdf
   //
   // The formula assumes other is not the identity; that case is
   // handled by conditional assignment at the end

   const auto x1 = fe2_load(m_x);
   const auto y1 = fe2_load(m_y);
   const auto z1 = fe2_load(m_z);
   const auto x2 = fe2_load(other.m_x);
   const auto y2 = fe2_load(other.m_y);

   auto t0 = x1 * x2;
   auto t1 = y1 * y2;
   auto t3 = x2 + y2;
   auto t4 = x1 + y1;
   t3 = t3 * t4;
   t4 = t0 + t1;
   t3 = t3 - t4;
   t4 = y2 * z1;
   t4 = t4 + y1;
   auto y3 = x2 * z1;
   y3 = y3 + x1;
   auto x3 = t0 + t0;
   t0 = x3 + t0;
   auto t2 = mul_by_3b(z1);
   auto z3 = t1 + t2;
   t1 = t1 - t2;
   y3 = mul_by_3b(y3);
   x3 = t4 * y3;
   t2 = t3 * t1;
   x3 = t2 - x3;
   y3 = y3 * t0;
   t1 = t1 * z3;
   y3 = t1 + y3;
   t0 = t0 * t3;
   z3 = z3 * t4;
   z3 = z3 + t0;

   auto result = G2Projective(x3, y3, z3);

   const auto other_is_identity = CT::Choice::from_int(other.m_infinity);
   CT::conditional_assign_mem(other_is_identity, result.m_x.data(), m_x.data(), FE2_WORDS);
   CT::conditional_assign_mem(other_is_identity, result.m_y.data(), m_y.data(), FE2_WORDS);
   CT::conditional_assign_mem(other_is_identity, result.m_z.data(), m_z.data(), FE2_WORDS);

   return result;
}

G2Projective G2Projective::mul(const Scalar& scalar) const {
   return PointMul<G2Projective>::mul(*this, scalar);
}

//static
G2Projective G2Projective::mul2(const G2Projective& p, const Scalar& a, const G2Projective& q, const Scalar& b) {
   return PointMul<G2Projective>::mul2(p, a, q, b);
}

//static
G2Projective G2Projective::mul2_vartime(const G2Projective& p,
                                        const Scalar& a,
                                        const G2Projective& q,
                                        const Scalar& b) {
   return PointMul<G2Projective>::mul2_vartime(p, a, q, b);
}

//static
G2Projective G2Projective::msm_vartime(std::span<const G2Affine> points, std::span<const Scalar> scalars) {
   return PointMul<G2Projective>::msm_vartime(points, scalars);
}

G2Projective G2Projective::psi() const {
   return G2Projective(
      fe2_load(m_x).conjugate() * G2_PSI_X, fe2_load(m_y).conjugate() * G2_PSI_Y, fe2_load(m_z).conjugate());
}

G2Projective G2Projective::psi2() const {
   return G2Projective(fe2_load(m_x) * G2_PSI2_X, fe2_load(m_y).negate(), fe2_load(m_z));
}

G2Projective G2Projective::clear_cofactor() const {
   // Budroni-Pintore cofactor clearing (https://eprint.iacr.org/2017/419 section 4.1)

   // [z]P; the parameter z is negative
   const auto t1 = PointMul<G2Projective>::mul_by_z_abs(*this).negate();
   const auto t2 = this->psi();

   auto r = this->dbl().psi2();
   r = r.add(PointMul<G2Projective>::mul_by_z_abs(t1.add(t2)).negate());
   r = r.add(t1.negate());
   r = r.add(t2.negate());
   r = r.add(this->negate());

   return r;
}

}  // namespace Botan::BLS12_381
