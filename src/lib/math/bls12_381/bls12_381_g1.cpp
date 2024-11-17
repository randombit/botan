/*
* (C) 2024,2025,2026 Jack Lloyd
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

static_assert(G1Affine::BYTES == FieldElement::BYTES);

// Standard generator coordinates, pre-converted into Montgomery form
constexpr auto G1_X = FieldElement::_unchecked_from_words(hex_to_words<word>(
   "120177419e0bfb75edce6ecc21dbf440f0ae6acdf3d0e747154f95c7143ba1c17817fc679976fff55cb38790fd530c16"));

constexpr auto G1_Y = FieldElement::_unchecked_from_words(hex_to_words<word>(
   "0bbc3efc5008a26a0e1c8c3fad0059c051ac582950405194dd595f13570725ce8c22631a7918fd8ebaac93d50ce72271"));

// A nontrivial cube root of unity, acting on G1 as multiplication by -z^2
constexpr auto G1_BETA = FieldElement::_unchecked_from_words(hex_to_words<word>(
   "051ba4ab241b61603636b76660701c6ec26a2ff874fd029b16a8ca3ac61577f7f3b8ddab7ece5a2a30f1361b798a64e8"));

FieldElement fe_load(const std::array<word, FieldElement::N>& w) {
   return FieldElement::_unchecked_from_words(w);
}

inline FieldElement mul_by_3b(const FieldElement& fe) {
   // b == 4 so 3*b == 12
   const auto fe2 = fe + fe;
   const auto fe4 = fe2 + fe2;
   return fe4 + fe4 + fe4;
}

}  // namespace

G1Affine::G1Affine(const FieldElement& x, const FieldElement& y, uint32_t infinity) :
      m_x(x._words()), m_y(y._words()), m_infinity(infinity) {}

//static
G1Affine G1Affine::identity() {
   return G1Affine(FieldElement::zero(), FieldElement::one(), 1);
}

//static
G1Affine G1Affine::generator() {
   return G1Affine(G1_X, G1_Y, 0);
}

FieldElement G1Affine::_x() const {
   return fe_load(m_x);
}

FieldElement G1Affine::_y() const {
   return fe_load(m_y);
}

bool G1Affine::is_identity() const {
   return m_infinity != 0;
}

//static
std::optional<G1Affine> G1Affine::deserialize(std::span<const uint8_t> bytes) {
   if(bytes.size() != G1Affine::BYTES) {
      return {};
   }

   const uint8_t flags = bytes[0];

   // Only the compressed encoding is supported
   if((flags & 0x80) != 0x80) {
      return {};
   }

   const bool is_infinity = (flags & 0x40) == 0x40;
   const bool y_is_largest = (flags & 0x20) == 0x20;

   std::array<uint8_t, G1Affine::BYTES> x_bytes{};
   copy_mem(x_bytes.data(), bytes.data(), bytes.size());
   x_bytes[0] &= 0x1F;

   if(is_infinity) {
      // The identity is encoded as the infinity flag with all other bits zero
      if(y_is_largest || !CT::all_zeros(x_bytes.data(), x_bytes.size()).as_bool()) {
         return {};
      }
      return G1Affine::identity();
   }

   const auto x = FieldElement::deserialize(x_bytes);
   if(!x) {
      return {};
   }

   const auto y2 = x->square() * (*x) + FieldElement::from_u32(4);
   auto y = y2.sqrt();
   if(!y) {
      return {};
   }

   // Choose either y or -y depending on the sign flag
   const auto flip = (y->_is_lexicographically_largest() != CT::Choice::from_int(static_cast<word>(flags & 0x20)));
   y->_conditional_assign(flip, y->negate());

   G1Affine pt(*x, *y, 0);

   // Fast subgroup check (https://eprint.iacr.org/2021/1130 section 6):
   // P is in the prime order subgroup iff phi(P) == -[z^2]P, where
   // phi(x, y) = (beta*x, y)
   using Mul = PointMul<G1Projective>;
   const auto zz_p = Mul::mul_by_z_abs(Mul::mul_by_z_abs(G1Projective::from_affine(pt))).negate();

   // Compare the projective -[z^2]P with the affine phi(P)
   const auto zz_p_z = fe_load(zz_p.m_z);
   const auto x_eq = (fe_load(zz_p.m_x) == (*x * G1_BETA) * zz_p_z);
   const auto y_eq = (fe_load(zz_p.m_y) == *y * zz_p_z);
   if(!(x_eq && y_eq).as_bool()) {
      return {};
   }

   return pt;
}

std::array<uint8_t, G1Affine::BYTES> G1Affine::serialize() const {
   auto bytes = fe_load(m_x).serialize();

   // Set the compressed point indicator bit
   bytes[0] |= 0x80;

   const auto identity = CT::Choice::from_int(m_infinity);

   // If the identity element, set the identity bit
   bytes[0] |= (identity.into_bitmask<uint8_t>() & 0x40);

   // If y is the larger choice *and* not the point at identity, set the large-y bit
   const auto large_y = fe_load(m_y)._is_lexicographically_largest();
   bytes[0] |= ((!identity && large_y).into_bitmask<uint8_t>() & 0x20);

   return bytes;
}

G1Projective::G1Projective(const FieldElement& x, const FieldElement& y, const FieldElement& z) :
      m_x(x._words()), m_y(y._words()), m_z(z._words()) {}

G1Projective::G1Projective() : m_x({}), m_y(FieldElement::one()._words()), m_z({}) {}

//static
G1Projective G1Projective::from_affine(const G1Affine& affine) {
   // z == 0 if the identity element or 1 otherwise
   auto z = FieldElement::one();
   z._conditional_assign(CT::Choice::from_int(affine.m_infinity), FieldElement::zero());
   return G1Projective(affine._x(), affine._y(), z);
}

//static
G1Projective G1Projective::_unchecked_from_affine_coords(const FieldElement& x, const FieldElement& y) {
   return G1Projective(x, y, FieldElement::one());
}

//static
G1Projective G1Projective::generator() {
   return G1Projective(G1_X, G1_Y, FieldElement::one());
}

G1Affine G1Projective::to_affine() const {
   const auto z = fe_load(m_z);
   const auto zinv = z.invert();
   const auto inf = z.is_zero();

   // Canonicalize the identity to (0, 1); otherwise a round trip
   // through from_affine would produce the invalid triple (0, 0, 0),
   // which acts as an absorbing element of the addition formulas
   auto y = fe_load(m_y) * zinv;
   y._conditional_assign(inf, FieldElement::one());

   return G1Affine(fe_load(m_x) * zinv, y, inf.into_bitmask<uint32_t>() & 1);
}

//static
std::vector<G1Affine> G1Projective::to_affine_batch(std::span<const G1Projective> points) {
   const size_t n = points.size();

   std::vector<G1Affine> affine;
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

   auto masked_z = [](const G1Projective& pt) {
      auto z = fe_load(pt.m_z);
      z._conditional_assign(z.is_zero(), FieldElement::one());
      return z;
   };

   auto affine_from = [](const G1Projective& pt, const FieldElement& z_inv) {
      const auto inf = fe_load(pt.m_z).is_zero();

      auto x = fe_load(pt.m_x) * z_inv;
      auto y = fe_load(pt.m_y) * z_inv;

      // Canonicalize the identity to (0, 1), as in to_affine
      x._conditional_assign(inf, FieldElement::zero());
      y._conditional_assign(inf, FieldElement::one());

      return G1Affine(x, y, inf.into_bitmask<uint32_t>() & 1);
   };

   std::vector<FieldElement> prefix;
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

G1Projective G1Projective::negate() const {
   return G1Projective(fe_load(m_x), fe_load(m_y).negate(), fe_load(m_z));
}

bool G1Projective::is_identity() const {
   return CT::all_zeros(m_z.data(), m_z.size()).as_bool();
}

G1Projective G1Projective::dbl() const {
   // Algorithm 9, https://eprint.iacr.org/2015/1060.pdf

   const auto x = fe_load(m_x);
   const auto y = fe_load(m_y);
   const auto z = fe_load(m_z);

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

   return G1Projective(x3, y3, z3);
}

G1Projective G1Projective::add(const G1Projective& other) const {
   // Algorithm 7, https://eprint.iacr.org/2015/1060.pdf

   const auto x1 = fe_load(m_x);
   const auto y1 = fe_load(m_y);
   const auto z1 = fe_load(m_z);
   const auto x2 = fe_load(other.m_x);
   const auto y2 = fe_load(other.m_y);
   const auto z2 = fe_load(other.m_z);

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

   return G1Projective(x3, y3, z3);
}

G1Projective G1Projective::add_mixed(const G1Affine& other) const {
   // Algorithm 8, https://eprint.iacr.org/2015/1060.pdf
   //
   // The formula assumes other is not the identity; that case is
   // handled by conditional assignment at the end

   const auto x1 = fe_load(m_x);
   const auto y1 = fe_load(m_y);
   const auto z1 = fe_load(m_z);
   const auto x2 = fe_load(other.m_x);
   const auto y2 = fe_load(other.m_y);

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

   auto result = G1Projective(x3, y3, z3);

   const auto other_is_identity = CT::Choice::from_int(other.m_infinity);
   CT::conditional_assign_mem(other_is_identity, result.m_x.data(), m_x.data(), FE_WORDS);
   CT::conditional_assign_mem(other_is_identity, result.m_y.data(), m_y.data(), FE_WORDS);
   CT::conditional_assign_mem(other_is_identity, result.m_z.data(), m_z.data(), FE_WORDS);

   return result;
}

G1Projective G1Projective::mul(const Scalar& scalar) const {
   return PointMul<G1Projective>::mul(*this, scalar);
}

//static
G1Projective G1Projective::mul2(const G1Projective& p, const Scalar& a, const G1Projective& q, const Scalar& b) {
   return PointMul<G1Projective>::mul2(p, a, q, b);
}

//static
G1Projective G1Projective::mul2_vartime(const G1Projective& p,
                                        const Scalar& a,
                                        const G1Projective& q,
                                        const Scalar& b) {
   return PointMul<G1Projective>::mul2_vartime(p, a, q, b);
}

//static
G1Projective G1Projective::msm_vartime(std::span<const G1Affine> points, std::span<const Scalar> scalars) {
   return PointMul<G1Projective>::msm_vartime(points, scalars);
}

}  // namespace Botan::BLS12_381
