/*
* (C) 2024,2025,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/bls12_381.h>

#include <botan/internal/bls12_381_fields.h>
#include <botan/internal/bls12_381_group.h>
#include <botan/internal/bls12_381_point_mul.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/mp_core.h>

namespace Botan::BLS12_381 {

namespace {

// Standard generator coordinates, pre-converted into Montgomery form
constexpr auto G1_X = FieldElement::_unchecked_from_words(hex_to_words<word>(
   "120177419e0bfb75edce6ecc21dbf440f0ae6acdf3d0e747154f95c7143ba1c17817fc679976fff55cb38790fd530c16"));

constexpr auto G1_Y = FieldElement::_unchecked_from_words(hex_to_words<word>(
   "0bbc3efc5008a26a0e1c8c3fad0059c051ac582950405194dd595f13570725ce8c22631a7918fd8ebaac93d50ce72271"));

// A nontrivial cube root of unity, acting on G1 as multiplication by -z^2
constexpr auto G1_BETA = FieldElement::_unchecked_from_words(hex_to_words<word>(
   "051ba4ab241b61603636b76660701c6ec26a2ff874fd029b16a8ca3ac61577f7f3b8ddab7ece5a2a30f1361b798a64e8"));

/**
* The G1 traits for GroupOps
*/
struct G1Group final {
      using Affine = G1Affine;
      using Projective = G1Projective;
      using FE = FieldElement;

      static FE load(const std::array<word, FieldElement::N>& w) { return FieldElement::_unchecked_from_words(w); }

      static std::array<word, FieldElement::N> store(const FE& v) { return v._words(); }

      static FE mul_by_3b(const FE& fe) {
         // b == 4 so 3*b == 12
         const auto fe2 = fe + fe;
         const auto fe4 = fe2 + fe2;
         return fe4 + fe4 + fe4;
      }

      static FE curve_b() { return FieldElement::from_u32(4); }
};

using G1Ops = GroupOps<G1Group>;

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
   return G1Group::load(m_x);
}

FieldElement G1Affine::_y() const {
   return G1Group::load(m_y);
}

bool G1Affine::is_identity() const {
   return m_infinity != 0;
}

//static
std::optional<G1Affine> G1Affine::deserialize(std::span<const uint8_t> bytes) {
   auto pt = G1Ops::deserialize_unchecked(bytes);
   if(!pt || pt->is_identity()) {
      return pt;
   }

   // Fast subgroup check (https://eprint.iacr.org/2021/1130 section 6):
   // P is in the prime order subgroup iff phi(P) == -[z^2]P, where
   // phi(x, y) = (beta*x, y); per the paper, "if the endomorphism is
   // true, then P must be of order r"
   using Mul = PointMul<G1Projective>;
   const auto zz_p = Mul::mul_by_z_abs(Mul::mul_by_z_abs(G1Projective::from_affine(*pt))).negate();

   // Compare the projective -[z^2]P with the affine phi(P)
   const auto zz_p_z = G1Group::load(zz_p.m_z);
   const auto x_eq = (G1Group::load(zz_p.m_x) == (pt->_x() * G1_BETA) * zz_p_z);
   const auto y_eq = (G1Group::load(zz_p.m_y) == pt->_y() * zz_p_z);
   if(!(x_eq && y_eq).as_bool()) {
      return {};
   }

   return pt;
}

std::array<uint8_t, G1Affine::BYTES> G1Affine::serialize() const {
   return G1Ops::serialize(*this);
}

G1Projective::G1Projective(const FieldElement& x, const FieldElement& y, const FieldElement& z) :
      m_x(x._words()), m_y(y._words()), m_z(z._words()) {}

G1Projective::G1Projective() : m_x({}), m_y(FieldElement::one()._words()), m_z({}) {}

//static
G1Projective G1Projective::from_affine(const G1Affine& affine) {
   return G1Ops::from_affine(affine);
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
   return G1Ops::to_affine(*this);
}

//static
std::vector<G1Affine> G1Projective::to_affine_batch(std::span<const G1Projective> points) {
   return G1Ops::to_affine_batch(points);
}

G1Projective G1Projective::negate() const {
   return G1Ops::negate(*this);
}

void G1Projective::conditional_negate(uint32_t negate) {
   G1Ops::conditional_negate(*this, negate);
}

bool G1Projective::is_identity() const {
   return CT::all_zeros(m_z.data(), m_z.size()).as_bool();
}

G1Projective G1Projective::dbl() const {
   return G1Ops::dbl(*this);
}

G1Projective G1Projective::add(const G1Projective& other) const {
   return G1Ops::add(*this, other);
}

G1Projective G1Projective::add_mixed(const G1Affine& other) const {
   return G1Ops::add_mixed(*this, other, false);
}

G1Projective G1Projective::add_mixed(const G1Affine& other, bool negate_other) const {
   return G1Ops::add_mixed(*this, other, negate_other);
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
