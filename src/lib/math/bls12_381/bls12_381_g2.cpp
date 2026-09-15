/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/bls12_381.h>

#include <botan/mem_ops.h>
#include <botan/internal/bls12_381_fields.h>
#include <botan/internal/bls12_381_group.h>
#include <botan/internal/bls12_381_point_mul.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/mp_core.h>

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

/**
* The G2 traits for GroupOps
*/
struct G2Group final {
      using Affine = G2Affine;
      using Projective = G2Projective;
      using FE = FieldElement2;

      static FE load(const std::array<word, 2 * FieldElement::N>& w) { return fe2_load(w); }

      static std::array<word, 2 * FieldElement::N> store(const FE& v) { return fe2_store(v); }

      static FE mul_by_3b(const FE& fe) {
         // b == 4*(u+1) so 3*b == 12*(u+1)
         const auto fe2 = fe + fe;
         const auto fe4 = fe2 + fe2;
         return (fe4 + fe4 + fe4).mul_by_nonresidue();
      }

      static FE curve_b() {
         const auto four = FieldElement::from_u32(4);
         return FieldElement2(four, four);
      }
};

using G2Ops = GroupOps<G2Group>;

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
   auto pt = G2Ops::deserialize_unchecked(bytes);
   if(!pt || pt->is_identity()) {
      return pt;
   }

   // Fast subgroup check (https://eprint.iacr.org/2021/1130 section 4):
   // P is in the prime order subgroup iff psi(P) == [z]P, where psi is
   // the untwist-Frobenius-twist endomorphism; the test is conclusive
   // since "Q is of order r under the condition gcd(h1, h2) = 1" and
   // for BLS12 curves "h2 mod h1 = 1 so that the condition is true"
   const auto z_p = PointMul<G2Projective>::mul_by_z_abs(G2Projective::from_affine(*pt)).negate();

   const auto psi_x = pt->_x().conjugate() * G2_PSI_X;
   const auto psi_y = pt->_y().conjugate() * G2_PSI_Y;

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
   return G2Ops::serialize(*this);
}

G2Projective::G2Projective(const FieldElement2& x, const FieldElement2& y, const FieldElement2& z) :
      m_x(fe2_store(x)), m_y(fe2_store(y)), m_z(fe2_store(z)) {}

G2Projective::G2Projective() : m_x({}), m_y(fe2_store(FieldElement2::one())), m_z({}) {}

//static
G2Projective G2Projective::from_affine(const G2Affine& affine) {
   return G2Ops::from_affine(affine);
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
   return G2Ops::to_affine(*this);
}

//static
std::vector<G2Affine> G2Projective::to_affine_batch(std::span<const G2Projective> points) {
   return G2Ops::to_affine_batch(points);
}

G2Projective G2Projective::negate() const {
   return G2Ops::negate(*this);
}

void G2Projective::conditional_negate(uint32_t negate) {
   G2Ops::conditional_negate(*this, negate);
}

bool G2Projective::is_identity() const {
   return CT::all_zeros(m_z.data(), m_z.size()).as_bool();
}

G2Projective G2Projective::dbl() const {
   return G2Ops::dbl(*this);
}

G2Projective G2Projective::add(const G2Projective& other) const {
   return G2Ops::add(*this, other);
}

G2Projective G2Projective::add_mixed(const G2Affine& other) const {
   return G2Ops::add_mixed(*this, other, false);
}

G2Projective G2Projective::add_mixed(const G2Affine& other, bool negate_other) const {
   return G2Ops::add_mixed(*this, other, negate_other);
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
