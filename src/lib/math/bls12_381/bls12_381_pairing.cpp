/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/bls12_381.h>

#include <botan/exceptn.h>
#include <botan/mem_ops.h>
#include <botan/internal/bls12_381_point_mul.h>
#include <botan/internal/bls12_381_tower.h>
#include <botan/internal/ct_utils.h>
#include <vector>

namespace Botan::BLS12_381 {

namespace {

/**
* The Miller loop accumulator point, in Jacobian coordinates
*/
struct MillerG2 {
      FieldElement2 x;
      FieldElement2 y;
      FieldElement2 z;
};

struct LineEval {
      FieldElement2 c0;
      FieldElement2 c1;
      FieldElement2 c2;
};

struct PairingTerm {
      FieldElement px;
      FieldElement py;
      FieldElement2 qx;
      FieldElement2 qy;
      MillerG2 cur;
};

LineEval doubling_step(MillerG2& r) {
   // Adaptation of Algorithm 26, https://eprint.iacr.org/2010/354.pdf
   const auto tmp0 = r.x.square();
   const auto tmp1 = r.y.square();
   const auto tmp2 = tmp1.square();
   auto tmp3 = (tmp1 + r.x).square() - tmp0 - tmp2;
   tmp3 = tmp3 + tmp3;
   const auto tmp4 = tmp0 + tmp0 + tmp0;
   auto tmp6 = r.x + tmp4;
   const auto tmp5 = tmp4.square();
   const auto zsquared = r.z.square();
   r.x = tmp5 - tmp3 - tmp3;
   r.z = (r.z + r.y).square() - tmp1 - zsquared;
   r.y = (tmp3 - r.x) * tmp4;
   auto tmp2_8 = tmp2 + tmp2;
   tmp2_8 = tmp2_8 + tmp2_8;
   tmp2_8 = tmp2_8 + tmp2_8;
   r.y = r.y - tmp2_8;
   auto ltmp3 = tmp4 * zsquared;
   ltmp3 = ltmp3 + ltmp3;
   ltmp3 = ltmp3.negate();
   tmp6 = tmp6.square() - tmp0 - tmp5;
   auto tmp1_4 = tmp1 + tmp1;
   tmp1_4 = tmp1_4 + tmp1_4;
   tmp6 = tmp6 - tmp1_4;
   auto ltmp0 = r.z * zsquared;
   ltmp0 = ltmp0 + ltmp0;

   return LineEval{ltmp0, ltmp3, tmp6};
}

LineEval addition_step(MillerG2& r, const FieldElement2& qx, const FieldElement2& qy) {
   // Adaptation of Algorithm 27, https://eprint.iacr.org/2010/354.pdf
   const auto zsquared = r.z.square();
   const auto ysquared = qy.square();
   const auto t0 = zsquared * qx;
   const auto t1 = ((qy + r.z).square() - ysquared - zsquared) * zsquared;
   const auto t2 = t0 - r.x;
   const auto t3 = t2.square();
   auto t4 = t3 + t3;
   t4 = t4 + t4;
   const auto t5 = t4 * t2;
   const auto t6 = t1 - r.y - r.y;
   auto t9 = t6 * qx;
   const auto t7 = t4 * r.x;
   r.x = t6.square() - t5 - t7 - t7;
   r.z = (r.z + t2).square() - zsquared - t3;
   auto t10 = qy + r.z;
   const auto t8 = (t7 - r.x) * t6;
   auto t0y = r.y * t5;
   t0y = t0y + t0y;
   r.y = t8 - t0y;
   t10 = t10.square() - ysquared;
   const auto ztsquared = r.z.square();
   t10 = t10 - ztsquared;
   t9 = t9 + t9 - t10;
   const auto lt10 = r.z + r.z;
   const auto t6neg = t6.negate();
   const auto lt1 = t6neg + t6neg;

   return LineEval{lt10, lt1, t9};
}

Fp12 ell(const Fp12& f, const LineEval& line, const FieldElement& px, const FieldElement& py) {
   const auto c0 = FieldElement2(line.c0.c0() * py, line.c0.c1() * py);
   const auto c1 = FieldElement2(line.c1.c0() * px, line.c1.c1() * px);

   return f.mul_by_014(line.c2, c1, c0);
}

Fp12 multi_miller_loop(std::span<PairingTerm> terms) {
   auto f = Fp12::one();

   bool found_one = false;
   for(size_t b = 64; b > 0; --b) {
      const bool i = (((BLS_Z_ABS >> 1) >> (b - 1)) & 1) == 1;
      if(!found_one) {
         found_one = i;
         continue;
      }

      for(auto& term : terms) {
         f = ell(f, doubling_step(term.cur), term.px, term.py);
      }

      if(i) {
         for(auto& term : terms) {
            f = ell(f, addition_step(term.cur, term.qx, term.qy), term.px, term.py);
         }
      }

      f = f.square();
   }

   for(auto& term : terms) {
      f = ell(f, doubling_step(term.cur), term.px, term.py);
   }

   // z is negative
   return f.conjugate();
}

Fp12 cyclotomic_exp(const Fp12& f) {
   // Exponentiation by |z|, in the cyclotomic subgroup, negated by
   // conjugation since z is negative
   auto tmp = Fp12::one();
   bool found_one = false;
   for(size_t b = 64; b > 0; --b) {
      const bool i = ((BLS_Z_ABS >> (b - 1)) & 1) == 1;
      if(found_one) {
         tmp = tmp.cyclotomic_square();
      } else {
         found_one = i;
      }

      if(i) {
         tmp = tmp * f;
      }
   }

   return tmp.conjugate();
}

Fp12 final_exponentiation(const Fp12& ml) {
   auto f = ml;
   auto t0 = f.frobenius_map().frobenius_map().frobenius_map().frobenius_map().frobenius_map().frobenius_map();
   auto t1 = f.invert();
   auto t2 = t0 * t1;
   t1 = t2;
   t2 = t2.frobenius_map().frobenius_map();
   t2 = t2 * t1;
   t1 = t2.cyclotomic_square().conjugate();
   auto t3 = cyclotomic_exp(t2);
   auto t4 = t3.cyclotomic_square();
   auto t5 = t1 * t3;
   t1 = cyclotomic_exp(t5);
   t0 = cyclotomic_exp(t1);
   auto t6 = cyclotomic_exp(t0);
   t6 = t6 * t4;
   t4 = cyclotomic_exp(t6);
   t5 = t5.conjugate();
   t4 = t4 * t5 * t2;
   t5 = t2.conjugate();
   t1 = t1 * t2;
   t1 = t1.frobenius_map().frobenius_map().frobenius_map();
   t6 = t6 * t5;
   t6 = t6.frobenius_map();
   t3 = t3 * t0;
   t3 = t3.frobenius_map().frobenius_map();
   t3 = t3 * t1;
   t3 = t3 * t6;
   f = t3 * t4;

   return f;
}

PairingTerm make_term(const G1Affine& p, const G2Affine& q) {
   const auto qx = q._x();
   const auto qy = q._y();
   return PairingTerm{p._x(), p._y(), qx, qy, MillerG2{qx, qy, FieldElement2::one()}};
}

}  // namespace

Gt::Gt(const Fp12& v) : m_coeffs{} {
   constexpr size_t N = FieldElement::N;

   const std::array<const FieldElement2*, 6> c = {
      &v.c0().c0(), &v.c0().c1(), &v.c0().c2(), &v.c1().c0(), &v.c1().c1(), &v.c1().c2()};

   for(size_t i = 0; i != c.size(); ++i) {
      copy_mem(m_coeffs.data() + (2 * i) * N, c[i]->c0()._words().data(), N);
      copy_mem(m_coeffs.data() + (2 * i + 1) * N, c[i]->c1()._words().data(), N);
   }
}

Fp12 Gt::_to_fp12() const {
   constexpr size_t N = FieldElement::N;

   std::array<FieldElement2, 6> c;
   for(size_t i = 0; i != c.size(); ++i) {
      std::array<word, N> c0{};
      std::array<word, N> c1{};
      copy_mem(c0.data(), m_coeffs.data() + (2 * i) * N, N);
      copy_mem(c1.data(), m_coeffs.data() + (2 * i + 1) * N, N);
      c[i] = FieldElement2::_unchecked_from_words(c0, c1);
   }

   return Fp12(Fp6(c[0], c[1], c[2]), Fp6(c[3], c[4], c[5]));
}

//static
Gt Gt::identity() {
   return Gt(Fp12::one());
}

bool Gt::is_identity() const {
   return (*this) == Gt::identity();
}

bool Gt::operator==(const Gt& other) const {
   // The Montgomery representation of a reduced element is unique
   return CT::is_equal(m_coeffs.data(), other.m_coeffs.data(), m_coeffs.size()).as_bool();
}

std::array<uint8_t, Gt::BYTES> Gt::serialize() const {
   return this->_to_fp12().serialize();
}

Gt Gt::pairing(const G1Affine& p, const G2Affine& q) {
   if(p.is_identity() || q.is_identity()) {
      return Gt::identity();
   }

   std::array<PairingTerm, 1> terms = {make_term(p, q)};

   return Gt(final_exponentiation(multi_miller_loop(terms)));
}

Gt Gt::multi_pairing(std::span<const G1Affine> p, std::span<const G2Affine> q) {
   if(p.size() != q.size()) {
      throw Invalid_Argument("BLS12_381::multi_pairing spans must have equal length");
   }

   std::vector<PairingTerm> terms;
   terms.reserve(p.size());

   for(size_t i = 0; i != p.size(); ++i) {
      // By bilinearity e(I,Q) = e(P,I) = I, contributing nothing to the product
      if(p[i].is_identity() || q[i].is_identity()) {
         continue;
      }
      terms.push_back(make_term(p[i], q[i]));
   }

   if(terms.empty()) {
      return Gt::identity();
   }

   return Gt(final_exponentiation(multi_miller_loop(terms)));
}

}  // namespace Botan::BLS12_381
