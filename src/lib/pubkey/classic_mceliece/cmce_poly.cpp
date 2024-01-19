/*
 * Classic McEliece Polynomials
 * Based on the public domain reference implementation by the designers
 * (https://classic.mceliece.org/impl.html - released in Oct 2022 for NISTPQC-R4)
 *
 * (C) 2023 Jack Lloyd
 *     2023,2024 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/internal/cmce_poly.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/stl_util.h>

namespace Botan {

Classic_McEliece_GF Classic_McEliece_Polynomial::operator()(Classic_McEliece_GF a) const {
   BOTAN_DEBUG_ASSERT(a.modulus() == coef_at(0).modulus());

   Classic_McEliece_GF r(CmceGfElem(0), a.modulus());
   for(auto it = m_coef.rbegin(); it != m_coef.rend(); ++it) {
      r *= a;
      r += *it;
   }

   return r;
}

Classic_McEliece_Polynomial Classic_McEliece_Polynomial_Ring::multiply(const Classic_McEliece_Polynomial& a,
                                                                       const Classic_McEliece_Polynomial& b) const {
   std::vector<Classic_McEliece_GF> prod(m_t * 2 - 1, {CmceGfElem(0), m_poly_f});

   for(size_t i = 0; i < m_t; ++i) {
      for(size_t j = 0; j < m_t; ++j) {
         prod.at(i + j) += (a.coef_at(i) * b.coef_at(j));
      }
   }

   for(size_t i = (m_t - 1) * 2; i >= m_t; --i) {
      for(auto& [idx, coef] : m_position_map) {
         prod.at(i - m_t + idx) += coef * prod.at(i);
      }
   }

   prod.erase(prod.begin() + m_t, prod.end());

   return Classic_McEliece_Polynomial(std::move(prod));
}

Classic_McEliece_Polynomial Classic_McEliece_Polynomial_Ring::create_element_from_bytes(
   std::span<const uint8_t> bytes) const {
   BOTAN_ARG_CHECK(bytes.size() == m_t * 2, "Correct input size");
   return create_element_from_coef(load_le<std::vector<CmceGfElem>>(bytes));
}

Classic_McEliece_Polynomial Classic_McEliece_Polynomial_Ring::create_element_from_coef(
   const std::vector<CmceGfElem>& coeff_vec) const {
   std::vector<Classic_McEliece_GF> coeff_vec_gf;
   CmceGfElem coeff_mask = CmceGfElem((uint16_t(1) << Classic_McEliece_GF::log_q_from_mod(m_poly_f)) - 1);
   std::transform(coeff_vec.begin(), coeff_vec.end(), std::back_inserter(coeff_vec_gf), [&](auto& coeff) {
      return Classic_McEliece_GF(coeff & coeff_mask, m_poly_f);
   });
   return Classic_McEliece_Polynomial(coeff_vec_gf);
}

bool operator==(const Classic_McEliece_Polynomial_Ring::Big_F_Coefficient& lhs,
                const Classic_McEliece_Polynomial_Ring::Big_F_Coefficient& rhs) {
   return lhs.coeff == rhs.coeff && lhs.idx == rhs.idx;
}

std::optional<Classic_McEliece_Minimal_Polynomial> Classic_McEliece_Polynomial_Ring::compute_minimal_polynomial(
   StrongSpan<const CmceIrreducibleBits> seed) const {
   auto polynomial = create_element_from_bytes(seed);
   std::vector<Classic_McEliece_Polynomial> mat;

   mat.push_back(create_element_from_coef(concat<std::vector<CmceGfElem>>(
      std::vector<CmceGfElem>{CmceGfElem(1)}, std::vector<CmceGfElem>(degree() - 1, CmceGfElem(0)))));

   mat.push_back(polynomial);

   for(size_t j = 2; j <= degree(); ++j) {
      mat.push_back(multiply(mat.at(j - 1), polynomial));
   }

   // Gaussian
   for(size_t j = 0; j < degree(); ++j) {
      for(size_t k = j + 1; k < degree(); ++k) {
         auto cond = GF_Mask::is_zero(mat.at(j).coef_at(j));

         for(size_t c = j; c < degree() + 1; ++c) {
            mat.at(c).coef_at(j) += cond.if_set_return(mat.at(c).coef_at(k));
         }
      }

      const bool is_zero_at_diagonal = mat.at(j).coef_at(j).is_zero();
      CT::unpoison(is_zero_at_diagonal);
      if(is_zero_at_diagonal) {
         // Fail if not systematic. New rejection sampling iteration starts.
         return std::nullopt;
      }

      auto inv = mat.at(j).coef_at(j).inv();

      for(size_t c = j; c < degree() + 1; ++c) {
         mat.at(c).coef_at(j) *= inv;
      }

      for(size_t k = 0; k < degree(); ++k) {
         if(k != j) {
            const auto t = mat.at(j).coef_at(k);

            for(size_t c = j; c < degree() + 1; ++c) {
               mat.at(c).coef_at(k) += mat.at(c).coef_at(j) * t;
            }
         }
      }
   }

   auto minimal_poly_coeffs = mat.at(degree()).coef();
   // Add coefficient 1 since polynomial is monic
   minimal_poly_coeffs.emplace_back(CmceGfElem(1), poly_f());

   return Classic_McEliece_Minimal_Polynomial(std::move(minimal_poly_coeffs));
}

secure_vector<uint8_t> Classic_McEliece_Minimal_Polynomial::serialize() const {
   BOTAN_ASSERT_NOMSG(!coef().empty());
   auto& all_coeffs = coef();
   // Store all except coef for monomial x^t since polynomial is monic (ISO Spec Section 9.2.9)
   auto coeffs_to_store = std::span(all_coeffs).first(all_coeffs.size() - 1);
   secure_vector<uint8_t> bytes(sizeof(uint16_t) * coeffs_to_store.size());
   BufferStuffer bytes_stuf(bytes);
   for(auto& coef : coeffs_to_store) {
      store_le(bytes_stuf.next<sizeof(CmceGfElem)>(), coef.elem().get());
   }
   BOTAN_ASSERT_NOMSG(bytes_stuf.full());
   return bytes;
}

Classic_McEliece_Minimal_Polynomial Classic_McEliece_Minimal_Polynomial::from_bytes(std::span<const uint8_t> bytes,
                                                                                    CmceGfMod poly_f) {
   BOTAN_ASSERT_NOMSG(bytes.size() % 2 == 0);
   const auto coef_vec = load_le<std::vector<CmceGfElem>>(bytes);
   std::vector<Classic_McEliece_GF> coeff_vec_gf;
   std::transform(coef_vec.begin(), coef_vec.end(), std::back_inserter(coeff_vec_gf), [poly_f](auto& coeff) {
      return Classic_McEliece_GF(coeff, poly_f);
   });

   coeff_vec_gf.emplace_back(CmceGfElem(1), poly_f);  // x^t as polynomial is monic

   return Classic_McEliece_Minimal_Polynomial(coeff_vec_gf);
}

}  // namespace Botan
