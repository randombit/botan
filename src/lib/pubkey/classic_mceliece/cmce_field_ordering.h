/*
 * Classic McEliece Field Ordering Generation
 * (C) 2023 Jack Lloyd
 *     2023,2024 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_CMCE_FIELD_ORDERING_H_
#define BOTAN_CMCE_FIELD_ORDERING_H_

#include <botan/internal/cmce_parameters.h>
#include <botan/internal/cmce_types.h>

#include <numeric>

namespace Botan {

/**
 * @brief Represents a field ordering for the Classic McEliece cryptosystem.
 *
 * Field ordering corresponds to the permutation pi defining the alpha sequence in
 * the Classic McEliece specification (see Classic McEliece ISO Sec. 8.2.).
 */
class BOTAN_TEST_API Classic_McEliece_Field_Ordering {
   public:
      /**
       * @brief Creates a field ordering from a random bit sequence. Corresponds to
       *        the algorithm described in Classic McEliece ISO Sec. 8.2.
       *
       * @param params The McEliece parameters.
       * @param random_bits The random bit sequence.
       * @return The field ordering.
       */
      static std::optional<Classic_McEliece_Field_Ordering> create_field_ordering(
         const Classic_McEliece_Parameters& params, StrongSpan<const CmceOrderingBits> random_bits);

      /**
       * @brief Create the field ordering from the control bits of a benes network.
       *
       * @param params The McEliece parameters.
       * @param control_bits The control bits of the benes network.
       * @return The field ordering.
       */
      static Classic_McEliece_Field_Ordering create_from_control_bits(const Classic_McEliece_Parameters& params,
                                                                      const secure_bitvector& control_bits);

      /**
       * @brief Returns the field ordering as a vector of all alphas from alpha_0 to alpha_{n-1}.
       *
       * @param n The number of alphas to return.
       * @return the vector of n alphas.
       */
      std::vector<Classic_McEliece_GF> alphas(size_t n) const;

      /**
       * @brief Generates the control bits of the benes network corresponding to the field ordering.
       *
       * @return the control bits.
       */
      secure_bitvector alphas_control_bits() const;

      /**
       * @brief The pi values representing the field ordering.
       *
       * @return pi values.
       */
      CmcePermutation& pi_ref() { return m_pi; }

      /**
       * @brief The pi values representing the field ordering.
       *
       * @return pi values.
       */
      const CmcePermutation& pi_ref() const { return m_pi; }

      /**
       * @brief Constant time comparison of two field orderings.
       *
       * @param other The other field ordering.
       * @return Mask of equality value
       */
      CT::Mask<uint16_t> ct_is_equal(const Classic_McEliece_Field_Ordering& other) const {
         BOTAN_ARG_CHECK(other.pi_ref().size() == pi_ref().size(), "Field orderings must have the same size");
         return CT::is_equal(pi_ref().data(), other.pi_ref().data(), pi_ref().size());
      }

      /**
       * @brief Permute the field ordering with the given pivots.
       *
       * For example: If the pivot vector is 10101, the first, third and fifth element of the field ordering
       * are permuted to positions 0, 1 and 2, respectively. The remaining elements are put at the end.
       *
       * The permutation is done for the elements from position m*t - mu,..., m*t + mu (excl.).
       * This function implements Classic McEliece ISO Sec. 7.2.3 Steps 4-5.
       *
       * @param params The McEliece parameters.
       * @param pivots The pivot vector.
       */
      void permute_with_pivots(const Classic_McEliece_Parameters& params, const CmceColumnSelection& pivots);

      void _const_time_poison() const { CT::poison(m_pi); }

      void _const_time_unpoison() const { CT::unpoison(m_pi); }

   private:
      Classic_McEliece_Field_Ordering(CmcePermutation pi, CmceGfMod poly_f) : m_pi(std::move(pi)), m_poly_f(poly_f) {}

   private:
      CmcePermutation m_pi;
      CmceGfMod m_poly_f;
};

}  // namespace Botan

#endif
