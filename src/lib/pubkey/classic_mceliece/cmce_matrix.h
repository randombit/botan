/*
 * Classic McEliece Matrix Logic
 *
 * (C) 2023 Jack Lloyd
 *     2023,2024 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_CMCE_MATRIX_H_
#define BOTAN_CMCE_MATRIX_H_

#include <botan/internal/bitvector.h>
#include <botan/internal/cmce_field_ordering.h>
#include <botan/internal/cmce_parameters.h>
#include <botan/internal/cmce_poly.h>
#include <botan/internal/cmce_types.h>

namespace Botan {

/**
 * @brief Representation of the binary Classic McEliece matrix H, with H = (I_mt | T).
 *
 * Only the bytes of the submatrix T are stored.
 */
class BOTAN_TEST_API Classic_McEliece_Matrix {
   public:
      /**
       * @brief Create the matrix H for a Classic McEliece instance given its
       * parameters, field ordering and minimal polynomial.
       *
       * Output is a pair of the matrix and the pivot vector c that was used to
       * create it in the semi-systematic form as described in Classic McEliece ISO
       * Section 9.2.11.
       *
       * The update of alpha values as per Classic McEliece ISO Section 7.2.3 Step 5
       * is not performed by this method because it is only used for public key loading
       * where the values are already permuted and field_ordering cannot be altered.
       *
       * @param params Classic McEliece parameters
       * @param field_ordering Field ordering
       * @param g Minimal polynomial
       * @return Pair(the matrix H, pivot vector c)
       */
      static std::optional<std::pair<Classic_McEliece_Matrix, CmceColumnSelection>> create_matrix(
         const Classic_McEliece_Parameters& params,
         const Classic_McEliece_Field_Ordering& field_ordering,
         const Classic_McEliece_Minimal_Polynomial& g);

      /**
       * @brief Create the matrix H for a Classic McEliece instance given its
       * parameters, field ordering and minimal polynomial.
       *
       * Output is a pair of the matrix and the pivot vector c that was used to
       * create it in the semi-systematic form as described in Classic McEliece ISO
       * Section 9.2.11.
       *
       * This method directly updates the field ordering values as described in Classic McEliece
       * ISO Section 7.2.3 Step 5 (for f parameter sets).
       *
       * @param params Classic McEliece parameters
       * @param field_ordering Field ordering (will be updated)
       * @param g Minimal polynomial
       * @return Pair(the matrix H, pivot vector c)
       */
      static std::optional<std::pair<Classic_McEliece_Matrix, CmceColumnSelection>> create_matrix_and_apply_pivots(
         const Classic_McEliece_Parameters& params,
         Classic_McEliece_Field_Ordering& field_ordering,
         const Classic_McEliece_Minimal_Polynomial& g);

      /**
       * @brief The bytes of the submatrix T, with H=(I_mt, T) as defined in Classic
       * McEliece ISO Section 9.2.7.
       *
       * @return The matrix bytes
       */
      const std::vector<uint8_t>& bytes() const { return m_mat_bytes; }

      /**
       * @brief Create a Classic_McEliece_Matrix from bytes.
       *
       * @param mat_bytes The bytes of the submatrix T as defined in Classic McEliece ISO Section 9.2.7.
       */
      Classic_McEliece_Matrix(const Classic_McEliece_Parameters& params, std::vector<uint8_t> mat_bytes) :
            m_mat_bytes(std::move(mat_bytes)) {
         BOTAN_ARG_CHECK(m_mat_bytes.size() == params.pk_size_bytes(), "Invalid byte size for matrix");
         if(params.pk_no_cols() % 8 == 0) {
            return;
         }
         // Check padding of mat_bytes rows
         BOTAN_ASSERT_NOMSG(m_mat_bytes.size() == params.pk_no_rows() * params.pk_row_size_bytes());
         for(size_t row = 0; row < params.pk_no_rows(); ++row) {
            uint8_t padded_byte = m_mat_bytes[(row + 1) * params.pk_row_size_bytes() - 1];
            CT::unpoison(padded_byte);
            BOTAN_ARG_CHECK(padded_byte >> (params.pk_no_cols() % 8) == 0, "Valid padding of unused bytes");
         }
      }

      /**
       * @brief Multiply the Classic McEliece matrix H with a bitvector e.
       *
       * @param params Classic McEliece parameters
       * @param e The bitvector e
       * @return H*e
       */
      CmceCodeWord mul(const Classic_McEliece_Parameters& params, const CmceErrorVector& e) const;

      constexpr void _const_time_unpoison() const { CT::unpoison(m_mat_bytes); }

   private:
      /// The bytes of the submatrix T
      const std::vector<uint8_t> m_mat_bytes;  // can we use bitvector?
};

}  // namespace Botan

#endif  // BOTAN_CMCE_MATRIX_H_
