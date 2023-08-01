/*
 * FrodoKEM matrix logic
 * Based on the MIT licensed reference implementation by the designers
 * (https://github.com/microsoft/PQCrypto-LWEKE/tree/master/src)
 *
 * The Fellowship of the FrodoKEM:
 * (C) 2023 Jack Lloyd
 *     2023 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_FRODOKEM_MATRIX_H_
#define BOTAN_FRODOKEM_MATRIX_H_

#include <botan/internal/ct_utils.h>
#include <botan/internal/frodo_constants.h>
#include <botan/internal/frodo_types.h>

#include <functional>
#include <tuple>
#include <utility>
#include <vector>

namespace Botan {

class FrodoMatrix {
   public:
      using Dimensions = std::tuple<size_t, size_t>;

      explicit FrodoMatrix(Dimensions dims);

      uint16_t elements_at(size_t i) const { return m_elements.at(i); }

      size_t packed_size(const FrodoKEMConstants& constants) const {
         const size_t lsb = constants.d();
         const size_t inlen = element_count();
         BOTAN_ASSERT_NOMSG((lsb * inlen) % 8 == 0);
         return lsb * inlen / 8;  // in bytes
      }

      FrodoPackedMatrix pack(const FrodoKEMConstants& constants) const {
         FrodoPackedMatrix out(packed_size(constants));
         pack(constants, out);
         return out;
      }

      // Pack m_elements into a output buffer, copying lsb = D = log2 q bits from each input element.
      // Section 7.3 of spec
      void pack(const FrodoKEMConstants& constants, StrongSpan<FrodoPackedMatrix> out) const;

      FrodoSerializedMatrix serialize() const;

      FrodoPlaintext decode(const FrodoKEMConstants& constants) const;

      // Unpack the input FrodoPackedMatrix into the 16 bit m_elements vector, copying d bits
      // for each output element from input. outlen must be at least ceil(inlen * 8 / d).
      // m_elements is allocated here.
      static FrodoMatrix unpack(const FrodoKEMConstants& constants,
                                const Dimensions& dimensions,
                                StrongSpan<const FrodoPackedMatrix> packed_bytes);

      static FrodoMatrix deserialize(const Dimensions& dimensions, StrongSpan<const FrodoSerializedMatrix> bytes);

      static FrodoMatrix encode(const FrodoKEMConstants& constants,
                                StrongSpan<const FrodoPlaintext> in);  // Section 7.2 of spec

      // Creates a matrix with n samples from the noise distribution which requires 16 bits to sample.
      // The distribution is specified by its CDF.
      // Input: pseudo-random values (2*n bytes) passed in r.
      // Section 7.5 of spec
      static FrodoMatrix sample(const FrodoKEMConstants& constants,
                                const Dimensions& dimensions,
                                StrongSpan<const FrodoSampleR> r);

      // Helper function that calls FrodoMatrix::sample on initially provided consts and shake XOF.
      // The output function calls shake.output at each invocation.
      static std::function<FrodoMatrix(const Dimensions& dimensions)> make_sample_generator(
         const FrodoKEMConstants& constants, Botan::XOF& shake);

      // Generate-and-multiply: generate matrix A (N x N) row-wise, multiply by s on the right.
      // Inputs: s^T (N_BAR x N), e (N x N_BAR), seed for matrix A
      // Output: The elements of the FrodoMatrix will correspond to A*s + e (N x N_BAR).
      static FrodoMatrix mul_add_as_plus_e(const FrodoKEMConstants& constants,
                                           const FrodoMatrix& s,
                                           const FrodoMatrix& e,
                                           StrongSpan<const FrodoSeedA> seed_a);

      // Generate-and-multiply: generate matrix A (N x N) column-wise, multiply by s' on the left.
      // Inputs: s', e' (N_BAR x N)
      // Output: out = s'*A + e' (N_BAR x N)
      // The matrix multiplication uses the row-wise blocking and packing (RWCF) approach described in: J.W. Bos, M. Ofner, J. Renes,
      // T. Schneider, C. van Vredendaal, "The Matrix Reloaded: Multiplication Strategies in FrodoKEM". https://eprint.iacr.org/2021/711
      static FrodoMatrix mul_add_sa_plus_e(const FrodoKEMConstants& constants,
                                           const FrodoMatrix& s,
                                           const FrodoMatrix& e,
                                           StrongSpan<const FrodoSeedA> seed_a);

      // Multiply by s on the left
      // Inputs: b (N x N_BAR), s (N_BAR x N), e (N_BAR x N_BAR)
      // Output: out = s*b + e (N_BAR x N_BAR). The existing elements are overwritten and a self reference is returned.
      static FrodoMatrix mul_add_sb_plus_e(const FrodoKEMConstants& constants,
                                           const FrodoMatrix& b,
                                           const FrodoMatrix& s,
                                           const FrodoMatrix& e);

      // Multiply by s on the right
      // Inputs: b (N_BAR x N), s^T (N_BAR x N)
      // Output: out = b*s (N_BAR x N_BAR)
      static FrodoMatrix mul_bs(const FrodoKEMConstants& constants, const FrodoMatrix& b_p, const FrodoMatrix& s);

      // Add a and b
      // Inputs: a, b (N_BAR x N_BAR)
      // Output: c = a + b
      static FrodoMatrix add(const FrodoKEMConstants& constants, const FrodoMatrix& a, const FrodoMatrix& b);

      // Subtract a and b
      // Inputs: a, b (N_BAR x N_BAR)
      // Output: c = a - b
      static FrodoMatrix sub(const FrodoKEMConstants& constants, const FrodoMatrix& a, const FrodoMatrix& b);

      Dimensions dimensions() const { return {m_dim1, m_dim2}; }

      CT::Mask<uint8_t> constant_time_compare(const FrodoMatrix& other) const;

      size_t element_count() const { return m_elements.size(); }

      void reduce(const FrodoKEMConstants& constants);

   private:
      FrodoMatrix(const Dimensions& dimensions, secure_vector<uint16_t> elements) :
            m_dim1(std::get<0>(dimensions)), m_dim2(std::get<1>(dimensions)), m_elements(std::move(elements)) {}

   private:
      size_t m_dim1;
      size_t m_dim2;

      secure_vector<uint16_t> m_elements;
};

}  // namespace Botan

#endif
