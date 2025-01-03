/*
 * Classic McEliece Parameters
 * (C) 2023 Jack Lloyd
 *     2023,2024 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_CMCE_PARAMS_H_
#define BOTAN_CMCE_PARAMS_H_

#include <botan/asn1_obj.h>
#include <botan/cmce_parameter_set.h>
#include <botan/hash.h>
#include <botan/xof.h>
#include <botan/internal/cmce_gf.h>
#include <botan/internal/cmce_poly.h>

#include <string_view>

namespace Botan {

struct Classic_McEliece_Big_F_Coefficient;
class Classic_McEliece_Polynomial_Ring;

/**
 * Container for all Classic McEliece parameters.
 */
class BOTAN_TEST_API Classic_McEliece_Parameters final {
   public:
      /**
       * @brief Create Classic McEliece parameters from a parameter set.
       */
      static Classic_McEliece_Parameters create(Classic_McEliece_Parameter_Set set);

      /**
       * @brief Create Classic McEliece parameters from a parameter set name.
       */
      static Classic_McEliece_Parameters create(std::string_view name);

      /**
       * @brief Create Classic McEliece parameters from an OID.
       */
      static Classic_McEliece_Parameters create(const OID& oid);

      /**
       * @brief The parameter set for this Classic McEliece instance.
       */
      Classic_McEliece_Parameter_Set parameter_set() const { return m_set; }

      /**
       * @brief The OID for the Classic McEliece instance.
       */
      OID object_identifier() const;

      /**
       * @returns true iff the instance is a plaintext confirmation (PC) instance.
       */
      bool is_pc() const {
         return (m_set == Classic_McEliece_Parameter_Set::ClassicMcEliece_6688128pc) ||
                (m_set == Classic_McEliece_Parameter_Set::ClassicMcEliece_6688128pcf) ||
                (m_set == Classic_McEliece_Parameter_Set::ClassicMcEliece_6960119pc) ||
                (m_set == Classic_McEliece_Parameter_Set::ClassicMcEliece_6960119pcf) ||
                (m_set == Classic_McEliece_Parameter_Set::ClassicMcEliece_8192128pc) ||
                (m_set == Classic_McEliece_Parameter_Set::ClassicMcEliece_8192128pcf);
      }

      /**
       * @returns true iff the instance is a fast (F) instance, i.e. if the semi-systematic
       * matrix creation is used.
`       */
      bool is_f() const {
         return (m_set == Classic_McEliece_Parameter_Set::ClassicMcEliece_348864f) ||
                (m_set == Classic_McEliece_Parameter_Set::ClassicMcEliece_460896f) ||
                (m_set == Classic_McEliece_Parameter_Set::ClassicMcEliece_6688128f) ||
                (m_set == Classic_McEliece_Parameter_Set::ClassicMcEliece_6688128pcf) ||
                (m_set == Classic_McEliece_Parameter_Set::ClassicMcEliece_6960119f) ||
                (m_set == Classic_McEliece_Parameter_Set::ClassicMcEliece_6960119pcf) ||
                (m_set == Classic_McEliece_Parameter_Set::ClassicMcEliece_8192128f) ||
                (m_set == Classic_McEliece_Parameter_Set::ClassicMcEliece_8192128pcf);
      }

      /**
       * @brief The degree of the Classic McEliece instance's underlying Galois Field, i.e. GF(q) = GF(2^m).
       */
      size_t m() const { return m_m; }

      /**
       * @brief The field size of the Classic McEliece instance's underlying Galois Field, i.e.
       * GF(q) is the underlying field.
       */
      size_t q() const { return (size_t(1) << m_m); }

      /**
       * @brief The code length of the Classic McEliece instance.
       *
       * E.g. the Classic McEliece matrix H is of size m*t x n,
       * the encoded error vector is, therefore, of size n.
       */
      size_t n() const { return m_n; }

      /**
       * @brief The weight of the error vector e.
       */
      size_t t() const { return m_poly_ring.degree(); }

      /**
       * @brief Bit output length of the hash function H.
       */
      static constexpr size_t ell() { return 256; }

      /**
       * @brief The number of bits each GF element is encoded with.
       */
      static constexpr size_t sigma1() { return 16; }

      /**
       * @brief Constant for field-ordering generation. (see Classic McEliece ISO 8.2)
       */
      static constexpr size_t sigma2() { return 32; }

      /**
       * @brief Constant mu for semi-systematic matrix creation. (see Classic McEliece ISO 7.2.3)
       */
      static constexpr size_t mu() { return 32; }

      /**
       * @brief Constant nu for semi-systematic matrix creation. (see Classic McEliece ISO 7.2.3)
       */
      static constexpr size_t nu() { return 64; }

      /**
       * @brief Constant tau for fixed-weight vector generation. (see Classic McEliece ISO 8.4)
       */
      size_t tau() const {
         // Section 8.4 of ISO:
         // The integer tau is defined as t if n=q; as 2t if q/2<=n<q; as 4t if q/4<=n<q/2; etc
         size_t tau_fact = size_t(1) << (m() - floor_log2(n()));
         return tau_fact * t();
      }

      /**
       * @brief The monic irreducible polynomial f(z) of degree m over GF(2). Used for modular
       * reduction in GF(2^m).
       */
      CmceGfMod poly_f() const { return m_poly_ring.poly_f(); }

      /**
       * @brief The estimated bit security strength of the Classic McEliece instance.
       *
       * Reference: Classic McEliece NIST Round 4 submission, Guide for security reviewers
       */
      size_t estimated_strength() const;

      /**
       * @brief The byte length of the seed delta. See ISO 9.2.12.
       */
      static constexpr size_t seed_len() { return ell() / 8; }

      /**
       * @brief The byte length of the column selection c. See ISO 9.2.12.
       */
      static constexpr size_t sk_c_bytes() { return 8; }

      /**
       * @brief The length of the byte representation of the minimal polynomial g. See ISO 9.2.12.
       */
      size_t sk_poly_g_bytes() const { return t() * sizeof(uint16_t); }

      /**
       * @brief The length of the byte representation of the field ordering's control bits. See ISO 9.2.12.
       */
      size_t sk_alpha_control_bytes() const { return (2 * m() - 1) * (size_t(1) << (m() - 4)); }

      /**
       * @brief The byte length of the seed s. s is used for implicit rejection. See ISO 9.2.12.
       */
      size_t sk_s_bytes() const { return n() / 8; }

      /**
       * @brief The byte length of the secret key sk. See ISO 9.2.12.
       */
      size_t sk_size_bytes() const {
         // ISO 9.2.12: sk = (delta, c, g, alpha(control bits), s)
         return seed_len() + sk_c_bytes() + sk_poly_g_bytes() + sk_alpha_control_bytes() + sk_s_bytes();
      }

      /**
       * @brief The number of rows in the public key's matrix.
       */
      size_t pk_no_rows() const { return t() * m(); }

      /**
       * @brief The number of columns in the public key's matrix.
       *
       * Note that this is only the column number of the submatrix T (with H = (I_mt | T)),
       * which is stored in the public key. The column number of the whole matrix H is n.
       * This constant is also denoted as k in the spec.
       */
      size_t pk_no_cols() const { return n() - pk_no_rows(); }

      /**
       * @brief The number of bytes for each row in the public key's matrix.
       */
      size_t pk_row_size_bytes() const { return (pk_no_cols() + 7) / 8; }

      /**
       * @brief The number of bytes for the public key.
       *
       * Equal to the byte size of the CMCE matrix.
       */
      size_t pk_size_bytes() const { return pk_no_rows() * pk_row_size_bytes(); }

      /**
       * @brief The output byte size of the encoding algorithm. See ISO 7.3
       */
      size_t encode_out_size() const { return ceil_division<size_t>(m() * t(), 8); }

      /**
       * @brief The byte size of the hash output.
       *
       * This is also the size of the shared key K that is a hash output.
       */
      static constexpr size_t hash_out_bytes() { return ell() / 8; }

      /**
       * @brief The byte size of the ciphertext.
       */
      size_t ciphertext_size() const {
         if(is_pc()) {
            // C_0 + C_1
            return encode_out_size() + hash_out_bytes();
         } else {
            return encode_out_size();
         }
      }

      /**
       * @brief The underlying polynomial ring.
       */
      const Classic_McEliece_Polynomial_Ring& poly_ring() const { return m_poly_ring; }

      /**
       * @brief Create a seeded XOF object representing Classic McEliece's PRG.
       * See Classic McEliece ISO 9.1.
       *
       * @param seed The seed used for the XOF.
       */
      std::unique_ptr<XOF> prg(std::span<const uint8_t> seed) const;

      /**
       * @brief Create an instance of the hash function Hash(x) used in Classic McEliece's
       * Decaps and Encaps algorithms.
       *
       * @return a new instance of the hash function.
       */
      std::unique_ptr<HashFunction> hash_func() const { return HashFunction::create_or_throw("SHAKE-256(256)"); }

      /**
       * @brief Create a GF(q) element using the modulus for the current instance.
       *
       * @param elem The GF(q) element value.
       * @return The GF(q) element.
       */
      Classic_McEliece_GF gf(CmceGfElem elem) const { return Classic_McEliece_GF(elem, poly_f()); }

   private:
      Classic_McEliece_Parameters(Classic_McEliece_Parameter_Set param_set,
                                  size_t m,
                                  size_t n,
                                  Classic_McEliece_Polynomial_Ring poly_ring);

      Classic_McEliece_Parameter_Set m_set;
      size_t m_m;
      size_t m_n;
      Classic_McEliece_Polynomial_Ring m_poly_ring;
};

}  // namespace Botan

#endif
