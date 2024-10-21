/*
 * Classic McEliece key generation with Internal Private and Public Key classes
 * (C) 2023 Jack Lloyd
 *     2023,2024 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_CMCE_KEYS_INTERNAL_H_
#define BOTAN_CMCE_KEYS_INTERNAL_H_

#include <botan/internal/cmce_field_ordering.h>
#include <botan/internal/cmce_matrix.h>
#include <botan/internal/cmce_parameters.h>
#include <botan/internal/cmce_poly.h>
#include <botan/internal/cmce_types.h>

namespace Botan {

class Classic_McEliece_PrivateKeyInternal;

/**
 * @brief Representation of a Classic McEliece public key.
 *
 * This class represents a Classic McEliece public key. It is used internally by the Classic McEliece
 * public key class and contains the following data:
 * - The Classic McEliece parameters
 * - The public key matrix
 */
class BOTAN_TEST_API Classic_McEliece_PublicKeyInternal {
   public:
      /**
       * @brief Construct a Classic McEliece public key.
       *
       * @param params The Classic McEliece parameters
       * @param matrix The public key matrix
       */
      Classic_McEliece_PublicKeyInternal(const Classic_McEliece_Parameters& params, Classic_McEliece_Matrix matrix) :
            m_params(params), m_matrix(std::move(matrix)) {
         BOTAN_ASSERT_NOMSG(m_matrix.bytes().size() == m_params.pk_size_bytes());
      }

      /**
       * @brief Create a Classic McEliece public key from a private key.
       *
       * Create the matrix from the private key values. Expects that the private key is valid, i.e.
       * the matrix creation works.
       *
       * @param sk The private key
       * @return The public key as a shared pointer
       */
      static std::shared_ptr<Classic_McEliece_PublicKeyInternal> create_from_private_key(
         const Classic_McEliece_PrivateKeyInternal& sk);

      /**
       * @brief Serializes the Classic McEliece public key as defined in Classic McEliece ISO Section 9.2.7.
       */
      std::vector<uint8_t> serialize() const { return m_matrix.bytes(); }

      /**
       * @brief The Classic McEliece matrix.
       */
      const Classic_McEliece_Matrix& matrix() const { return m_matrix; }

      /**
       * @brief The Classic McEliece parameters.
       */
      const Classic_McEliece_Parameters& params() const { return m_params; }

      constexpr void _const_time_unpoison() const { CT::unpoison(m_matrix); }

   private:
      Classic_McEliece_Parameters m_params;
      Classic_McEliece_Matrix m_matrix;
};

/**
 * @brief Representation of a Classic McEliece private key.
 *
 * This class represents a Classic McEliece private key. It is used internally by the Classic McEliece
 * private key class and contains the following data (see Classic McEliece ISO Section 9.2.12):
 * - The Classic McEliece parameters
 * - The seed delta
 * - The column selection pivot vector c
 * - The minimal polynomial g
 * - The field ordering alpha
 * - The seed s for implicit rejection
 */
class BOTAN_TEST_API Classic_McEliece_PrivateKeyInternal {
   public:
      /**
       * @brief Construct a Classic McEliece private key.
       *
       * @param params The Classic McEliece parameters
       * @param delta The seed delta
       * @param c The column selection pivot vector c
       * @param g The minimal polynomial g
       * @param alpha The field ordering alpha
       * @param s The seed s for implicit rejection
       */
      Classic_McEliece_PrivateKeyInternal(const Classic_McEliece_Parameters& params,
                                          CmceKeyGenSeed delta,
                                          CmceColumnSelection c,
                                          Classic_McEliece_Minimal_Polynomial g,
                                          Classic_McEliece_Field_Ordering alpha,
                                          CmceRejectionSeed s) :
            m_params(params),
            m_delta(std::move(delta)),
            m_c(std::move(c)),
            m_g(std::move(g)),
            m_field_ordering(std::move(alpha)),
            m_s(std::move(s)) {}

      /**
       * @brief Parses a Classic McEliece private key from a byte sequence.
       *
       * It also creates the field ordering from the control bits in @p sk_bytes.
       *
       * @param params The Classic McEliece parameters
       * @param sk_bytes The secret key byte sequence
       * @return the Classic McEliece private key
       */
      static Classic_McEliece_PrivateKeyInternal from_bytes(const Classic_McEliece_Parameters& params,
                                                            std::span<const uint8_t> sk_bytes);

      /**
       * @brief Serializes the Classic McEliece private key as defined in Classic McEliece ISO Section 9.2.12.
       *
       * @return the serialized Classic McEliece private key
       */
      secure_vector<uint8_t> serialize() const;

      /**
       * @brief The seed delta that was used to create the private key.
       */
      const CmceKeyGenSeed& delta() const { return m_delta; }

      /**
       * @brief The column selection pivot vector c as defined in Classic McEliece ISO Section 9.2.11.
       */
      const CmceColumnSelection& c() const { return m_c; }

      /**
       * @brief The minimal polynomial g.
       */
      const Classic_McEliece_Minimal_Polynomial& g() const { return m_g; }

      /**
       * @brief The field ordering alpha.
       */
      const Classic_McEliece_Field_Ordering& field_ordering() const { return m_field_ordering; }

      /**
       * @brief The seed s for implicit rejection on decryption failure.
       */
      const CmceRejectionSeed& s() const { return m_s; }

      /**
       * @brief The Classic McEliece parameters.
       */
      const Classic_McEliece_Parameters& params() const { return m_params; }

      /**
       * @brief Checks the private key for consistency with the first component delta, i.e.,
       * recomputes s as a hash of delta and checks equivalence with sk.s, checks the weight of c,
       * and checks the control bits. It also recomputes beta based on delta and recomputes g based on beta,
       * checking that g is equal to the value sk.s
       *
       * See NIST Impl. guide 6.3 Double-Checks on Private Keys.
       */
      bool check_key() const;

      constexpr void _const_time_poison() const { CT::poison_all(m_delta, m_c, m_g, m_field_ordering, m_s); }

      constexpr void _const_time_unpoison() const { CT::unpoison_all(m_delta, m_c, m_g, m_field_ordering, m_s); }

   private:
      Classic_McEliece_Parameters m_params;
      CmceKeyGenSeed m_delta;
      CmceColumnSelection m_c;
      Classic_McEliece_Minimal_Polynomial m_g;
      Classic_McEliece_Field_Ordering m_field_ordering;
      CmceRejectionSeed m_s;
};

/**
 * @brief Representation of a Classic McEliece key pair.
 */
struct BOTAN_TEST_API Classic_McEliece_KeyPair_Internal {
      std::shared_ptr<Classic_McEliece_PrivateKeyInternal> private_key;
      std::shared_ptr<Classic_McEliece_PublicKeyInternal> public_key;

      /**
       * @brief Generate a Classic McEliece key pair using the algorithm described
       * in Classic McEliece ISO Section 8.3
       */
      static Classic_McEliece_KeyPair_Internal generate(const Classic_McEliece_Parameters& params,
                                                        StrongSpan<const CmceInitialSeed> seed);

      /**
       * @brief Decompose the key pair into a pair of shared pointers to the private and public key.
       */
      std::pair<std::shared_ptr<Classic_McEliece_PrivateKeyInternal>,
                std::shared_ptr<Classic_McEliece_PublicKeyInternal>>
      decompose_to_pair() && {
         return {std::move(private_key), std::move(public_key)};
      }
};

}  // namespace Botan

#endif  // BOTAN_CMCE_KEYS_INTERNAL_H_
