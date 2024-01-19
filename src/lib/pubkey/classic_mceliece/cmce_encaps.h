/*
* Classic McEliece Encapsulation
* (C) 2023 Jack Lloyd
*     2023,2024 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
**/

#ifndef BOTAN_CMCE_ENCAPS_H_
#define BOTAN_CMCE_ENCAPS_H_

#include <botan/cmce.h>
#include <botan/pk_keys.h>
#include <botan/pk_ops.h>
#include <botan/internal/cmce_field_ordering.h>
#include <botan/internal/cmce_keys_internal.h>
#include <botan/internal/cmce_matrix.h>
#include <botan/internal/cmce_parameters.h>
#include <botan/internal/cmce_poly.h>
#include <botan/internal/cmce_types.h>
#include <botan/internal/pk_ops_impl.h>

namespace Botan {

/**
 * Classic McEliece Encapsulation Operation
 */
class BOTAN_TEST_API Classic_McEliece_Encryptor final : public PK_Ops::KEM_Encryption_with_KDF {
   public:
      Classic_McEliece_Encryptor(std::shared_ptr<Classic_McEliece_PublicKeyInternal> key, std::string_view kdf) :
            KEM_Encryption_with_KDF(kdf), m_key(std::move(key)) {}

      size_t raw_kem_shared_key_length() const override { return m_key->params().hash_out_bytes(); }

      size_t encapsulated_key_length() const override { return m_key->params().ciphertext_size(); }

      void raw_kem_encrypt(std::span<uint8_t> out_encapsulated_key,
                           std::span<uint8_t> out_shared_key,
                           RandomNumberGenerator& rng) override;

   private:
      std::shared_ptr<Classic_McEliece_PublicKeyInternal> m_key;

      /**
       * @brief Encodes an error vector by multiplying it with the Classic McEliece matrix.
       */
      CmceCodeWord encode(const Classic_McEliece_Parameters& params,
                          const CmceErrorVector& e,
                          const Classic_McEliece_Matrix& mat) const;

      /**
      * @brief Fixed-weight-vector generation algorithm according to ISO McEliece.
      */
      std::optional<CmceErrorVector> fixed_weight_vector_gen(const Classic_McEliece_Parameters& params,
                                                             RandomNumberGenerator& rng) const;
};

}  // namespace Botan

#endif  // BOTAN_CMCE_ENCAPS_H_
