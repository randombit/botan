/*
 * Classic McEliece Decapsulation
 * (C) 2023 Jack Lloyd
 *     2023,2024 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_CMCE_DECAPS_H_
#define BOTAN_CMCE_DECAPS_H_

#include <botan/cmce.h>
#include <botan/pk_ops.h>
#include <botan/rng.h>
#include <botan/internal/bitvector.h>
#include <botan/internal/cmce_field_ordering.h>
#include <botan/internal/cmce_keys_internal.h>
#include <botan/internal/cmce_matrix.h>
#include <botan/internal/cmce_types.h>
#include <botan/internal/pk_ops_impl.h>

namespace Botan {

/**
 * Classic McEliece Decapsulation Operation
 */
class BOTAN_TEST_API Classic_McEliece_Decryptor final : public PK_Ops::KEM_Decryption_with_KDF {
   public:
      /**
       * @brief Constructs a Classic_McEliece_Decryptor object with the given private key.
       * @param key The private key used for decryption.
       */
      Classic_McEliece_Decryptor(std::shared_ptr<Classic_McEliece_PrivateKeyInternal> key, std::string_view kdf) :
            KEM_Decryption_with_KDF(kdf), m_key(std::move(key)) {}

      size_t raw_kem_shared_key_length() const override { return m_key->params().hash_out_bytes(); }

      size_t encapsulated_key_length() const override { return m_key->params().ciphertext_size(); }

      void raw_kem_decrypt(std::span<uint8_t> out_shared_key, std::span<const uint8_t> encapsulated_key) override;

   private:
      /**
       * @brief Computes the syndrome of a code word.
       *
       * Corresponds to H' * code_word of the spec, where H' is the syndrome computation matrix used for the
       * Berlekamp's method of decoding. See https://tungchou.github.io/papers/mcbits.pdf for more information.
       *
       * @param params The McEliece parameters.
       * @param goppa_poly The Goppa polynomial.
       * @param ordering The field ordering.
       * @param code_word The code word.
       * @return The syndrome S(x) of the code word.
       */
      Classic_McEliece_Polynomial compute_goppa_syndrome(const Classic_McEliece_Parameters& params,
                                                         const Classic_McEliece_Minimal_Polynomial& goppa_poly,
                                                         const Classic_McEliece_Field_Ordering& ordering,
                                                         const secure_bitvector& code_word) const;

      /**
       * @brief Applies the Berlekamp-Massey algorithm to compute the error locator polynomial given a syndrome.
       *
       * The error locator polynomial C can be used for decoding, as C(a_i) = 0 <=> error at position i.
       *
       * @param params The McEliece parameters.
       * @param syndrome The syndrome polynomial of the code word.
       * @return The error locator polynomial.
       */
      Classic_McEliece_Polynomial berlekamp_massey(const Classic_McEliece_Parameters& params,
                                                   const Classic_McEliece_Polynomial& syndrome) const;

      /**
       * @brief Decodes a code word using Berlekamp's method.
       *
       * @param big_c The code word.
       * @return A pair containing the decoded message and the error pattern.
       */
      std::pair<CT::Mask<uint8_t>, CmceErrorVector> decode(CmceCodeWord big_c) const;

      std::shared_ptr<Classic_McEliece_PrivateKeyInternal> m_key;
};

}  // namespace Botan

#endif  // BOTAN_CMCE_DECAPS_H_
