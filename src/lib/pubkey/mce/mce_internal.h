/*
 * (C) Copyright Projet SECRET, INRIA, Rocquencourt
 * (C) Bhaskar Biswas and  Nicolas Sendrier
 *
 * (C) 2014 cryptosource GmbH
 * (C) 2014 Falko Strenzke fstrenzke@cryptosource.de
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 *
 */

#ifndef BOTAN_MCELIECE_INTERNAL_H_
#define BOTAN_MCELIECE_INTERNAL_H_

#include <botan/mceliece.h>
#include <botan/pk_ops.h>
#include <botan/internal/polyn_gf2m.h>

namespace Botan {

class McEliece_PublicKeyInternal final {
   public:
      McEliece_PublicKeyInternal(std::vector<uint8_t> public_matrix, size_t t, size_t code_length) :
            m_public_matrix(std::move(public_matrix)), m_t(t), m_code_length(code_length) {}

      const std::vector<uint8_t>& public_matrix() const { return m_public_matrix; }

      size_t t() const { return m_t; }

      size_t code_length() const { return m_code_length; }

      size_t message_word_bit_length() const;

      secure_vector<uint8_t> random_plaintext_element(RandomNumberGenerator& rng) const;

   private:
      std::vector<uint8_t> m_public_matrix;
      size_t m_t;
      size_t m_code_length;
};

class McEliece_PrivateKeyInternal final {
   public:
      McEliece_PrivateKeyInternal(std::vector<polyn_gf2m> g,
                                  std::vector<polyn_gf2m> sqrtmod,
                                  std::vector<gf2m> support_inverse,
                                  std::vector<uint32_t> parity_check_coeffs,
                                  size_t codimension,
                                  size_t dimension) :
            m_g(std::move(g)),
            m_sqrtmod(std::move(sqrtmod)),
            m_Linv(std::move(support_inverse)),
            m_coeffs(std::move(parity_check_coeffs)),
            m_codimension(codimension),
            m_dimension(dimension) {}

      const polyn_gf2m& goppa_polyn() const { return m_g[0]; }

      const std::vector<polyn_gf2m>& goppa_polyn_vec() const { return m_g; }

      const std::vector<polyn_gf2m>& sqrtmod() const { return m_sqrtmod; }

      const std::vector<gf2m>& Linv() const { return m_Linv; }

      const std::vector<uint32_t>& H_coeffs() const { return m_coeffs; }

      size_t codimension() const { return m_codimension; }

      size_t dimension() const { return m_dimension; }

      size_t code_length() const { return m_dimension + m_codimension; }

      size_t message_word_bit_length() const { return m_dimension; }

   private:
      std::vector<polyn_gf2m> m_g;  // single element
      std::vector<polyn_gf2m> m_sqrtmod;
      std::vector<gf2m> m_Linv;
      std::vector<uint32_t> m_coeffs;
      size_t m_codimension;
      size_t m_dimension;
};

void mceliece_decrypt(secure_vector<uint8_t>& plaintext_out,
                      secure_vector<uint8_t>& error_mask_out,
                      const uint8_t ciphertext[],
                      size_t ciphertext_len,
                      const McEliece_PrivateKeyInternal& key);

void mceliece_decrypt(secure_vector<uint8_t>& plaintext_out,
                      secure_vector<uint8_t>& error_mask_out,
                      const secure_vector<uint8_t>& ciphertext,
                      const McEliece_PrivateKeyInternal& key);

secure_vector<uint8_t> mceliece_decrypt(secure_vector<gf2m>& error_pos,
                                        const uint8_t* ciphertext,
                                        size_t ciphertext_len,
                                        const McEliece_PrivateKeyInternal& key);

void mceliece_encrypt(secure_vector<uint8_t>& ciphertext_out,
                      secure_vector<uint8_t>& error_mask_out,
                      const secure_vector<uint8_t>& plaintext,
                      const McEliece_PublicKeyInternal& key,
                      RandomNumberGenerator& rng);

McEliece_PrivateKey generate_mceliece_key(RandomNumberGenerator& rng, size_t ext_deg, size_t code_length, size_t t);

}  // namespace Botan

#endif
