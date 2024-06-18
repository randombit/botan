/*
* Two-Step KDF defined in NIST SP 800-56Cr2 (Section 5)
* (C) 2016 Kai Michaelis
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sp800_56c_two_step.h>

#include <botan/internal/fmt.h>

namespace Botan {

std::string SP800_56C_Two_Step::name() const {
   return fmt("SP800-56C({})", m_prf->name());
}

std::unique_ptr<KDF> SP800_56C_Two_Step::new_object() const {
   return std::make_unique<SP800_56C_Two_Step>(m_prf->new_object(), m_exp->new_object());
}

void SP800_56C_Two_Step::kdf(uint8_t key[],
                             size_t key_len,
                             const uint8_t secret[],
                             size_t secret_len,
                             const uint8_t salt[],
                             size_t salt_len,
                             const uint8_t label[],
                             size_t label_len) const {
   // Randomness Extraction
   secure_vector<uint8_t> k_dk;

   m_prf->set_key(salt, salt_len);
   m_prf->update(secret, secret_len);
   m_prf->final(k_dk);

   // Key Expansion
   m_exp->kdf(key, key_len, k_dk.data(), k_dk.size(), nullptr, 0, label, label_len);
}

}  // namespace Botan
