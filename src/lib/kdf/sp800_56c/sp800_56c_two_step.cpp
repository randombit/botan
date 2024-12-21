/*
* Two-Step KDF defined in NIST SP 800-56Cr2 (Section 5)
* (C) 2016 Kai Michaelis
* (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
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

void SP800_56C_Two_Step::perform_kdf(std::span<uint8_t> key,
                                     std::span<const uint8_t> secret,
                                     std::span<const uint8_t> salt,
                                     std::span<const uint8_t> label) const {
   // Randomness Extraction
   m_prf->set_key(salt);
   m_prf->update(secret);
   const auto k_dk = m_prf->final();

   // Key Expansion
   m_exp->derive_key(key, k_dk, {} /* no salt */, label);
}

}  // namespace Botan
