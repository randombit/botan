/*
* TLSv1.2 PRF
* (C) 2004-2010 Jack Lloyd
* (C) 2024      René Meusel, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/prf_tls.h>

#include <botan/exceptn.h>
#include <botan/internal/fmt.h>
#include <botan/internal/stl_util.h>

namespace Botan {

/*
* TLS PRF P_hash function
*/
void TLS_12_PRF::perform_kdf(std::span<uint8_t> key,
                             std::span<const uint8_t> secret,
                             std::span<const uint8_t> salt,
                             std::span<const uint8_t> label) const {
   try {
      m_mac->set_key(secret);
   } catch(Invalid_Key_Length&) {
      throw Internal_Error(fmt("The premaster secret of {} bytes is too long for TLS-PRF", secret.size()));
   }

   auto A = concat<secure_vector<uint8_t>>(label, salt);
   secure_vector<uint8_t> h;

   BufferStuffer o(key);
   while(!o.full()) {
      A = m_mac->process(A);

      m_mac->update(A);
      m_mac->update(label);
      m_mac->update(salt);
      m_mac->final(h);

      const size_t writing = std::min(h.size(), o.remaining_capacity());
      xor_buf(o.next(writing), std::span{h}.first(writing));
   }
}

std::string TLS_12_PRF::name() const {
   return fmt("TLS-12-PRF({})", m_mac->name());
}

std::unique_ptr<KDF> TLS_12_PRF::new_object() const {
   return std::make_unique<TLS_12_PRF>(m_mac->new_object());
}

}  // namespace Botan
