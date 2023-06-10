/*
* TLSv1.2 PRF
* (C) 2004-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/prf_tls.h>

#include <botan/exceptn.h>
#include <botan/internal/fmt.h>

namespace Botan {

namespace {

/*
* TLS PRF P_hash function
*/
void P_hash(uint8_t out[],
            size_t out_len,
            MessageAuthenticationCode& mac,
            const uint8_t secret[],
            size_t secret_len,
            const uint8_t salt[],
            size_t salt_len) {
   try {
      mac.set_key(secret, secret_len);
   } catch(Invalid_Key_Length&) {
      throw Internal_Error(fmt("The premaster secret of {} bytes is too long for TLS-PRF", secret_len));
   }

   secure_vector<uint8_t> A(salt, salt + salt_len);
   secure_vector<uint8_t> h;

   size_t offset = 0;

   while(offset != out_len) {
      A = mac.process(A);

      mac.update(A);
      mac.update(salt, salt_len);
      mac.final(h);

      const size_t writing = std::min(h.size(), out_len - offset);
      xor_buf(&out[offset], h.data(), writing);
      offset += writing;
   }
}

}  // namespace

std::string TLS_12_PRF::name() const {
   return fmt("TLS-12-PRF({})", m_mac->name());
}

std::unique_ptr<KDF> TLS_12_PRF::new_object() const {
   return std::make_unique<TLS_12_PRF>(m_mac->new_object());
}

void TLS_12_PRF::kdf(uint8_t key[],
                     size_t key_len,
                     const uint8_t secret[],
                     size_t secret_len,
                     const uint8_t salt[],
                     size_t salt_len,
                     const uint8_t label[],
                     size_t label_len) const {
   secure_vector<uint8_t> msg;

   msg.reserve(label_len + salt_len);
   msg += std::make_pair(label, label_len);
   msg += std::make_pair(salt, salt_len);

   P_hash(key, key_len, *m_mac, secret, secret_len, msg.data(), msg.size());
}

}  // namespace Botan
