/*
* KDF defined in NIST SP 800-56a (Approved Alternative 1)
*
* (C) 2017 Ribose Inc. Written by Krzysztof Kwiatkowski.
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sp800_56a.h>

#include <botan/exceptn.h>
#include <botan/internal/fmt.h>

namespace Botan {

namespace {

template <class AuxiliaryFunction_t>
void SP800_56A_kdf(AuxiliaryFunction_t& auxfunc,
                   uint8_t key[],
                   size_t key_len,
                   const uint8_t secret[],
                   size_t secret_len,
                   const uint8_t label[],
                   size_t label_len) {
   const uint64_t kRepsUpperBound = (1ULL << 32);

   const size_t digest_len = auxfunc.output_length();

   const size_t reps = key_len / digest_len + ((key_len % digest_len) ? 1 : 0);

   if(reps >= kRepsUpperBound) {
      // See SP-800-56A, point 5.8.1
      throw Invalid_Argument("SP800-56A KDF requested output too large");
   }

   uint32_t counter = 1;
   secure_vector<uint8_t> result;
   for(size_t i = 0; i < reps; i++) {
      auxfunc.update_be(counter++);
      auxfunc.update(secret, secret_len);
      auxfunc.update(label, label_len);
      auxfunc.final(result);

      const size_t offset = digest_len * i;
      const size_t len = std::min(result.size(), key_len - offset);
      copy_mem(&key[offset], result.data(), len);
   }
}

}  // namespace

void SP800_56A_Hash::kdf(uint8_t key[],
                         size_t key_len,
                         const uint8_t secret[],
                         size_t secret_len,
                         const uint8_t salt[],
                         size_t salt_len,
                         const uint8_t label[],
                         size_t label_len) const {
   BOTAN_UNUSED(salt);

   if(salt_len > 0)
      throw Invalid_Argument("SP800_56A_Hash does not support a non-empty salt");

   SP800_56A_kdf(*m_hash, key, key_len, secret, secret_len, label, label_len);
}

std::string SP800_56A_Hash::name() const { return fmt("SP800-56A({})", m_hash->name()); }

std::unique_ptr<KDF> SP800_56A_Hash::new_object() const {
   return std::make_unique<SP800_56A_Hash>(m_hash->new_object());
}

SP800_56A_HMAC::SP800_56A_HMAC(std::unique_ptr<MessageAuthenticationCode> mac) : m_mac(std::move(mac)) {
   // TODO: we need a MessageAuthenticationCode::is_hmac
   if(!m_mac->name().starts_with("HMAC(")) {
      throw Algorithm_Not_Found("Only HMAC can be used with KDF SP800-56A");
   }
}

void SP800_56A_HMAC::kdf(uint8_t key[],
                         size_t key_len,
                         const uint8_t secret[],
                         size_t secret_len,
                         const uint8_t salt[],
                         size_t salt_len,
                         const uint8_t label[],
                         size_t label_len) const {
   /*
   * SP 800-56A specifies if the salt is empty then a block of zeros
   * equal to the hash's underlying block size are used. However this
   * is equivalent to setting a zero-length key, so the same call
   * works for either case.
   */
   m_mac->set_key(salt, salt_len);

   SP800_56A_kdf(*m_mac, key, key_len, secret, secret_len, label, label_len);
}

std::string SP800_56A_HMAC::name() const { return fmt("SP800-56A({})", m_mac->name()); }

std::unique_ptr<KDF> SP800_56A_HMAC::new_object() const {
   return std::make_unique<SP800_56A_HMAC>(m_mac->new_object());
}

}  // namespace Botan
