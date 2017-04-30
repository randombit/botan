/*
* KDF defined in NIST SP 800-56a (Approved Alternative 1)
* (C) 2017 Krzysztof Kwiatkowski
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/sp800_56a.h>
#include <botan/hmac.h>
#include <botan/assert.h>
#include <botan/mem_ops.h>

namespace Botan {

static const size_t MAX_REPS = (2ULL << 32);

size_t SP800_56A::kdf(  uint8_t key[], size_t key_len,
                        const uint8_t secret[], size_t secret_len,
                        const uint8_t salt[], size_t salt_len,
                        const uint8_t label[], size_t label_len) const
{
   // Salt is not used by this algorithm
   BOTAN_UNUSED(salt, salt_len);

   secure_vector<uint8_t> h;
   const size_t digest_len = m_hash->output_length();

   size_t reps = key_len / digest_len + !!(key_len % digest_len);
   if (reps >= MAX_REPS) {
      // See SP-800-56A, point 5.8.1
      throw Invalid_Argument(
            "key_len / digest output size "
            "can't be bigger than 2^32 - 1");
   }

   uint32_t counter = 1;
   for(size_t i = 0; i < reps; i++) {
      m_hash->update_be(counter++);
      m_hash->update(secret, secret_len);
      m_hash->update(label, label_len);
      m_hash->final(h);

      const size_t offset = digest_len * i;
      const size_t len = std::min(h.size(), key_len - offset);
      copy_mem(&key[offset], h.data(), len);
   }

   return key_len;
}

}
