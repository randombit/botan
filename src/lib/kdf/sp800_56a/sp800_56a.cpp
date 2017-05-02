/*
* KDF defined in NIST SP 800-56a (Approved Alternative 1)
* (C) 2017 Krzysztof Kwiatkowski
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/sp800_56a.h>
#include <botan/hmac.h>
#include <botan/scan_name.h>
#include <botan/exceptn.h>

namespace Botan {

namespace {
static const size_t MAX_REPS = (2ULL << 32);

// Option1: auxiliary function is a hash function
template<typename T>
void Init(
      T *t,
      const uint8_t salt[],
      const size_t salt_len)
{
   BOTAN_UNUSED(t, salt, salt_len);
}

// Option1: auxiliary function is a HMAC function
template<>
void Init<MessageAuthenticationCode>(
      MessageAuthenticationCode *hmac_func,
      const uint8_t salt[],
      const size_t salt_len)
{
   const SCAN_Name req(hmac_func->name());
   if(req.algo_name() != "HMAC") {
      throw Algorithm_Not_Found("Only HMAC can be used with KDF SP800-56A");
   }

   if (salt_len) {
      hmac_func->set_key(salt, salt_len);
   } else {
      /* 5.8.1.1: Salt shall be an all-zero string whose bit length
         equals that specified as the length of the input block for
         the hash function  */
      auto hash = HashFunction::create(req.arg(0));
      if (!hash) {
         // Should never happen
         throw Algorithm_Not_Found(req.arg(0));
      }

      secure_vector<uint8_t> s(hash->hash_block_size(), 0);
      hmac_func->set_key(s.data(), s.size());
   }
}
}

template<class AuxiliaryFunction_t>
size_t SP800_56A<AuxiliaryFunction_t>::kdf(
      uint8_t key[], size_t key_len,
      const uint8_t secret[], size_t secret_len,
      const uint8_t salt[], size_t salt_len,
      const uint8_t label[], size_t label_len) const
{

   Init<AuxiliaryFunction_t>(m_auxfunc.get(), salt, salt_len);
   const size_t digest_len = m_auxfunc->output_length();

   size_t reps = key_len / digest_len + !!(key_len % digest_len);
   if (reps >= MAX_REPS) {
      // See SP-800-56A, point 5.8.1
      throw Invalid_Argument(
            "key_len / digest output size "
            "can't be bigger than 2^32 - 1");
   }

   uint32_t counter = 1;
   secure_vector<uint8_t> result;
   for(size_t i = 0; i < reps; i++) {
      m_auxfunc->update_be(counter++);
      m_auxfunc->update(secret, secret_len);
      m_auxfunc->update(label, label_len);
      m_auxfunc->final(result);

      const size_t offset = digest_len * i;
      const size_t len = std::min(result.size(), key_len - offset);
      copy_mem(&key[offset], result.data(), len);
   }

   return key_len;
}

/* Template initialization */
template class SP800_56A<MessageAuthenticationCode>;
template class SP800_56A<HashFunction>;

}
