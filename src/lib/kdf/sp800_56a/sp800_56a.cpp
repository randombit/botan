/*
* KDF defined in NIST SP 800-56a (Approved Alternative 1)
*
* (C) 2017 Ribose Inc. Written by Krzysztof Kwiatkowski.
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/sp800_56a.h>
#include <botan/scan_name.h>
#include <botan/exceptn.h>

namespace Botan {

namespace {

template<class AuxiliaryFunction_t>
size_t SP800_56A_kdf(
   AuxiliaryFunction_t& auxfunc,
   uint8_t key[], size_t key_len,
   const uint8_t secret[], size_t secret_len,
   const uint8_t label[], size_t label_len)
   {
   const uint64_t kRepsUpperBound = (1ULL << 32);

   const size_t digest_len = auxfunc.output_length();

   const size_t reps = key_len / digest_len + ((key_len % digest_len) ? 1 : 0);

   if (reps >= kRepsUpperBound)
      {
      // See SP-800-56A, point 5.8.1
      throw Invalid_Argument("SP800-56A KDF requested output too large");
      }

   uint32_t counter = 1;
   secure_vector<uint8_t> result;
   for(size_t i = 0; i < reps; i++)
      {
      auxfunc.update_be(counter++);
      auxfunc.update(secret, secret_len);
      auxfunc.update(label, label_len);
      auxfunc.final(result);

      const size_t offset = digest_len * i;
      const size_t len = std::min(result.size(), key_len - offset);
      copy_mem(&key[offset], result.data(), len);
      }

   return key_len;
   }

}

size_t SP800_56A_Hash::kdf(uint8_t key[], size_t key_len,
                           const uint8_t secret[], size_t secret_len,
                           const uint8_t salt[], size_t salt_len,
                           const uint8_t label[], size_t label_len) const
   {
   /*
   * TODO: should we reject a non-empty salt with an exception?
   * Ignoring the salt seems quite dangerous to applications which
   * don't expect it.
   */
   BOTAN_UNUSED(salt, salt_len);

   return SP800_56A_kdf(*m_hash, key, key_len, secret, secret_len, label, label_len);
   }

SP800_56A_HMAC::SP800_56A_HMAC(MessageAuthenticationCode* mac) : m_mac(mac)
   {
   // TODO: we need a MessageAuthenticationCode::is_hmac
   const SCAN_Name req(m_mac->name());
   if(req.algo_name() != "HMAC")
      {
      throw Algorithm_Not_Found("Only HMAC can be used with KDF SP800-56A");
      }
   }

size_t SP800_56A_HMAC::kdf(uint8_t key[], size_t key_len,
                           const uint8_t secret[], size_t secret_len,
                           const uint8_t salt[], size_t salt_len,
                           const uint8_t label[], size_t label_len) const
   {
   /*
   * SP 800-56A specifies if the salt is empty then a block of zeros
   * equal to the hash's underlying block size are used. However this
   * is equivalent to setting a zero-length key, so the same call
   * works for either case.
   */
   m_mac->set_key(salt, salt_len);

   return SP800_56A_kdf(*m_mac, key, key_len, secret, secret_len, label, label_len);
   }



}
