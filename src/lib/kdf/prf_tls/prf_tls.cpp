/*
* TLS v1.0 and v1.2 PRFs
* (C) 2004-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/prf_tls.h>
#include <botan/exceptn.h>

namespace Botan {

TLS_PRF::TLS_PRF() :
   TLS_PRF(MessageAuthenticationCode::create_or_throw("HMAC(MD5)"),
           MessageAuthenticationCode::create_or_throw("HMAC(SHA-1)"))
   {
   }

namespace {

/*
* TLS PRF P_hash function
*/
void P_hash(uint8_t out[], size_t out_len,
            MessageAuthenticationCode& mac,
            const uint8_t secret[], size_t secret_len,
            const uint8_t salt[], size_t salt_len)
   {
   try
      {
      mac.set_key(secret, secret_len);
      }
   catch(Invalid_Key_Length&)
      {
      throw Internal_Error("The premaster secret of " +
                           std::to_string(secret_len) +
                           " bytes is too long for the PRF");
      }

   secure_vector<uint8_t> A(salt, salt + salt_len);
   secure_vector<uint8_t> h;

   size_t offset = 0;

   while(offset != out_len)
      {
      A = mac.process(A);

      mac.update(A);
      mac.update(salt, salt_len);
      mac.final(h);

      const size_t writing = std::min(h.size(), out_len - offset);
      xor_buf(&out[offset], h.data(), writing);
      offset += writing;
      }
   }

}

size_t TLS_PRF::kdf(uint8_t key[], size_t key_len,
                    const uint8_t secret[], size_t secret_len,
                    const uint8_t salt[], size_t salt_len,
                    const uint8_t label[], size_t label_len) const
   {
   const size_t S1_len = (secret_len + 1) / 2,
                S2_len = (secret_len + 1) / 2;
   const uint8_t* S1 = secret;
   const uint8_t* S2 = secret + (secret_len - S2_len);
   secure_vector<uint8_t> msg;

   msg.reserve(label_len + salt_len);
   msg += std::make_pair(label, label_len);
   msg += std::make_pair(salt, salt_len);

   P_hash(key, key_len, *m_hmac_md5,  S1, S1_len, msg.data(), msg.size());
   P_hash(key, key_len, *m_hmac_sha1, S2, S2_len, msg.data(), msg.size());
   return key_len;
   }

size_t TLS_12_PRF::kdf(uint8_t key[], size_t key_len,
                       const uint8_t secret[], size_t secret_len,
                       const uint8_t salt[], size_t salt_len,
                       const uint8_t label[], size_t label_len) const
   {
   secure_vector<uint8_t> msg;

   msg.reserve(label_len + salt_len);
   msg += std::make_pair(label, label_len);
   msg += std::make_pair(salt, salt_len);

   P_hash(key, key_len, *m_mac, secret, secret_len, msg.data(), msg.size());
   return key_len;
   }

}
