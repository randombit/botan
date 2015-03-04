/*
* TLS v1.0 and v1.2 PRFs
* (C) 2004-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/kdf_utils.h>
#include <botan/prf_tls.h>
#include <botan/hmac.h>

namespace Botan {

TLS_12_PRF* TLS_12_PRF::make(const Spec& spec)
   {
   if(auto mac = get_mac(spec.arg(0)))
      return new TLS_12_PRF(mac);
   if(auto hash = get_hash_function(spec.arg(0)))
      return new TLS_12_PRF(new HMAC(hash));
   return nullptr;
   }

BOTAN_REGISTER_NAMED_T(KDF, "TLS-12-PRF", TLS_12_PRF, TLS_12_PRF::make);
BOTAN_REGISTER_KDF_NOARGS(TLS_PRF, "TLS-PRF");

TLS_PRF::TLS_PRF() :
   m_hmac_md5(make_message_auth("HMAC(MD5)")),
   m_hmac_sha1(make_message_auth("HMAC(SHA-1)"))
   {
   }

namespace {

/*
* TLS PRF P_hash function
*/
void P_hash(byte out[], size_t out_len,
            MessageAuthenticationCode& mac,
            const byte secret[], size_t secret_len,
            const byte salt[], size_t salt_len)
   {
   try
      {
      mac.set_key(secret, secret_len);
      }
   catch(Invalid_Key_Length)
      {
      throw Internal_Error("The premaster secret of " +
                           std::to_string(secret_len) +
                           " bytes is too long for the PRF");
      }

   secure_vector<byte> A(salt, salt + salt_len);
   secure_vector<byte> h;

   size_t offset = 0;

   while(offset != out_len)
      {
      A = mac.process(A);

      mac.update(A);
      mac.update(salt, salt_len);
      mac.final(h);

      const size_t writing = std::min(h.size(), out_len - offset);
      xor_buf(&out[offset], &h[0], writing);
      offset += writing;
      }
   }

}

size_t TLS_PRF::kdf(byte key[], size_t key_len,
                    const byte secret[], size_t secret_len,
                    const byte salt[], size_t salt_len) const
   {
   const size_t S1_len = (secret_len + 1) / 2,
                S2_len = (secret_len + 1) / 2;
   const byte* S1 = secret;
   const byte* S2 = secret + (secret_len - S2_len);

   P_hash(key, key_len, *m_hmac_md5,  S1, S1_len, salt, salt_len);
   P_hash(key, key_len, *m_hmac_sha1, S2, S2_len, salt, salt_len);
   return key_len;
   }

size_t TLS_12_PRF::kdf(byte key[], size_t key_len,
                       const byte secret[], size_t secret_len,
                       const byte salt[], size_t salt_len) const
   {
   P_hash(key, key_len, *m_mac, secret, secret_len, salt, salt_len);
   return key_len;
   }

}
