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
   if(auto mac = make_a<MessageAuthenticationCode>(spec.arg(0)))
      return new TLS_12_PRF(mac);
   if(auto hash = make_a<HashFunction>(spec.arg(0)))
      return new TLS_12_PRF(new HMAC(hash));
   return nullptr;
   }

BOTAN_REGISTER_NAMED_T(KDF, "TLS-12-PRF", TLS_12_PRF, TLS_12_PRF::make);
BOTAN_REGISTER_KDF_NOARGS(TLS_PRF, "TLS-PRF");

namespace {

/*
* TLS PRF P_hash function
*/
void P_hash(secure_vector<byte>& output,
            MessageAuthenticationCode& mac,
            const byte secret[], size_t secret_len,
            const byte seed[], size_t seed_len)
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

   secure_vector<byte> A(seed, seed + seed_len);

   size_t offset = 0;

   while(offset != output.size())
      {
      const size_t this_block_len =
         std::min<size_t>(mac.output_length(), output.size() - offset);

      A = mac.process(A);

      mac.update(A);
      mac.update(seed, seed_len);
      secure_vector<byte> block = mac.final();

      xor_buf(&output[offset], &block[0], this_block_len);
      offset += this_block_len;
      }
   }

}

/*
* TLS PRF Constructor and Destructor
*/
TLS_PRF::TLS_PRF()
   {
   hmac_md5.reset(make_a<MessageAuthenticationCode>("HMAC(MD5)"));
   hmac_sha1.reset(make_a<MessageAuthenticationCode>("HMAC(SHA-1)"));
   }

/*
* TLS PRF
*/
secure_vector<byte> TLS_PRF::derive(size_t key_len,
                                   const byte secret[], size_t secret_len,
                                   const byte seed[], size_t seed_len) const
   {
   secure_vector<byte> output(key_len);

   size_t S1_len = (secret_len + 1) / 2,
          S2_len = (secret_len + 1) / 2;
   const byte* S1 = secret;
   const byte* S2 = secret + (secret_len - S2_len);

   P_hash(output, *hmac_md5,  S1, S1_len, seed, seed_len);
   P_hash(output, *hmac_sha1, S2, S2_len, seed, seed_len);

   return output;
   }

/*
* TLS v1.2 PRF Constructor and Destructor
*/
TLS_12_PRF::TLS_12_PRF(MessageAuthenticationCode* mac) : m_mac(mac)
   {
   }

secure_vector<byte> TLS_12_PRF::derive(size_t key_len,
                                      const byte secret[], size_t secret_len,
                                      const byte seed[], size_t seed_len) const
   {
   secure_vector<byte> output(key_len);

   P_hash(output, *m_mac, secret, secret_len, seed, seed_len);

   return output;
   }

}
