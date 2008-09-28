/*************************************************
* TLS PRF Source File                            *
* (C) 2004-2006 Jack Lloyd                       *
*************************************************/

#include <botan/prf_tls.h>
#include <botan/lookup.h>
#include <botan/xor_buf.h>
#include <botan/hmac.h>

namespace Botan {

/*************************************************
* TLS PRF                                        *
*************************************************/
SecureVector<byte> TLS_PRF::derive(u32bit key_len,
                                   const byte secret[], u32bit secret_len,
                                   const byte seed[], u32bit seed_len) const
   {
   u32bit S1_len = (secret_len + 1) / 2,
          S2_len = (secret_len + 1) / 2;
   const byte* S1 = secret;
   const byte* S2 = secret + (secret_len - S2_len);

   SecureVector<byte> key1, key2;
   key1 = P_hash("MD5",   key_len, S1, S1_len, seed, seed_len);
   key2 = P_hash("SHA-1", key_len, S2, S2_len, seed, seed_len);

   xor_buf(key1.begin(), key2.begin(), key2.size());

   return key1;
   }

/*************************************************
* TLS PRF P_hash function                        *
*************************************************/
SecureVector<byte> TLS_PRF::P_hash(const std::string& hash, u32bit len,
                                   const byte secret[], u32bit secret_len,
                                   const byte seed[], u32bit seed_len) const
   {
   SecureVector<byte> out;

   HMAC hmac(hash);
   hmac.set_key(secret, secret_len);

   SecureVector<byte> A(seed, seed_len);
   while(len)
      {
      const u32bit this_block_len = std::min(hmac.OUTPUT_LENGTH, len);

      A = hmac.process(A);

      hmac.update(A);
      hmac.update(seed, seed_len);
      SecureVector<byte> block = hmac.final();

      out.append(block, this_block_len);
      len -= this_block_len;
      }
   return out;
   }

}
