/*
* TLS PRF
* (C) 2004-2006 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/prf_tls.h>
#include <botan/xor_buf.h>
#include <botan/hmac.h>
#include <botan/md5.h>
#include <botan/sha160.h>

namespace Botan {

namespace {

/*
* TLS PRF P_hash function
*/
SecureVector<byte> P_hash(MessageAuthenticationCode* mac,
                          u32bit len,
                          const byte secret[], u32bit secret_len,
                          const byte seed[], u32bit seed_len)
   {
   SecureVector<byte> out;

   mac->set_key(secret, secret_len);

   SecureVector<byte> A(seed, seed_len);
   while(len)
      {
      const u32bit this_block_len = std::min(mac->OUTPUT_LENGTH, len);

      A = mac->process(A);

      mac->update(A);
      mac->update(seed, seed_len);
      SecureVector<byte> block = mac->final();

      out.append(block, this_block_len);
      len -= this_block_len;
      }
   return out;
   }

}

/*
* TLS PRF Constructor and Destructor
*/
TLS_PRF::TLS_PRF()
   {
   hmac_md5 = new HMAC(new MD5);
   hmac_sha1 = new HMAC(new SHA_160);
   }

TLS_PRF::~TLS_PRF()
   {
   delete hmac_md5;
   delete hmac_sha1;
   }

/*
* TLS PRF
*/
SecureVector<byte> TLS_PRF::derive(u32bit key_len,
                                   const byte secret[], u32bit secret_len,
                                   const byte seed[], u32bit seed_len) const
   {
   u32bit S1_len = (secret_len + 1) / 2,
          S2_len = (secret_len + 1) / 2;
   const byte* S1 = secret;
   const byte* S2 = secret + (secret_len - S2_len);

   SecureVector<byte> key1, key2;
   key1 = P_hash(hmac_md5,  key_len, S1, S1_len, seed, seed_len);
   key2 = P_hash(hmac_sha1, key_len, S2, S2_len, seed, seed_len);

   xor_buf(key1.begin(), key2.begin(), key2.size());

   return key1;
   }

}
