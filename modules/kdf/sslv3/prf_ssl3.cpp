/*************************************************
* SSLv3 PRF Source File                          *
* (C) 2004-2006 Jack Lloyd                       *
*************************************************/

#include <botan/prf_ssl3.h>
#include <botan/lookup.h>
#include <memory>

namespace Botan {

namespace {

/*************************************************
* Return the next inner hash                     *
*************************************************/
OctetString next_hash(u32bit where, u32bit want,
                      HashFunction* md5, HashFunction* sha1,
                      const byte secret[], u32bit secret_len,
                      const byte seed[], u32bit seed_len)
   {
   if(want > md5->OUTPUT_LENGTH)
      throw Internal_Error("SSL3_PRF:next_hash: want is too big");

   const byte ASCII_A_CHAR = 0x41;

   for(u32bit j = 0; j != where + 1; j++)
      sha1->update(ASCII_A_CHAR + where);
   sha1->update(secret, secret_len);
   sha1->update(seed, seed_len);
   SecureVector<byte> sha1_hash = sha1->final();

   md5->update(secret, secret_len);
   md5->update(sha1_hash);
   SecureVector<byte> md5_hash = md5->final();

   return OctetString(md5_hash, want);
   }

}

/*************************************************
* SSL3 PRF                                       *
*************************************************/
SecureVector<byte> SSL3_PRF::derive(u32bit key_len,
                                    const byte secret[], u32bit secret_len,
                                    const byte seed[], u32bit seed_len) const
   {
   if(key_len > 416)
      throw Internal_Error("SSL3_PRF: Requested key length is too large");

   std::auto_ptr<HashFunction> md5(get_hash("MD5"));
   std::auto_ptr<HashFunction> sha1(get_hash("SHA-1"));

   OctetString output;

   int counter = 0;
   while(key_len)
      {
      const u32bit produce = std::min(key_len, md5->OUTPUT_LENGTH);

      output = output + next_hash(counter++, produce, md5.get(), sha1.get(),
                                  secret, secret_len, seed, seed_len);

      key_len -= produce;
      }

   return output.bits_of();
   }

}
