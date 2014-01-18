/*
* X9.42 PRF
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/prf_x942.h>
#include <botan/der_enc.h>
#include <botan/oids.h>
#include <botan/sha160.h>
#include <botan/loadstor.h>
#include <algorithm>

namespace Botan {

namespace {

/*
* Encode an integer as an OCTET STRING
*/
std::vector<byte> encode_x942_int(u32bit n)
   {
   byte n_buf[4] = { 0 };
   store_be(n, n_buf);
   return DER_Encoder().encode(n_buf, 4, OCTET_STRING).get_contents_unlocked();
   }

}

/*
* X9.42 PRF
*/
secure_vector<byte> X942_PRF::derive(size_t key_len,
                                    const byte secret[], size_t secret_len,
                                    const byte salt[], size_t salt_len) const
   {
   SHA_160 hash;
   const OID kek_algo(key_wrap_oid);

   secure_vector<byte> key;
   u32bit counter = 1;

   while(key.size() != key_len && counter)
      {
      hash.update(secret, secret_len);

      hash.update(
         DER_Encoder().start_cons(SEQUENCE)

            .start_cons(SEQUENCE)
               .encode(kek_algo)
               .raw_bytes(encode_x942_int(counter))
            .end_cons()

            .encode_if(salt_len != 0,
               DER_Encoder()
                  .start_explicit(0)
                     .encode(salt, salt_len, OCTET_STRING)
                  .end_explicit()
               )

            .start_explicit(2)
               .raw_bytes(encode_x942_int(static_cast<u32bit>(8 * key_len)))
            .end_explicit()

         .end_cons().get_contents()
         );

      secure_vector<byte> digest = hash.final();
      const size_t needed = std::min(digest.size(), key_len - key.size());
      key += std::make_pair(&digest[0], needed);

      ++counter;
      }

   return key;
   }

/*
* X9.42 Constructor
*/
X942_PRF::X942_PRF(const std::string& oid)
   {
   if(OIDS::have_oid(oid))
      key_wrap_oid = OIDS::lookup(oid).as_string();
   else
      key_wrap_oid = oid;
   }

}
