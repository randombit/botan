/*
* X9.42 PRF
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/prf_x942.h>
#include <botan/der_enc.h>
#include <botan/oids.h>
#include <botan/hash.h>
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

size_t X942_PRF::kdf(byte key[], size_t key_len,
                     const byte secret[], size_t secret_len,
                     const byte salt[], size_t salt_len,
                     const byte label[], size_t label_len) const
   {
   std::unique_ptr<HashFunction> hash(HashFunction::create("SHA-160"));
   const OID kek_algo(m_key_wrap_oid);

   secure_vector<byte> h;
   secure_vector<byte> in;
   size_t offset = 0;
   u32bit counter = 1;

   in.reserve(salt_len + label_len);
   in += std::make_pair(label,label_len);
   in += std::make_pair(salt,salt_len);

   while(offset != key_len && counter)
      {
      hash->update(secret, secret_len);

      hash->update(
         DER_Encoder().start_cons(SEQUENCE)

            .start_cons(SEQUENCE)
               .encode(kek_algo)
               .raw_bytes(encode_x942_int(counter))
            .end_cons()

            .encode_if(salt_len != 0,
               DER_Encoder()
                  .start_explicit(0)
                     .encode(in, OCTET_STRING)
                  .end_explicit()
               )

            .start_explicit(2)
               .raw_bytes(encode_x942_int(static_cast<u32bit>(8 * key_len)))
            .end_explicit()

         .end_cons().get_contents()
         );

      hash->final(h);
      const size_t copied = std::min(h.size(), key_len - offset);
      copy_mem(&key[offset], h.data(), copied);
      offset += copied;

      ++counter;
      }

   return offset;
   }

/*
* X9.42 Constructor
*/
X942_PRF::X942_PRF(const std::string& oid)
   {
   if(OIDS::have_oid(oid))
      m_key_wrap_oid = OIDS::lookup(oid).as_string();
   else
      m_key_wrap_oid = oid;
   }

}
