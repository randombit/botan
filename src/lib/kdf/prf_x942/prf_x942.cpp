/*
* X9.42 PRF
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/prf_x942.h>
#include <botan/der_enc.h>
#include <botan/hash.h>
#include <botan/loadstor.h>
#include <algorithm>

namespace Botan {

namespace {

/*
* Encode an integer as an OCTET STRING
*/
std::vector<uint8_t> encode_x942_int(uint32_t n)
   {
   uint8_t n_buf[4] = { 0 };
   store_be(n, n_buf);

   std::vector<uint8_t> output;
   DER_Encoder(output).encode(n_buf, 4, OCTET_STRING);
   return output;
   }

}

size_t X942_PRF::kdf(uint8_t key[], size_t key_len,
                     const uint8_t secret[], size_t secret_len,
                     const uint8_t salt[], size_t salt_len,
                     const uint8_t label[], size_t label_len) const
   {
   std::unique_ptr<HashFunction> hash(HashFunction::create("SHA-160"));

   secure_vector<uint8_t> h;
   secure_vector<uint8_t> in;
   size_t offset = 0;
   uint32_t counter = 1;

   in.reserve(salt_len + label_len);
   in += std::make_pair(label,label_len);
   in += std::make_pair(salt,salt_len);

   while(offset != key_len && counter)
      {
      hash->update(secret, secret_len);

      hash->update(
         DER_Encoder().start_cons(SEQUENCE)

            .start_cons(SEQUENCE)
               .encode(m_key_wrap_oid)
               .raw_bytes(encode_x942_int(counter))
            .end_cons()

            .encode_if(salt_len != 0,
               DER_Encoder()
                  .start_explicit(0)
                     .encode(in, OCTET_STRING)
                  .end_explicit()
               )

            .start_explicit(2)
               .raw_bytes(encode_x942_int(static_cast<uint32_t>(8 * key_len)))
            .end_explicit()

         .end_cons().get_contents()
         );

      hash->final(h);
      const size_t copied = std::min(h.size(), key_len - offset);
      copy_mem(&key[offset], h.data(), copied);
      offset += copied;

      ++counter;
      }

   // FIXME: returns truncated output
   return offset;
   }

std::string X942_PRF::name() const
   {
   return "X9.42-PRF(" + m_key_wrap_oid.to_formatted_string() + ")";
   }

}
