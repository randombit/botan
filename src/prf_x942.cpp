/*************************************************
* X9.42 PRF Source File                          *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/kdf.h>
#include <botan/der_enc.h>
#include <botan/oids.h>
#include <botan/lookup.h>
#include <botan/bit_ops.h>
#include <algorithm>
#include <memory>

namespace Botan {

namespace {

/*************************************************
* Encode an integer as an OCTET STRING           *
*************************************************/
MemoryVector<byte> encode_x942_int(u32bit n)
   {
   byte n_buf[4];
   for(u32bit j = 0; j != 4; ++j)
      n_buf[j] = get_byte(j, n);

   DER_Encoder encoder;
   encoder.encode(n_buf, 4, OCTET_STRING);
   return encoder.get_contents();
   }

}

/*************************************************
* X9.42 PRF                                      *
*************************************************/
SecureVector<byte> X942_PRF::derive(u32bit key_len,
                                    const byte secret[], u32bit secret_len,
                                    const byte salt[], u32bit salt_len) const
   {
   std::auto_ptr<HashFunction> hash(get_hash("SHA-1"));
   const OID kek_algo(key_wrap_oid);

   SecureVector<byte> key;
   u32bit counter = 1;

   while(key.size() != key_len)
      {
      DER_Encoder encoder;

      encoder.start_sequence()
         .start_sequence()
            .encode(kek_algo)
            .add_raw_octets(encode_x942_int(counter))
         .end_sequence();

      if(salt_len)
         {
         encoder.start_explicit(ASN1_Tag(0));
         encoder.encode(salt, salt_len, OCTET_STRING);
         encoder.end_explicit(ASN1_Tag(0));
         }

         encoder.start_explicit(ASN1_Tag(2))
            .add_raw_octets(encode_x942_int(8 * key_len))
         .end_explicit(ASN1_Tag(2))
      .end_sequence();

      hash->update(secret, secret_len);
      hash->update(encoder.get_contents());
      SecureVector<byte> digest = hash->final();
      key.append(digest, std::min(digest.size(), key_len - key.size()));

      ++counter;
      }

   return key;
   }

/*************************************************
* X9.42 Constructor                              *
*************************************************/
X942_PRF::X942_PRF(const std::string& oid)
   {
   if(OIDS::have_oid(oid))
      key_wrap_oid = OIDS::lookup(oid).as_string();
   else
      key_wrap_oid = oid;
   }

}
