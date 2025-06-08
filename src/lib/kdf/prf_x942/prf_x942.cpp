/*
* X9.42 PRF
* (C) 1999-2007 Jack Lloyd
* (C) 2024      René Meusel, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/prf_x942.h>

#include <botan/der_enc.h>
#include <botan/hash.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>

namespace Botan {

namespace {

/*
* Encode an integer as an OCTET STRING
*/
std::vector<uint8_t> encode_x942_int(uint32_t n) {
   const auto n_buf = store_be(n);

   std::vector<uint8_t> output;
   DER_Encoder(output).encode(n_buf.data(), n_buf.size(), ASN1_Type::OctetString);
   return output;
}

}  // namespace

void X942_PRF::perform_kdf(std::span<uint8_t> key,
                           std::span<const uint8_t> secret,
                           std::span<const uint8_t> salt,
                           std::span<const uint8_t> label) const {
   if(key.empty()) {
      return;
   }

   constexpr size_t sha1_output_bytes = 20;  // Fixed to use SHA-1
   const auto blocks_required = ceil_division<uint64_t /* for 32bit systems */>(key.size(), sha1_output_bytes);

   // This KDF uses a 32-bit counter for the hash blocks, initialized at 1.
   // It will wrap around after 2^32 - 1 iterations limiting the theoretically
   // possible output to 2^32 - 1 blocks.
   BOTAN_ARG_CHECK(blocks_required <= 0xFFFFFFFE, "X942_PRF maximum output length exceeeded");

   auto hash = HashFunction::create("SHA-1");
   const auto in = concat<secure_vector<uint8_t>>(label, salt);

   BufferStuffer k(key);
   for(uint32_t counter = 1; !k.full(); ++counter) {
      BOTAN_ASSERT_NOMSG(counter != 0);  // overflow check

      hash->update(secret);
      hash->update(
         DER_Encoder()
            .start_sequence()

            .start_sequence()
            .encode(m_key_wrap_oid)
            .raw_bytes(encode_x942_int(counter))
            .end_cons()

            .encode_if(!salt.empty(), DER_Encoder().start_explicit(0).encode(in, ASN1_Type::OctetString).end_explicit())

            .start_explicit(2)
            .raw_bytes(encode_x942_int(static_cast<uint32_t>(8 * key.size())))
            .end_explicit()

            .end_cons()
            .get_contents());

      // Write straight into the output buffer, except if the hash output needs
      // a truncation in the final iteration.
      if(k.remaining_capacity() >= sha1_output_bytes) {
         hash->final(k.next(sha1_output_bytes));
      } else {
         std::array<uint8_t, sha1_output_bytes> h;
         hash->final(h);
         k.append(std::span{h}.first(k.remaining_capacity()));
      }
   }
}

std::string X942_PRF::name() const {
   return "X9.42-PRF(" + m_key_wrap_oid.to_formatted_string() + ")";
}

}  // namespace Botan
