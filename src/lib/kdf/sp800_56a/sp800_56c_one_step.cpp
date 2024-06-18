/*
* KDF defined in NIST SP 800-56a revision 2 (Single-step key-derivation function)
* or in NIST SP 800-56C revision 2 (Section 4 - One-Step KDM)
*
* (C) 2017 Ribose Inc. Written by Krzysztof Kwiatkowski.
* (C) 2024 Fabian Albert - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sp800_56c_one_step.h>

#include <botan/exceptn.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/fmt.h>
#include <botan/internal/kmac.h>

#include <functional>

namespace Botan {

namespace {
template <typename T>
concept hash_or_mac_type = std::is_same_v<T, HashFunction> || std::is_same_v<T, MessageAuthenticationCode>;

/**
 * @brief One-Step Key Derivation as defined in SP800-56Cr2 Section 4
 */
template <hash_or_mac_type HashOrMacType>
void kdm_internal(std::span<uint8_t> output_buffer,
                  std::span<const uint8_t> z,
                  std::span<const uint8_t> fixed_info,
                  HashOrMacType& hash_or_mac,
                  const std::function<void(HashOrMacType&)>& init_h_callback) {
   size_t l = output_buffer.size() * 8;
   // 1. If L > 0, then set reps = ceil(L / H_outputBits); otherwise,
   //    output an error indicator and exit this process without
   //    performing the remaining actions (i.e., omit steps 2 through 8).
   BOTAN_ARG_CHECK(l > 0, "Zero KDM output length");
   size_t reps = ceil_division(l, hash_or_mac.output_length() * 8);

   // 2. If reps > (2^32 − 1), then output an error indicator and exit this
   //    process without performing the remaining actions
   //    (i.e., omit steps 3 through 8).
   BOTAN_ARG_CHECK(reps <= 0xFFFFFFFF, "Too large KDM output length");

   // 3. Initialize a big-endian 4-byte unsigned integer counter as
   //    0x00000000, corresponding to a 32-bit binary representation of
   //    the number zero.
   uint32_t counter = 0;

   // 4. If counter || Z || FixedInfo is more than max_H_inputBits bits
   //    long, then output an error indicator and exit this process
   //    without performing any of the remaining actions (i.e., omit
   //    steps 5 through 8). => SHA3 and KMAC are unlimited

   // 5. Initialize Result(0) as an empty bit string
   //    (i.e., the null string).
   secure_vector<uint8_t> result;

   // 6. For i = 1 to reps, do the following:
   for(size_t i = 1; i <= reps; i++) {
      // 6.1. Increment counter by 1.
      counter++;
      // Reset the hash/MAC object. For MAC, also set the key (salt) and IV.
      hash_or_mac.clear();
      init_h_callback(hash_or_mac);

      // 6.2 Compute K(i) = H(counter || Z || FixedInfo).
      hash_or_mac.update_be(counter);
      hash_or_mac.update(z);
      hash_or_mac.update(fixed_info);
      auto k_i = hash_or_mac.final();

      // 6.3. Set Result(i) = Result(i−1) || K(i).
      result.insert(result.end(), k_i.begin(), k_i.end());
   }

   // 7. Set DerivedKeyingMaterial equal to the leftmost L bits of Result(reps).
   copy_mem(output_buffer, std::span(result).subspan(0, output_buffer.size()));
}

}  // namespace

void SP800_56C_One_Step_Hash::kdf(uint8_t key[],
                                  size_t key_len,
                                  const uint8_t secret[],
                                  size_t secret_len,
                                  const uint8_t salt[],
                                  size_t salt_len,
                                  const uint8_t label[],
                                  size_t label_len) const {
   BOTAN_UNUSED(salt);
   BOTAN_ARG_CHECK(salt_len == 0, "SP800_56A_Hash does not support a non-empty salt");

   kdm_internal<HashFunction>(
      {key, key_len}, {secret, secret_len}, {label, label_len}, *m_hash, [](HashFunction&) { /* NOP */ });
}

std::string SP800_56C_One_Step_Hash::name() const {
   return fmt("SP800-56A({})", m_hash->name());
}

std::unique_ptr<KDF> SP800_56C_One_Step_Hash::new_object() const {
   return std::make_unique<SP800_56C_One_Step_Hash>(m_hash->new_object());
}

SP800_56C_One_Step_HMAC::SP800_56C_One_Step_HMAC(std::unique_ptr<MessageAuthenticationCode> mac) :
      m_mac(std::move(mac)) {
   // TODO: we need a MessageAuthenticationCode::is_hmac
   if(!m_mac->name().starts_with("HMAC(")) {
      throw Algorithm_Not_Found("Only HMAC can be used with SP800_56A_HMAC");
   }
}

void SP800_56C_One_Step_HMAC::kdf(uint8_t key[],
                                  size_t key_len,
                                  const uint8_t secret[],
                                  size_t secret_len,
                                  const uint8_t salt[],
                                  size_t salt_len,
                                  const uint8_t label[],
                                  size_t label_len) const {
   kdm_internal<MessageAuthenticationCode>(
      {key, key_len}, {secret, secret_len}, {label, label_len}, *m_mac, [&](MessageAuthenticationCode& kdf_mac) {
         // 4.1 Option 2 and 3 - An implementation dependent byte string, salt,
         //     whose (non-null) value may be optionally provided in
         //     OtherInput, serves as the HMAC# key ..

         // SP 800-56Cr2 specifies if the salt is empty then a block of zeros
         // equal to the hash's underlying block size are used. However for HMAC
         // this is equivalent to setting a zero-length key, so the same call
         // works for either case.
         kdf_mac.set_key(std::span{salt, salt_len});
      });
}

std::string SP800_56C_One_Step_HMAC::name() const {
   return fmt("SP800-56A({})", m_mac->name());
}

std::unique_ptr<KDF> SP800_56C_One_Step_HMAC::new_object() const {
   return std::make_unique<SP800_56C_One_Step_HMAC>(m_mac->new_object());
}

// Option 3 - KMAC
void SP800_56A_One_Step_KMAC_Abstract::kdf(uint8_t key[],
                                           size_t key_len,
                                           const uint8_t secret[],
                                           size_t secret_len,
                                           const uint8_t salt[],
                                           size_t salt_len,
                                           const uint8_t label[],
                                           size_t label_len) const {
   auto mac = create_kmac_instance(key_len);
   kdm_internal<MessageAuthenticationCode>(
      {key, key_len}, {secret, secret_len}, {label, label_len}, *mac, [&](MessageAuthenticationCode& kdf_mac) {
         // 4.1 Option 2 and 3 - An implementation dependent byte string, salt,
         //     whose (non-null) value may be optionally provided in
         //     OtherInput, serves as the KMAC# key ...
         if(salt_len == 0) {
            // 4.1 Implementation-Dependent Parameters 3
            //     If H(x) = KMAC128[or 256](salt, x, H_outputBits, "KDF"),
            //     then – in the absence of an agreed-upon alternative –
            //     the default_salt shall be an all - zero string of
            //     164 bytes [or 132 bytes]
            kdf_mac.set_key(std::vector<uint8_t>(default_salt_length(), 0));
         } else {
            kdf_mac.set_key(std::span{salt, salt_len});
         }

         // 4.1 Option 3 - The "customization string" S shall be the byte string
         //     01001011 || 01000100 || 01000110, which represents the sequence
         //     of characters 'K', 'D', and 'F' in 8-bit ASCII.
         kdf_mac.start(std::array<uint8_t, 3>{'K', 'D', 'F'});
      });
}

std::unique_ptr<MessageAuthenticationCode> SP800_56C_One_Step_KMAC128::create_kmac_instance(
   size_t output_byte_len) const {
   return std::make_unique<KMAC128>(output_byte_len * 8);
}

std::unique_ptr<MessageAuthenticationCode> SP800_56C_One_Step_KMAC256::create_kmac_instance(
   size_t output_byte_len) const {
   return std::make_unique<KMAC256>(output_byte_len * 8);
}

}  // namespace Botan
