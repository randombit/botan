/*
* HOTP
* (C) 2017,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/otp.h>

#include <botan/exceptn.h>
#include <botan/internal/loadstor.h>

namespace Botan {

namespace {

// Use compile-time constant divisors to ensure the compiler emits a
// multiply+shift sequence instead of a variable-time division instruction
uint32_t hotp_truncate(uint32_t code, size_t digits) {
   switch(digits) {
      case 6:
         return code % 1000000;
      case 7:
         return code % 10000000;
      case 8:
         return code % 100000000;
      default:
         BOTAN_ASSERT_UNREACHABLE();
   }
}

}  // namespace

HOTP::HOTP(const uint8_t key[], size_t key_len, std::string_view hash_algo, size_t digits) : m_digits(digits) {
   BOTAN_ARG_CHECK(m_digits == 6 || m_digits == 7 || m_digits == 8, "Invalid HOTP digits");

   /*
   RFC 4228 only supports SHA-1 but TOTP allows SHA-256 and SHA-512
   and some HOTP libs support one or both as extensions
   */
   if(hash_algo == "SHA-1") {
      m_mac = MessageAuthenticationCode::create_or_throw("HMAC(SHA-1)");
   } else if(hash_algo == "SHA-256") {
      m_mac = MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");
   } else if(hash_algo == "SHA-512") {
      m_mac = MessageAuthenticationCode::create_or_throw("HMAC(SHA-512)");
   } else {
      throw Invalid_Argument("Unsupported HOTP hash function");
   }

   m_mac->set_key(key, key_len);
}

uint32_t HOTP::generate_hotp(uint64_t counter) {
   m_mac->update_be(counter);
   const secure_vector<uint8_t> mac = m_mac->final();

   const size_t offset = mac[mac.size() - 1] & 0x0F;
   const uint32_t code = load_be<uint32_t>(mac.data() + offset, 0) & 0x7FFFFFFF;
   return hotp_truncate(code, m_digits);
}

std::pair<bool, uint64_t> HOTP::verify_hotp(uint32_t otp, uint64_t starting_counter, size_t resync_range) {
   BOTAN_ARG_CHECK(resync_range <= 100000, "HOTP resync_range too large");

   for(size_t i = 0; i <= resync_range; ++i) {
      const uint64_t ctr = starting_counter + i;

      if(ctr == std::numeric_limits<uint64_t>::max()) {
         throw Invalid_State("HOTP counter has been exhausted");
      }

      if(generate_hotp(ctr) == otp) {
         return std::make_pair(true, ctr + 1);
      }
   }
   return std::make_pair(false, starting_counter);
}

}  // namespace Botan
