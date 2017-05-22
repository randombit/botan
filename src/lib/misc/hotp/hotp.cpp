/*
* HOTP
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/hotp.h>

namespace Botan {

HOTP::HOTP(const SymmetricKey& key, const std::string& hash_algo, size_t digits)
   {
   if(digits == 6)
      m_digit_mod = 1000000;
   else if(digits == 7)
      m_digit_mod = 10000000;
   else if(digits == 8)
      m_digit_mod = 100000000;
   else
      throw Invalid_Argument("Invalid HOTP digits");

   /*
   RFC 4228 only supports SHA-1 but TOTP allows SHA-256 and SHA-512
   and some HOTP libs support one or both as extensions
   */
   if(hash_algo == "SHA-1")
      m_mac = MessageAuthenticationCode::create_or_throw("HMAC(SHA-1)");
   else if(hash_algo == "SHA-256")
      m_mac = MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");
   else if(hash_algo == "SHA-512")
      m_mac = MessageAuthenticationCode::create_or_throw("HMAC(SHA-512)");
   else
      throw Invalid_Argument("Unsupported HOTP hash function");

   m_mac->set_key(key);
   }

uint32_t HOTP::generate_hotp(uint64_t counter)
   {
   uint8_t counter8[8] = { 0 };
   store_be(counter, counter8);
   m_mac->update(counter8, sizeof(counter8));
   const secure_vector<uint8_t> mac = m_mac->final();

   const size_t offset = mac[mac.size()-1] & 0x0F;
   const uint32_t code = load_be<uint32_t>(mac.data() + offset, 0) & 0x7FFFFFFF;
   return code % m_digit_mod;
   }

std::pair<bool,uint64_t> HOTP::verify_hotp(uint32_t otp, uint64_t starting_counter, size_t resync_range)
   {
   for(size_t i = 0; i <= resync_range; ++i)
      {
      if(generate_hotp(starting_counter + i) == otp)
         return std::make_pair(true, starting_counter + i + 1);
      }
   return std::make_pair(false, starting_counter);
   }

}

