/*
* HOTP/TOTP
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ONE_TIME_PASSWORDS_H_
#define BOTAN_ONE_TIME_PASSWORDS_H_

#include <botan/mac.h>
#include <botan/symkey.h>
#include <chrono>

namespace Botan {

/**
* HOTP one time passwords (RFC 4226)
*/
class BOTAN_PUBLIC_API(2, 2) HOTP final {
   public:
      /**
      * Create an HOTP instance
      * @param key the secret key shared between client and server
      * @param hash_algo the hash algorithm to use, should be SHA-1 or SHA-256
      * @param digits the number of digits in the OTP (must be 6, 7, or 8)
      * TODO(Botan4) remove the default hash param here
      */
      BOTAN_FUTURE_EXPLICIT HOTP(const SymmetricKey& key, std::string_view hash_algo = "SHA-1", size_t digits = 6) :
            HOTP(key.begin(), key.size(), hash_algo, digits) {}

      /**
      * Create an HOTP instance
      * @param key the secret key shared between client and server
      * @param key_len length of key param
      * @param hash_algo the hash algorithm to use, should be SHA-1 or SHA-256
      * @param digits the number of digits in the OTP (must be 6, 7, or 8)
      * TODO(Botan4) remove the default hash param here
      */
      HOTP(const uint8_t key[], size_t key_len, std::string_view hash_algo = "SHA-1", size_t digits = 6);

      /**
      * Generate the HOTP for a particular counter value
      * @warning if the counter value is repeated the OTP ceases to be one-time
      */
      uint32_t generate_hotp(uint64_t counter);

      /**
      * Check an OTP value using a starting counter and a resync range
      * @param otp the client provided OTP
      * @param starting_counter the server's guess as to the current counter state
      * @param resync_range if 0 then only HOTP(starting_counter) is accepted
      * If larger than 0, up to resync_range values after HOTP are also checked.
      * @return (valid,next_counter). If the OTP does not validate, always
      * returns (false,starting_counter). Otherwise returns (true,next_counter)
      * where next_counter is at most starting_counter + resync_range + 1
      */
      std::pair<bool, uint64_t> verify_hotp(uint32_t otp, uint64_t starting_counter, size_t resync_range = 0);

   private:
      std::unique_ptr<MessageAuthenticationCode> m_mac;
      size_t m_digits;
};

/**
* TOTP (time based) one time passwords (RFC 6238)
*/
class BOTAN_PUBLIC_API(2, 2) TOTP final {
   public:
      /**
      * Create a TOTP instance
      * @param key the secret key shared between client and server
      * @param hash_algo the hash algorithm to use, should be SHA-1, SHA-256 or SHA-512
      * @param digits the number of digits in the OTP (must be 6, 7, or 8)
      * @param time_step granularity of OTP in seconds
      * TODO(Botan4) remove the default hash param here
      */
      BOTAN_FUTURE_EXPLICIT TOTP(const SymmetricKey& key,
                                 std::string_view hash_algo = "SHA-1",
                                 size_t digits = 6,
                                 size_t time_step = 30) :
            TOTP(key.begin(), key.size(), hash_algo, digits, time_step) {}

      /**
      * Create a TOTP instance
      * @param key the secret key shared between client and server
      * @param key_len length of key
      * @param hash_algo the hash algorithm to use, should be SHA-1, SHA-256 or SHA-512
      * @param digits the number of digits in the OTP (must be 6, 7, or 8)
      * @param time_step granularity of OTP in seconds
      * TODO(Botan4) remove the default hash param here
      */
      TOTP(const uint8_t key[],
           size_t key_len,
           std::string_view hash_algo = "SHA-1",
           size_t digits = 6,
           size_t time_step = 30);

      /**
      * Convert the provided time_point to a Unix timestamp and call generate_totp
      */
      uint32_t generate_totp(std::chrono::system_clock::time_point time_point);

      /**
      * Generate the OTP corresponding the the provided "Unix timestamp" (ie
      * number of seconds since midnight Jan 1, 1970)
      */
      uint32_t generate_totp(uint64_t unix_time);

      /**
      * Verify a TOTP against the provided time point
      * @param otp the presented OTP
      * @param time the current local time
      * @param clock_drift_accepted the acceptable clock drift, in time steps
      * @return true if the OTP is valid
      */
      bool verify_totp(uint32_t otp, std::chrono::system_clock::time_point time, size_t clock_drift_accepted = 0);

      /**
      * Verify a TOTP against the provided Unix timestamp
      * @param otp the presented OTP
      * @param unix_time the current local time as a Unix timestamp
      * @param clock_drift_accepted the acceptable clock drift, in time steps
      * @return true if the OTP is valid
      */
      bool verify_totp(uint32_t otp, uint64_t unix_time, size_t clock_drift_accepted = 0);

   private:
      HOTP m_hotp;
      size_t m_time_step;
      std::chrono::system_clock::time_point m_unix_epoch;
};

}  // namespace Botan

#endif
