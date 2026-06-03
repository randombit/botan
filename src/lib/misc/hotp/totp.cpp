/*
* TOTP
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/otp.h>

#include <botan/assert.h>
#include <botan/internal/calendar.h>

namespace Botan {

TOTP::TOTP(const uint8_t key[], size_t key_len, std::string_view hash_algo, size_t digits, size_t time_step) :
      m_hotp(key, key_len, hash_algo, digits),
      m_time_step(time_step),
      m_unix_epoch(calendar_point(1970, 1, 1, 0, 0, 0).to_std_timepoint()) {
   /*
   * Technically any time step except 0 is valid, but 30 is typical
   * and over 5 minutes seems unlikely.
   */
   BOTAN_ARG_CHECK(m_time_step > 0 && m_time_step <= 300, "Invalid TOTP time step");
}

uint32_t TOTP::generate_totp(std::chrono::system_clock::time_point current_time) {
   const uint64_t unix_time = std::chrono::duration_cast<std::chrono::seconds>(current_time - m_unix_epoch).count();
   return this->generate_totp(unix_time);
}

uint32_t TOTP::generate_totp(uint64_t unix_time) {
   return m_hotp.generate_hotp(unix_time / m_time_step);
}

bool TOTP::verify_totp(uint32_t otp, std::chrono::system_clock::time_point current_time, size_t clock_drift_accepted) {
   const uint64_t unix_time = std::chrono::duration_cast<std::chrono::seconds>(current_time - m_unix_epoch).count();
   return verify_totp(otp, unix_time, clock_drift_accepted);
}

bool TOTP::verify_totp(uint32_t otp, uint64_t unix_time, size_t clock_drift_accepted) {
   /*
   clock_drift_accepted is denominated in time steps. This bounds the loop to
   far more iterations than any reasonable clock drift would require. For the
   almost universally used 30 second time step, this limit is about 3.5 days
   */
   BOTAN_ARG_CHECK(clock_drift_accepted <= 10000, "TOTP clock_drift_accepted too large");

   // This was on Sep 9, 2001
   BOTAN_ARG_CHECK(unix_time >= 1000000000, "TOTP unix_time argument is implausibly small");

   const uint64_t t = unix_time / m_time_step;

   for(size_t i = 0; i <= clock_drift_accepted; ++i) {
      BOTAN_ASSERT_NOMSG(t >= i);
      if(m_hotp.generate_hotp(t - i) == otp) {
         return true;
      }
   }

   return false;
}

}  // namespace Botan
