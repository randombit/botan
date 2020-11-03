/*
* OTP tests
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_HOTP) && defined(BOTAN_HAS_TOTP)
   #include <botan/parsing.h>
   #include <botan/otp.h>
   #include <botan/hash.h>
   #include <botan/calendar.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_HOTP) && defined(BOTAN_HAS_TOTP)

class HOTP_KAT_Tests final : public Text_Based_Test
   {
   public:
      HOTP_KAT_Tests()
         : Text_Based_Test("otp/hotp.vec", "Key,Digits,Counter,OTP")
         {}

      bool clear_between_callbacks() const override { return false; }

      Test::Result run_one_test(const std::string& hash_algo, const VarMap& vars) override
         {
         Test::Result result("HOTP " + hash_algo);

         std::unique_ptr<Botan::HashFunction> hash_test = Botan::HashFunction::create(hash_algo);
         if(!hash_test)
            return {result};

         const std::vector<uint8_t> key = vars.get_req_bin("Key");
         const uint32_t otp = static_cast<uint32_t>(vars.get_req_sz("OTP"));
         const uint64_t counter = vars.get_req_sz("Counter");
         const size_t digits = vars.get_req_sz("Digits");

         Botan::HOTP hotp(key, hash_algo, digits);

         result.test_int_eq("OTP", hotp.generate_hotp(counter), otp);

         std::pair<bool, uint64_t> otp_res = hotp.verify_hotp(otp, counter, 0);
         result.test_eq("OTP verify result", otp_res.first, true);
         result.confirm("OTP verify next counter", otp_res.second == counter + 1);

         // Test invalid OTP
         otp_res = hotp.verify_hotp(otp + 1, counter, 0);
         result.test_eq("OTP verify result", otp_res.first, false);
         result.confirm("OTP verify next counter", otp_res.second == counter);

         // Test invalid OTP with long range
         otp_res = hotp.verify_hotp(otp + 1, counter, 100);
         result.test_eq("OTP verify result", otp_res.first, false);
         result.confirm("OTP verify next counter", otp_res.second == counter);

         // Test valid OTP with long range
         otp_res = hotp.verify_hotp(otp, counter - 90, 100);
         result.test_eq("OTP verify result", otp_res.first, true);
         result.confirm("OTP verify next counter", otp_res.second == counter + 1);

         return result;
         }
   };

BOTAN_REGISTER_TEST("otp", "otp_hotp", HOTP_KAT_Tests);

class TOTP_KAT_Tests final : public Text_Based_Test
   {
   public:
      TOTP_KAT_Tests()
         : Text_Based_Test("otp/totp.vec", "Key,Digits,Timestep,Timestamp,OTP")
         {}

      bool clear_between_callbacks() const override { return false; }

      Test::Result run_one_test(const std::string& hash_algo, const VarMap& vars) override
         {
         Test::Result result("TOTP " + hash_algo);

         std::unique_ptr<Botan::HashFunction> hash_test = Botan::HashFunction::create(hash_algo);
         if(!hash_test)
            return {result};

         const std::vector<uint8_t> key = vars.get_req_bin("Key");
         const uint32_t otp = static_cast<uint32_t>(vars.get_req_sz("OTP"));
         const size_t digits = vars.get_req_sz("Digits");
         const size_t timestep = vars.get_req_sz("Timestep");
         const std::string timestamp = vars.get_req_str("Timestamp");

         Botan::TOTP totp(key, hash_algo, digits, timestep);

         std::chrono::system_clock::time_point time = from_timestring(timestamp);
         std::chrono::system_clock::time_point later_time = time + std::chrono::seconds(timestep);
         std::chrono::system_clock::time_point too_late = time + std::chrono::seconds(2*timestep);

         result.test_int_eq("TOTP generate", totp.generate_totp(time), otp);

         result.test_eq("TOTP verify valid", totp.verify_totp(otp, time, 0), true);
         result.test_eq("TOTP verify invalid", totp.verify_totp(otp ^ 1, time, 0), false);
         result.test_eq("TOTP verify time slip", totp.verify_totp(otp, later_time, 0), false);
         result.test_eq("TOTP verify time slip allowed", totp.verify_totp(otp, later_time, 1), true);
         result.test_eq("TOTP verify time slip out of range", totp.verify_totp(otp, too_late, 1), false);

         return result;
         }

   private:
      std::chrono::system_clock::time_point from_timestring(const std::string& time_str)
         {
         if(time_str.size() != 19)
            throw Test_Error("Invalid TOTP timestamp string " + time_str);
         // YYYY-MM-DDTHH:MM:SS
         // 0123456789012345678
         const uint32_t year = Botan::to_u32bit(time_str.substr(0, 4));
         const uint32_t month = Botan::to_u32bit(time_str.substr(5, 2));
         const uint32_t day = Botan::to_u32bit(time_str.substr(8, 2));
         const uint32_t hour = Botan::to_u32bit(time_str.substr(11, 2));
         const uint32_t minute = Botan::to_u32bit(time_str.substr(14, 2));
         const uint32_t second = Botan::to_u32bit(time_str.substr(17, 2));
         return Botan::calendar_point(year, month, day, hour, minute, second).to_std_timepoint();
         }
   };

BOTAN_REGISTER_TEST("otp", "otp_totp", TOTP_KAT_Tests);

#endif

}


