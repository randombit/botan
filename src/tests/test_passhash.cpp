/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_BCRYPT)
   #include <botan/bcrypt.h>
#endif

#if defined(BOTAN_HAS_PASSHASH9)
   #include <botan/passhash9.h>
#endif

#if defined(BOTAN_HAS_ARGON2)
   #include <botan/argon2.h>
   #include "test_rng.h"
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_BCRYPT)
class Bcrypt_Tests final : public Text_Based_Test
   {
   public:
      Bcrypt_Tests() : Text_Based_Test("passhash/bcrypt.vec", "Password,Passhash") {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         // Encoded as binary so we can test binary inputs
         const std::vector<uint8_t> password_vec = vars.get_req_bin("Password");
         const std::string password(reinterpret_cast<const char*>(password_vec.data()),
                                    password_vec.size());

         const std::string passhash = vars.get_req_str("Passhash");

         Test::Result result("bcrypt");
         result.test_eq("correct hash accepted", Botan::check_bcrypt(password, passhash), true);

         // self-test low levels for each test password
         for(uint16_t level = 4; level <= 6; ++level)
            {
            const std::string gen_hash = Botan::generate_bcrypt(password, Test::rng(), level);
            result.test_eq("generated hash accepted", Botan::check_bcrypt(password, gen_hash), true);
            }

         return result;
         }

      std::vector<Test::Result> run_final_tests() override
         {
         Test::Result result("bcrypt");

         uint64_t start = Test::timestamp();

         const std::string password = "ag00d1_2BE5ur3";

         const uint16_t max_level = (Test::run_long_tests() ? 15 : 10);

         for(uint16_t level = 4; level <= max_level; ++level)
            {
            const std::string gen_hash = Botan::generate_bcrypt(password, Test::rng(), level);
            result.test_eq("generated hash accepted", Botan::check_bcrypt(password, gen_hash), true);
            }

         result.test_throws("Invalid bcrypt version rejected",
                            "Unknown bcrypt version 'q'",
                            []() { Botan::generate_bcrypt("pass", Test::rng(), 4, 'q'); });

         result.set_ns_consumed(Test::timestamp() - start);

         return {result};
         }
   };

BOTAN_REGISTER_TEST("pbkdf", "bcrypt", Bcrypt_Tests);

#endif

#if defined(BOTAN_HAS_ARGON2)
class Argon2_Tests final : public Text_Based_Test
   {
   public:
      Argon2_Tests() : Text_Based_Test("passhash/argon2.vec", "Password,Passhash", "Mode,M,T,P,Salt,OutLen") {}

      Test::Result run_one_test(const std::string& header, const VarMap& vars) override
         {
         const std::string password = vars.get_req_str("Password");
         const std::string passhash = vars.get_req_str("Passhash");

         Test::Result result("Argon2 password hash");

         if(header == "Verify")
            {
            const bool accepted = Botan::argon2_check_pwhash(password.data(), password.size(), passhash);
            result.test_eq("correct hash accepted", accepted, true);
            }
         else if(header == "Generate")
            {
            const std::vector<uint8_t> salt = vars.get_req_bin("Salt");
            const uint8_t y = vars.get_req_u8("Mode");
            const size_t M = vars.get_req_sz("M");
            const size_t t = vars.get_req_sz("T");
            const size_t p = vars.get_req_sz("P");
            const size_t out_len = vars.get_req_sz("OutLen");

            Fixed_Output_RNG rng(salt);

            const std::string generated = Botan::argon2_generate_pwhash(password.data(), password.size(),
                                                                        rng,
                                                                        p, M, t, y, salt.size(), out_len);

            result.test_eq("expected hash generated", generated, passhash);
            const bool accepted = Botan::argon2_check_pwhash(password.data(), password.size(), generated);
            result.test_eq("generated hash accepted", accepted, true);
            }
         else
            throw Test_Error("Unexpected header in Argon2 password hash test file");

         return result;
         }
   };

BOTAN_REGISTER_TEST("pbkdf", "argon2_pass", Argon2_Tests);

#endif

#if defined(BOTAN_HAS_PASSHASH9)
class Passhash9_Tests final : public Text_Based_Test
   {
   public:
      Passhash9_Tests() : Text_Based_Test("passhash/passhash9.vec", "Password,Passhash,PRF") {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         // Encoded as binary so we can test binary inputs
         const std::vector<uint8_t> password_vec = vars.get_req_bin("Password");
         const std::string password(reinterpret_cast<const char*>(password_vec.data()),
                                    password_vec.size());

         const std::string passhash = vars.get_req_str("Passhash");
         const std::size_t prf = vars.get_req_sz("PRF");

         Test::Result result("passhash9");

         if(Botan::is_passhash9_alg_supported(uint8_t(prf)))
            {
            result.test_eq("correct hash accepted", Botan::check_passhash9(password, passhash), true);
            }

         for(uint8_t alg_id = 0; alg_id <= 4; ++alg_id)
            {
            if(Botan::is_passhash9_alg_supported(alg_id))
               {
               const std::string gen_hash = Botan::generate_passhash9(password, Test::rng(), 2, alg_id);

               if(!result.test_eq("generated hash accepted", Botan::check_passhash9(password, gen_hash), true))
                  {
                  result.test_note("hash was " + gen_hash);
                  }
               }
            }

         const uint16_t max_level = (Test::run_long_tests() ? 14 : 8);

         for(uint16_t level = 1; level <= max_level; ++level)
            {
            const uint8_t alg_id = 1; // default used by generate_passhash9()
            if(Botan::is_passhash9_alg_supported(alg_id))
               {
               const std::string gen_hash = Botan::generate_passhash9(password, Test::rng(), level, alg_id);
               if(!result.test_eq("generated hash accepted", Botan::check_passhash9(password, gen_hash), true))
                  {
                  result.test_note("hash was " + gen_hash);
                  }
               }
            }

         return result;
         }

      std::vector<Test::Result> run_final_tests() override
         {
         Test::Result result("passhash9");

         result.confirm("Unknown algorithm is unknown",
                        Botan::is_passhash9_alg_supported(255) == false);

         result.test_throws("Throws if algorithm not supported",
                            "Passhash9: Algorithm id 255 is not defined",
                            []() { Botan::generate_passhash9("pass", Test::rng(), 3, 255); });

         result.test_throws("Throws if iterations is too high",
                            "Requested passhash9 work factor 513 is too large",
                            []() { Botan::check_passhash9("floof", "$9$AgIB3c5J3kvAuML84sZ5hWT9WzJtiYRPLCEARaujS7I6IKbNCwp0"); });
         return {result};
         }
   };

BOTAN_REGISTER_TEST("pbkdf", "passhash9", Passhash9_Tests);

#endif

}

}
