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

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_BCRYPT)
class Bcrypt_Tests : public Text_Based_Test
   {
   public:
      Bcrypt_Tests() : Text_Based_Test("bcrypt.vec", "Password,Passhash") {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         // Encoded as binary so we can test binary inputs
         const std::vector<uint8_t> password_vec = get_req_bin(vars, "Password");
         const std::string password(reinterpret_cast<const char*>(password_vec.data()),
                                    password_vec.size());

         const std::string passhash = get_req_str(vars, "Passhash");

         Test::Result result("bcrypt");
         result.test_eq("correct hash accepted", Botan::check_bcrypt(password, passhash), true);

         const size_t max_level = 1 + std::min<size_t>(Test::soak_level() / 2, 10);

         for(size_t level = 1; level <= max_level; ++level)
            {
            const std::string gen_hash = generate_bcrypt(password, Test::rng(), level);
            result.test_eq("generated hash accepted", Botan::check_bcrypt(password, gen_hash), true);
            }

         return result;
         }
   };

BOTAN_REGISTER_TEST("bcrypt", Bcrypt_Tests);

#endif

#if defined(BOTAN_HAS_PASSHASH9)
class Passhash9_Tests : public Text_Based_Test
   {
   public:
      Passhash9_Tests() : Text_Based_Test("passhash9.vec", "Password,Passhash") {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         // Encoded as binary so we can test binary inputs
         const std::vector<uint8_t> password_vec = get_req_bin(vars, "Password");
         const std::string password(reinterpret_cast<const char*>(password_vec.data()),
                                    password_vec.size());

         const std::string passhash = get_req_str(vars, "Passhash");

         Test::Result result("passhash9");
         result.test_eq("correct hash accepted", Botan::check_passhash9(password, passhash), true);

         for(uint8_t alg_id = 0; alg_id <= 4; ++alg_id)
            {
            const std::string gen_hash = Botan::generate_passhash9(password, Test::rng(), 2, alg_id);

            if(!result.test_eq("generated hash accepted", Botan::check_passhash9(password, gen_hash), true))
               {
               result.test_note("hash was " + gen_hash);
               }
            }

         const size_t max_level = 1 + std::min<size_t>(Test::soak_level() / 2, 10);

         for(size_t level = 1; level <= max_level; ++level)
            {
            const std::string gen_hash = Botan::generate_passhash9(password, Test::rng(), level);
            if(!result.test_eq("generated hash accepted", Botan::check_passhash9(password, gen_hash), true))
               {
               result.test_note("hash was " + gen_hash);
               }
            }

         return result;
         }
   };

BOTAN_REGISTER_TEST("passhash9", Passhash9_Tests);

#endif

}

}
