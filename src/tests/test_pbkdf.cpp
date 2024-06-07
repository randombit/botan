/*
* (C) 2014,2015,2019 Jack Lloyd
* (C) 2018 Ribose Inc
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_PBKDF)
   #include <botan/pbkdf.h>
   #include <botan/pwdhash.h>
#endif

#if defined(BOTAN_HAS_RFC4880)
   #include <botan/rfc4880.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_PBKDF)
class PBKDF_KAT_Tests final : public Text_Based_Test {
   public:
      PBKDF_KAT_Tests() : Text_Based_Test("pbkdf", "Iterations,Salt,Passphrase,Output") {}

      Test::Result run_one_test(const std::string& pbkdf_name, const VarMap& vars) override {
         const size_t iterations = vars.get_req_sz("Iterations");
         const std::vector<uint8_t> salt = vars.get_req_bin("Salt");
         const std::string passphrase = vars.get_req_str("Passphrase");
         const std::vector<uint8_t> expected = vars.get_req_bin("Output");
         const size_t outlen = expected.size();

         Test::Result result(pbkdf_name);
         auto pbkdf = Botan::PBKDF::create(pbkdf_name);

         if(!pbkdf) {
            result.note_missing(pbkdf_name);
            return result;
         }

         result.test_eq("Expected name", pbkdf->name(), pbkdf_name);

         const Botan::secure_vector<uint8_t> derived =
            pbkdf->derive_key(outlen, passphrase, salt.data(), salt.size(), iterations).bits_of();
         result.test_eq("derived key", derived, expected);

         auto pwdhash_fam = Botan::PasswordHashFamily::create(pbkdf_name);

         if(!pwdhash_fam) {
            result.note_missing("No PasswordHashFamily for " + pbkdf_name);
            return result;
         }

         auto pwdhash = pwdhash_fam->from_params(iterations);

         std::vector<uint8_t> pwdhash_derived(outlen);
         pwdhash->hash(pwdhash_derived, passphrase, salt);

         result.test_eq("pwdhash derived key", pwdhash_derived, expected);

         return result;
      }
};

BOTAN_REGISTER_SMOKE_TEST("pbkdf", "pbkdf_kat", PBKDF_KAT_Tests);

class Pwdhash_Tests : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         const std::vector<std::string> all_pwdhash = {
            "Scrypt", "PBKDF2(SHA-256)", "OpenPGP-S2K(SHA-384)", "Argon2d", "Argon2i", "Argon2id", "Bcrypt-PBKDF"};

         const auto run_time = std::chrono::milliseconds(3);
         const auto tune_time = std::chrono::milliseconds(1);
         const size_t max_mem = 32;

         for(const std::string& pwdhash : all_pwdhash) {
            Test::Result result("Pwdhash " + pwdhash);
            auto pwdhash_fam = Botan::PasswordHashFamily::create(pwdhash);

            if(pwdhash_fam) {
               result.start_timer();

               const std::vector<uint8_t> salt(8);
               const std::string password = "test";

               auto tuned_pwhash = pwdhash_fam->tune(32, run_time, max_mem, tune_time);

               std::vector<uint8_t> output1(32);
               tuned_pwhash->hash(output1, password, salt);

               std::unique_ptr<Botan::PasswordHash> pwhash;

               if(pwdhash_fam->name() == "Scrypt" || pwdhash_fam->name().starts_with("Argon2")) {
                  pwhash = pwdhash_fam->from_params(
                     tuned_pwhash->memory_param(), tuned_pwhash->iterations(), tuned_pwhash->parallelism());
               } else {
                  pwhash = pwdhash_fam->from_params(tuned_pwhash->iterations());
               }

               std::vector<uint8_t> output2(32);
               pwhash->hash(output2, password, salt);

               result.test_eq("PasswordHash produced same output when run with same params", output1, output2);

               auto default_pwhash = pwdhash_fam->default_params();
               std::vector<uint8_t> output3(32);
               default_pwhash->hash(output3, password, salt);

               result.end_timer();
            } else {
               result.test_note("No such algo " + pwdhash);
            }

            results.push_back(result);
         }

         return results;
      }
};

BOTAN_REGISTER_TEST("pbkdf", "pwdhash", Pwdhash_Tests);

#endif

#if defined(BOTAN_HAS_PBKDF_BCRYPT)

class Bcrypt_PBKDF_KAT_Tests final : public Text_Based_Test {
   public:
      Bcrypt_PBKDF_KAT_Tests() : Text_Based_Test("bcrypt_pbkdf.vec", "Passphrase,Salt,Iterations,Output") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         const size_t rounds = vars.get_req_sz("Iterations");
         const std::vector<uint8_t> salt = vars.get_req_bin("Salt");
         const std::string passphrase = vars.get_req_str("Passphrase");
         const std::vector<uint8_t> expected = vars.get_req_bin("Output");

         Test::Result result("bcrypt PBKDF");

         auto pwdhash_fam = Botan::PasswordHashFamily::create("Bcrypt-PBKDF");

         if(!pwdhash_fam) {
            result.test_failure("Bcrypt-PBKDF is missing PasswordHashFamily");
            return result;
         }

         auto pwdhash = pwdhash_fam->from_iterations(rounds);

         std::vector<uint8_t> derived(expected.size());
         pwdhash->hash(derived, passphrase, salt);

         result.test_eq("derived key", derived, expected);

         return result;
      }
};

BOTAN_REGISTER_TEST("pbkdf", "bcrypt_pbkdf", Bcrypt_PBKDF_KAT_Tests);

#endif

#if defined(BOTAN_HAS_SCRYPT)

class Scrypt_KAT_Tests final : public Text_Based_Test {
   public:
      Scrypt_KAT_Tests() : Text_Based_Test("scrypt.vec", "Passphrase,Salt,N,R,P,Output") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         const size_t N = vars.get_req_sz("N");
         const size_t R = vars.get_req_sz("R");
         const size_t P = vars.get_req_sz("P");
         const std::vector<uint8_t> salt = vars.get_req_bin("Salt");
         const std::string passphrase = vars.get_req_str("Passphrase");
         const std::vector<uint8_t> expected = vars.get_req_bin("Output");

         Test::Result result("scrypt");

         if(N >= 1048576 && Test::run_long_tests() == false) {
            return result;
         }

         auto pwdhash_fam = Botan::PasswordHashFamily::create("Scrypt");

         if(!pwdhash_fam) {
            result.test_failure("Scrypt is missing PasswordHashFamily");
            return result;
         }

         auto pwdhash = pwdhash_fam->from_params(N, R, P);

         std::vector<uint8_t> pwdhash_derived(expected.size());
         pwdhash->hash(pwdhash_derived, passphrase, salt);

         result.test_eq("pwdhash derived key", pwdhash_derived, expected);

         return result;
      }
};

BOTAN_REGISTER_TEST("pbkdf", "scrypt", Scrypt_KAT_Tests);

#endif

#if defined(BOTAN_HAS_ARGON2)

class Argon2_KAT_Tests final : public Text_Based_Test {
   public:
      Argon2_KAT_Tests() : Text_Based_Test("argon2.vec", "Passphrase,Salt,P,M,T,Output", "Secret,AD") {}

      Test::Result run_one_test(const std::string& mode, const VarMap& vars) override {
         const size_t P = vars.get_req_sz("P");
         const size_t M = vars.get_req_sz("M");
         const size_t T = vars.get_req_sz("T");
         const std::vector<uint8_t> key = vars.get_opt_bin("Secret");
         const std::vector<uint8_t> ad = vars.get_opt_bin("AD");
         const std::vector<uint8_t> salt = vars.get_req_bin("Salt");
         const std::vector<uint8_t> passphrase = vars.get_req_bin("Passphrase");
         const std::vector<uint8_t> expected = vars.get_req_bin("Output");

         Test::Result result(mode);

         auto pwdhash_fam = Botan::PasswordHashFamily::create(mode);

         if(!pwdhash_fam) {
            result.test_failure("Argon2 is missing PasswordHashFamily");
            return result;
         }

         auto pwdhash = pwdhash_fam->from_params(M, T, P);

         const std::string passphrase_str(passphrase.begin(), passphrase.end());

         std::vector<uint8_t> pwdhash_derived(expected.size());
         pwdhash->hash(pwdhash_derived, passphrase_str, salt, ad, key);

         result.test_eq("pwdhash derived key", pwdhash_derived, expected);

         return result;
      }
};

BOTAN_REGISTER_SERIALIZED_TEST("pbkdf", "argon2", Argon2_KAT_Tests);

#endif

#if defined(BOTAN_HAS_PGP_S2K)

class PGP_S2K_Iter_Test final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("PGP_S2K iteration encoding");

         // The maximum representable iteration count
         const size_t max_iter = 65011712;

         result.test_eq("Encoding of large value accepted", Botan::RFC4880_encode_count(max_iter * 2), size_t(255));
         result.test_eq("Encoding of small value accepted", Botan::RFC4880_encode_count(0), size_t(0));

         for(size_t c = 0; c != 256; ++c) {
            const size_t dec = Botan::RFC4880_decode_count(static_cast<uint8_t>(c));
            const size_t comp_dec = (16 + (c & 0x0F)) << ((c >> 4) + 6);
            result.test_eq("Decoded value matches PGP formula", dec, comp_dec);

            const size_t enc = Botan::RFC4880_encode_count(comp_dec);
            result.test_eq("Encoded value matches PGP formula", enc, c);
         }

         uint8_t last_enc = 0;

         for(size_t i = 0; i <= max_iter; i += 64) {
            const uint8_t enc = Botan::RFC4880_encode_count(i);
            result.test_lte("Encoded value non-decreasing", last_enc, enc);

            /*
            The iteration count as encoded may not be exactly the
            value requested, but should never be less
            */
            const size_t dec = Botan::RFC4880_decode_count(enc);
            result.test_gte("Decoded value is >= requested", dec, i);

            last_enc = enc;
         }

         return std::vector<Test::Result>{result};
      }
};

BOTAN_REGISTER_TEST("pbkdf", "pgp_s2k_iter", PGP_S2K_Iter_Test);

#endif

}  // namespace

}  // namespace Botan_Tests
