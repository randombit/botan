/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "perf.h"

#if defined(BOTAN_HAS_PASSWORD_HASHING)
   #include <botan/pwdhash.h>
#endif

#if defined(BOTAN_HAS_BCRYPT)
   #include <botan/bcrypt.h>
#endif

#if defined(BOTAN_HAS_PASSHASH9)
   #include <botan/passhash9.h>
#endif

namespace Botan_CLI {

#if defined(BOTAN_HAS_BCRYPT)

class PerfTest_Bcrypt final : public PerfTest {
   public:
      void go(const PerfConfig& config) override {
         const std::string password = "not a very good password";

         for(size_t work_factor = 4; work_factor <= 14; ++work_factor) {
            auto timer = config.make_timer(Botan::fmt("bcrypt wf={}", work_factor));

            timer->run([&] { Botan::generate_bcrypt(password, config.rng(), static_cast<uint16_t>(work_factor)); });

            config.record_result(*timer);
         }
      }
};

BOTAN_REGISTER_PERF_TEST("bcrypt", PerfTest_Bcrypt);

#endif

#if defined(BOTAN_HAS_PASSHASH9)

class PerfTest_Passhash9 final : public PerfTest {
   public:
      void go(const PerfConfig& config) override {
         const std::string password = "not a very good password";

         for(uint8_t alg = 0; alg <= 4; ++alg) {
            if(Botan::is_passhash9_alg_supported(alg) == false) {
               continue;
            }

            for(auto work_factor : {10, 15}) {
               auto timer = config.make_timer(Botan::fmt("passhash9 alg={} wf={}", alg, work_factor));

               timer->run(
                  [&] { Botan::generate_passhash9(password, config.rng(), static_cast<uint8_t>(work_factor), alg); });

               config.record_result(*timer);
            }
         }
      }
};

BOTAN_REGISTER_PERF_TEST("passhash9", PerfTest_Passhash9);

#endif

#if defined(BOTAN_HAS_SCRYPT)

class PerfTest_Scrypt final : public PerfTest {
   public:
      void go(const PerfConfig& config) override {
         auto pwdhash_fam = Botan::PasswordHashFamily::create_or_throw("Scrypt");

         for(size_t N : {8192, 16384, 32768, 65536}) {
            for(size_t r : {1, 8, 16}) {
               for(size_t p : {1}) {
                  auto pwdhash = pwdhash_fam->from_params(N, r, p);

                  const size_t mem_usage = pwdhash->total_memory_usage() / (1024 * 1024);
                  auto scrypt_timer = config.make_timer(Botan::fmt("scrypt-{}-{}-{} ({} MiB)", N, r, p, mem_usage));

                  uint8_t out[64];
                  uint8_t salt[8];
                  config.rng().randomize(salt, sizeof(salt));

                  auto runtime = config.runtime();

                  while(scrypt_timer->under(runtime)) {
                     scrypt_timer->run([&] {
                        pwdhash->derive_key(out, sizeof(out), "password", 8, salt, sizeof(salt));
                        std::memcpy(salt, out, 8);
                     });
                  }

                  config.record_result(*scrypt_timer);

                  if(scrypt_timer->events() == 1) {
                     break;
                  }
               }
            }
         }
      }
};

BOTAN_REGISTER_PERF_TEST("scrypt", PerfTest_Scrypt);

#endif

#if defined(BOTAN_HAS_ARGON2)

class PerfTest_Argon2 final : public PerfTest {
   public:
      void go(const PerfConfig& config) override {
         auto pwhash_fam = Botan::PasswordHashFamily::create_or_throw("Argon2id");

         const auto msec = config.runtime();

         for(size_t M : {8 * 1024, 64 * 1024, 256 * 1024}) {
            for(size_t t : {1, 4}) {
               for(size_t p : {1, 4}) {
                  auto pwhash = pwhash_fam->from_params(M, t, p);
                  auto timer = config.make_timer(pwhash->to_string());

                  uint8_t out[64];
                  uint8_t salt[16];
                  config.rng().randomize(salt, sizeof(salt));

                  while(timer->under(msec)) {
                     timer->run([&] { pwhash->derive_key(out, sizeof(out), "password", 8, salt, sizeof(salt)); });
                  }

                  config.record_result(*timer);
               }
            }
         }
      }
};

BOTAN_REGISTER_PERF_TEST("argon2", PerfTest_Argon2);

#endif

}  // namespace Botan_CLI
