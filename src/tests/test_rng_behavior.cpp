/*
* (C) 2014,2015,2017 Jack Lloyd
* (C) 2016 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "test_rng.h"
#include "tests.h"

#include <botan/internal/target_info.h>

#if defined(BOTAN_HAS_STATEFUL_RNG)
   #include <botan/stateful_rng.h>
#endif

#if defined(BOTAN_HAS_HMAC_DRBG)
   #include <botan/hmac_drbg.h>
#endif

#if defined(BOTAN_HAS_AUTO_RNG)
   #include <botan/auto_rng.h>
#endif

#if defined(BOTAN_HAS_CHACHA_RNG)
   #include <botan/chacha_rng.h>
#endif

#if defined(BOTAN_HAS_SYSTEM_RNG)
   #include <botan/system_rng.h>
#endif

#if defined(BOTAN_HAS_PROCESSOR_RNG)
   #include <botan/processor_rng.h>
#endif

#if defined(BOTAN_HAS_ENTROPY_SOURCE)
   #include <botan/entropy_src.h>
#endif

#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   #include <sys/wait.h>
   #include <unistd.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_STATEFUL_RNG)

class Stateful_RNG_Tests : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;
         results.push_back(test_reseed_kat());
         results.push_back(test_reseed());
         results.push_back(test_reseed_interval_limits());
         results.push_back(test_max_number_of_bytes_per_request());
         results.push_back(test_broken_entropy_input());
         results.push_back(test_check_nonce());
         results.push_back(test_prediction_resistance());
         results.push_back(test_randomize_with_ts_input());
         results.push_back(test_security_level());
         results.push_back(test_input_output_edge_cases());

         /*
         * This test uses the library in both parent and child processes. But
         * this causes a race with other threads, where if any other test thread
         * is holding the mlock pool mutex, it is killed after the fork. Then,
         * in the child, any attempt to allocate or free memory will cause a
         * deadlock.
         */
         if(Test::options().test_threads() == 1) {
            results.push_back(test_fork_safety());
         }

         return results;
      }

   protected:
      virtual std::string rng_name() const = 0;

      virtual std::unique_ptr<Botan::Stateful_RNG> create_rng(Botan::RandomNumberGenerator* underlying_rng,
                                                              Botan::Entropy_Sources* underlying_es,
                                                              size_t reseed_interval) = 0;

      std::unique_ptr<Botan::Stateful_RNG> make_rng(Botan::RandomNumberGenerator& underlying_rng,
                                                    size_t reseed_interval = 1024) {
         return create_rng(&underlying_rng, nullptr, reseed_interval);
      }

      std::unique_ptr<Botan::Stateful_RNG> make_rng(Botan::Entropy_Sources& underlying_srcs,
                                                    size_t reseed_interval = 1024) {
         return create_rng(nullptr, &underlying_srcs, reseed_interval);
      }

      std::unique_ptr<Botan::Stateful_RNG> make_rng(Botan::RandomNumberGenerator& underlying_rng,
                                                    Botan::Entropy_Sources& underlying_srcs,
                                                    size_t reseed_interval = 1024) {
         return create_rng(&underlying_rng, &underlying_srcs, reseed_interval);
      }

      virtual Test::Result test_reseed_kat() = 0;

      virtual Test::Result test_security_level() = 0;

      virtual Test::Result test_max_number_of_bytes_per_request() = 0;

      virtual Test::Result test_reseed_interval_limits() = 0;

   private:
      Test::Result test_reseed() {
         Test::Result result(rng_name() + " Reseed");

         // test reseed_interval is enforced
         Request_Counting_RNG counting_rng;

         auto rng = make_rng(counting_rng, 2);

         rng->random_vec(7);
         result.test_eq("initial seeding", counting_rng.randomize_count(), 1);
         rng->random_vec(9);
         result.test_eq("still initial seed", counting_rng.randomize_count(), 1);

         rng->random_vec(1);
         result.test_eq("first reseed", counting_rng.randomize_count(), 2);
         rng->random_vec(15);
         result.test_eq("still first reseed", counting_rng.randomize_count(), 2);

         rng->random_vec(15);
         result.test_eq("second reseed", counting_rng.randomize_count(), 3);
         rng->random_vec(1);
         result.test_eq("still second reseed", counting_rng.randomize_count(), 3);

         if(rng->max_number_of_bytes_per_request() > 0) {
            // request > max_number_of_bytes_per_request, do reseeds occur?
            rng->random_vec(64 * 1024 + 1);
            result.test_eq("request exceeds output limit", counting_rng.randomize_count(), 4);

            rng->random_vec(9 * 64 * 1024 + 1);
            result.test_eq("request exceeds output limit", counting_rng.randomize_count(), 9);
         }

         return result;
      }

      Test::Result test_broken_entropy_input() {
         Test::Result result(rng_name() + " Broken Entropy Input");

   #if defined(BOTAN_HAS_ENTROPY_SOURCE)
         class Broken_Entropy_Source final : public Botan::Entropy_Source {
            public:
               std::string name() const override { return "Broken Entropy Source"; }

               size_t poll(Botan::RandomNumberGenerator& /*rng*/) override {
                  throw Botan::Not_Implemented("polling not available");
               }
         };

         class Insufficient_Entropy_Source final : public Botan::Entropy_Source {
            public:
               std::string name() const override { return "Insufficient Entropy Source"; }

               size_t poll(Botan::RandomNumberGenerator& /*rng*/) override { return 0; }
         };
   #endif

         // make sure no output is generated when the entropy input source is broken

         // underlying_rng throws exception
         Botan::Null_RNG broken_entropy_input_rng;
         result.test_eq("Null_RNG not seeded", broken_entropy_input_rng.is_seeded(), false);
         auto rng_with_broken_rng = make_rng(broken_entropy_input_rng);

         result.test_throws("broken underlying rng", [&rng_with_broken_rng]() { rng_with_broken_rng->random_vec(16); });

   #if defined(BOTAN_HAS_ENTROPY_SOURCE)

         // entropy_sources throw exception
         auto broken_entropy_source_1 = std::make_unique<Broken_Entropy_Source>();
         auto broken_entropy_source_2 = std::make_unique<Broken_Entropy_Source>();

         Botan::Entropy_Sources broken_entropy_sources;
         broken_entropy_sources.add_source(std::move(broken_entropy_source_1));
         broken_entropy_sources.add_source(std::move(broken_entropy_source_2));

         auto rng_with_broken_es = make_rng(broken_entropy_sources);
         result.test_throws("broken entropy sources", [&rng_with_broken_es]() { rng_with_broken_es->random_vec(16); });

         // entropy source returns insufficient entropy
         Botan::Entropy_Sources insufficient_entropy_sources;
         auto insufficient_entropy_source = std::make_unique<Insufficient_Entropy_Source>();
         insufficient_entropy_sources.add_source(std::move(insufficient_entropy_source));

         auto rng_with_insufficient_es = make_rng(insufficient_entropy_sources);
         result.test_throws("insufficient entropy source",
                            [&rng_with_insufficient_es]() { rng_with_insufficient_es->random_vec(16); });

         // one of or both underlying_rng and entropy_sources throw exception

         auto rng_with_broken_rng_and_good_es =
            make_rng(broken_entropy_input_rng, Botan::Entropy_Sources::global_sources());

         result.test_throws("broken underlying rng but good entropy sources",
                            [&rng_with_broken_rng_and_good_es]() { rng_with_broken_rng_and_good_es->random_vec(16); });

         auto rng_with_good_rng_and_broken_es = make_rng(this->rng(), broken_entropy_sources);

         result.test_throws("good underlying rng but broken entropy sources",
                            [&rng_with_good_rng_and_broken_es]() { rng_with_good_rng_and_broken_es->random_vec(16); });

         auto rng_with_broken_rng_and_broken_es = make_rng(broken_entropy_input_rng, broken_entropy_sources);

         result.test_throws("underlying rng and entropy sources broken", [&rng_with_broken_rng_and_broken_es]() {
            rng_with_broken_rng_and_broken_es->random_vec(16);
         });
   #endif

         return result;
      }

      Test::Result test_check_nonce() {
         Test::Result result(rng_name() + " Nonce Check");

         // make sure the nonce has at least security_strength bits
         auto rng = create_rng(nullptr, nullptr, 0);

         for(size_t nonce_size : {0, 4, 8, 16, 31, 32, 34, 64}) {
            rng->clear();
            result.test_eq("not seeded", rng->is_seeded(), false);

            const std::vector<uint8_t> nonce(nonce_size);
            rng->initialize_with(nonce.data(), nonce.size());

            if(nonce_size < rng->security_level() / 8) {
               result.test_eq("not seeded", rng->is_seeded(), false);
               result.test_throws("invalid nonce size", [&rng]() { rng->random_vec(32); });
            } else {
               result.test_eq("is seeded", rng->is_seeded(), true);
               rng->random_vec(32);
            }
         }

         return result;
      }

      Test::Result test_prediction_resistance() {
         Test::Result result(rng_name() + " Prediction Resistance");

         // set reseed_interval = 1, forcing a reseed for every RNG request
         Request_Counting_RNG counting_rng;
         auto rng = make_rng(counting_rng, 1);

         rng->random_vec(16);
         result.test_eq("first request", counting_rng.randomize_count(), size_t(1));

         rng->random_vec(16);
         result.test_eq("second request", counting_rng.randomize_count(), size_t(2));

         rng->random_vec(16);
         result.test_eq("third request", counting_rng.randomize_count(), size_t(3));

         return result;
      }

      Test::Result test_fork_safety() {
         Test::Result result(rng_name() + " Fork Safety");

   #if defined(BOTAN_TARGET_OS_HAS_POSIX1)
         const size_t reseed_interval = 1024;

         // make sure rng is reseeded after every fork
         Request_Counting_RNG counting_rng;
         auto rng = make_rng(counting_rng, reseed_interval);

         rng->random_vec(16);
         result.test_eq("first request", counting_rng.randomize_count(), size_t(1));

         // fork and request from parent and child, both should output different sequences
         size_t count = counting_rng.randomize_count();
         Botan::secure_vector<uint8_t> parent_bytes(16);
         Botan::secure_vector<uint8_t> child_bytes(16);
         int fd[2];
         int rc = ::pipe(fd);
         if(rc != 0) {
            result.test_failure("failed to create pipe");
         }

         pid_t pid = ::fork();
         if(pid == -1) {
      #if defined(BOTAN_TARGET_OS_IS_EMSCRIPTEN)
            result.test_note("failed to fork process");
      #else
            result.test_failure("failed to fork process");
      #endif
            return result;
         } else if(pid != 0) {
            // parent process, wait for randomize_count from child's rng
            ::close(fd[1]);  // close write end in parent
            ssize_t got = ::read(fd[0], &count, sizeof(count));

            if(got > 0) {
               result.test_eq("expected bytes from child", got, sizeof(count));
               result.test_eq("parent not reseeded", counting_rng.randomize_count(), 1);
               result.test_eq("child reseed occurred", count, 2);
            } else {
               result.test_failure("Failed to read count size from child process");
            }

            parent_bytes = rng->random_vec(16);
            got = ::read(fd[0], child_bytes.data(), child_bytes.size());

            if(got > 0) {
               result.test_eq("expected bytes from child", got, child_bytes.size());
               result.test_ne("parent and child output sequences differ", parent_bytes, child_bytes);
            } else {
               result.test_failure("Failed to read RNG bytes from child process");
            }
            ::close(fd[0]);  // close read end in parent

            // wait for the child to exit
            int status = 0;
            ::waitpid(pid, &status, 0);
         } else {
            // child process, send randomize_count and first output sequence back to parent
            ::close(fd[0]);  // close read end in child
            rng->randomize(child_bytes.data(), child_bytes.size());
            count = counting_rng.randomize_count();
            ssize_t written = ::write(fd[1], &count, sizeof(count));
            BOTAN_UNUSED(written);
            try {
               rng->randomize(child_bytes.data(), child_bytes.size());
            } catch(std::exception& e) {
               static_cast<void>(fprintf(stderr, "%s", e.what()));  // NOLINT(*-vararg)
            }
            written = ::write(fd[1], child_bytes.data(), child_bytes.size());
            BOTAN_UNUSED(written);
            ::close(fd[1]);  // close write end in child

            /*
            * We can't call exit because it causes the mlock pool to be freed (#602)
            * We can't call _exit because it makes valgrind think we leaked memory.
            * So instead we execute something that will return 0 for us.
            */
            ::execl("/bin/true", "true", NULL);  // NOLINT(*-vararg)
            ::_exit(0);                          // just in case /bin/true isn't available (sandbox?)
         }
   #endif
         return result;
      }

      Test::Result test_randomize_with_ts_input() {
         Test::Result result(rng_name() + " Randomize With Timestamp Input");

         const size_t request_bytes = 64;
         const std::vector<uint8_t> seed(128);

         // check that randomize_with_ts_input() creates different output based on a timestamp
         // and possibly additional data, such as process id even with identical seeds
         Fixed_Output_RNG fixed_output_rng1(seed);
         Fixed_Output_RNG fixed_output_rng2(seed);

         auto rng1 = make_rng(fixed_output_rng1);
         auto rng2 = make_rng(fixed_output_rng2);

         Botan::secure_vector<uint8_t> output1(request_bytes);
         Botan::secure_vector<uint8_t> output2(request_bytes);

         rng1->randomize(output1.data(), output1.size());
         rng2->randomize(output2.data(), output2.size());

         result.test_eq("equal output due to same seed", output1, output2);

         rng1->randomize_with_ts_input(output1.data(), output1.size());
         rng2->randomize_with_ts_input(output2.data(), output2.size());

         result.test_ne("output differs due to different timestamp", output1, output2);

         return result;
      }

      Test::Result test_input_output_edge_cases() {
         Test::Result result(rng_name() + " randomize");

         const std::vector<uint8_t> seed(128);
         Fixed_Output_RNG fixed_output_rng(seed);

         auto rng = make_rng(fixed_output_rng);

         for(size_t i = 0; i != 4096; ++i) {
            std::vector<uint8_t> buf(i);
            rng->randomize(buf.data(), buf.size());
            rng->add_entropy(buf.data(), buf.size());

            result.test_success("RNG accepted input and output length");
         }

         return result;
      }
};

#endif

#if defined(BOTAN_HAS_HMAC_DRBG) && defined(BOTAN_HAS_SHA2_32)

class HMAC_DRBG_Unit_Tests final : public Stateful_RNG_Tests {
   public:
      std::string rng_name() const override { return "HMAC_DRBG"; }

      std::unique_ptr<Botan::Stateful_RNG> create_rng(Botan::RandomNumberGenerator* underlying_rng,
                                                      Botan::Entropy_Sources* underlying_es,
                                                      size_t reseed_interval) override {
         std::unique_ptr<Botan::MessageAuthenticationCode> mac =
            Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");

         if(underlying_rng != nullptr && underlying_es != nullptr) {
            return std::make_unique<Botan::HMAC_DRBG>(std::move(mac), *underlying_rng, *underlying_es, reseed_interval);
         } else if(underlying_rng != nullptr) {
            return std::make_unique<Botan::HMAC_DRBG>(std::move(mac), *underlying_rng, reseed_interval);
         } else if(underlying_es != nullptr) {
            return std::make_unique<Botan::HMAC_DRBG>(std::move(mac), *underlying_es, reseed_interval);
         } else if(reseed_interval == 0) {
            return std::make_unique<Botan::HMAC_DRBG>(std::move(mac));
         } else {
            throw Test_Error("Invalid reseed interval in HMAC_DRBG unit test");
         }
      }

      Test::Result test_max_number_of_bytes_per_request() override {
         Test::Result result("HMAC_DRBG max_number_of_bytes_per_request");

         const std::string mac_string = "HMAC(SHA-256)";

         Request_Counting_RNG counting_rng;

         result.test_throws(
            "HMAC_DRBG does not accept 0 for max_number_of_bytes_per_request", [&mac_string, &counting_rng]() {
               Botan::HMAC_DRBG failing_rng(Botan::MessageAuthenticationCode::create(mac_string), counting_rng, 2, 0);
            });

         result.test_throws("HMAC_DRBG does not accept values higher than 64KB for max_number_of_bytes_per_request",
                            [&mac_string, &counting_rng]() {
                               Botan::HMAC_DRBG failing_rng(
                                  Botan::MessageAuthenticationCode::create(mac_string), counting_rng, 2, 64 * 1024 + 1);
                            });

         // set reseed_interval to 1 so we can test that a long request is split
         // into multiple, max_number_of_bytes_per_request long requests
         // for each smaller request, reseed_check() calls counting_rng::randomize(),
         // which we can compare with
         Botan::HMAC_DRBG rng(Botan::MessageAuthenticationCode::create(mac_string), counting_rng, 1, 64);

         rng.random_vec(63);
         result.test_eq("one request", counting_rng.randomize_count(), 1);

         rng.clear();
         counting_rng.clear();

         rng.random_vec(64);
         result.test_eq("one request", counting_rng.randomize_count(), 1);

         rng.clear();
         counting_rng.clear();

         rng.random_vec(65);
         result.test_eq("two requests", counting_rng.randomize_count(), 2);

         rng.clear();
         counting_rng.clear();

         rng.random_vec(1025);
         result.test_eq("17 requests", counting_rng.randomize_count(), 17);

         return result;
      }

      Test::Result test_reseed_interval_limits() override {
         Test::Result result("HMAC_DRBG reseed_interval limits");

         const std::string mac_string = "HMAC(SHA-256)";

         Request_Counting_RNG counting_rng;

         result.test_throws("HMAC_DRBG does not accept 0 for reseed_interval", [&mac_string, &counting_rng]() {
            Botan::HMAC_DRBG failing_rng(Botan::MessageAuthenticationCode::create(mac_string), counting_rng, 0);
         });

         result.test_throws("HMAC_DRBG does not accept values higher than 2^24 for reseed_interval",
                            [&mac_string, &counting_rng]() {
                               Botan::HMAC_DRBG failing_rng(Botan::MessageAuthenticationCode::create(mac_string),
                                                            counting_rng,
                                                            (static_cast<size_t>(1) << 24) + 1);
                            });

         return result;
      }

      Test::Result test_security_level() override {
         Test::Result result("HMAC_DRBG Security Level");

         std::vector<std::string> approved_hash_fns{"SHA-1", "SHA-224", "SHA-256", "SHA-512/256", "SHA-384", "SHA-512"};
         std::vector<uint32_t> security_strengths{128, 192, 256, 256, 256, 256};

         for(size_t i = 0; i < approved_hash_fns.size(); ++i) {
            const auto& hash_fn = approved_hash_fns[i];
            const size_t expected_security_level = security_strengths[i];

            const std::string mac_name = "HMAC(" + hash_fn + ")";
            auto mac = Botan::MessageAuthenticationCode::create(mac_name);
            if(!mac) {
               result.note_missing(mac_name);
               continue;
            }

            Botan::HMAC_DRBG rng(std::move(mac));
            result.test_eq(hash_fn + " security level", rng.security_level(), expected_security_level);
         }

         return result;
      }

      Test::Result test_reseed_kat() override {
         Test::Result result("HMAC_DRBG Reseed KAT");

         Request_Counting_RNG counting_rng;
         auto rng = make_rng(counting_rng, 2);

         const Botan::secure_vector<uint8_t> seed_input(
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
             0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF});

         result.test_eq("is_seeded", rng->is_seeded(), false);

         rng->initialize_with(seed_input.data(), seed_input.size());

         Botan::secure_vector<uint8_t> out(32);

         rng->randomize(out.data(), out.size());
         result.test_eq("underlying RNG calls", counting_rng.randomize_count(), size_t(0));
         result.test_eq("out before reseed", out, "48D3B45AAB65EF92CCFCB9427EF20C90297065ECC1B8A525BFE4DC6FF36D0E38");

         // reseed must happen here
         rng->randomize(out.data(), out.size());
         result.test_eq("underlying RNG calls", counting_rng.randomize_count(), size_t(1));
         result.test_eq("out after reseed", out, "2F8FCA696832C984781123FD64F4B20C7379A25C87AB29A21C9BF468B0081CE2");

         return result;
      }
};

std::vector<Test::Result> hmac_drbg_multiple_requests() {
   auto null_rng = Botan::Null_RNG();
   constexpr auto rng_max_output = 1024;
   const auto seed = Botan::hex_decode("deadbeefbaadcafedeadbeefbaadcafedeadbeefbaadcafedeadbeefbaadcafe");

   auto make_seeded_rng = [&](size_t reseed_interval) {
      auto rng = std::make_unique<Botan::HMAC_DRBG>(Botan::MessageAuthenticationCode::create("HMAC(SHA-256)"),
                                                    null_rng,
                                                    reseed_interval + 1 /* off by one */,
                                                    rng_max_output);
      rng->add_entropy(seed);
      return rng;
   };

   return {CHECK("bulk and split output without input",
                 [&](auto& result) {
                    auto rng1 = make_seeded_rng(2);
                    auto rng2 = make_seeded_rng(2);

                    result.confirm("RNG 1 is seeded and ready to go", rng1->is_seeded());
                    result.confirm("RNG 2 is seeded and ready to go", rng2->is_seeded());

                    auto bulk = rng1->random_vec<std::vector<uint8_t>>(2 * rng_max_output);

                    auto split1 = rng2->random_vec<std::vector<uint8_t>>(rng_max_output);
                    auto split2 = rng2->random_vec<std::vector<uint8_t>>(rng_max_output);
                    split1.insert(split1.end(), split2.begin(), split2.end());

                    result.test_eq("Output is equal, regardless bulk request", bulk, split1);

                    return result;
                 }),

           CHECK("bulk and split output with input", [&](auto& result) {
              auto rng1 = make_seeded_rng(3);
              auto rng2 = make_seeded_rng(3);

              result.confirm("RNG 1 is seeded and ready to go", rng1->is_seeded());
              result.confirm("RNG 2 is seeded and ready to go", rng2->is_seeded());

              std::vector<uint8_t> bulk(3 * rng_max_output);
              rng1->randomize_with_input(bulk, seed);

              std::vector<uint8_t> split(3 * rng_max_output);
              std::span<uint8_t> split_span(split);
              rng2->randomize_with_input(split_span.subspan(0, rng_max_output), seed);
              rng2->randomize_with_input(split_span.subspan(rng_max_output, rng_max_output), {});
              rng2->randomize_with_input(split_span.subspan(2 * rng_max_output), {});

              result.test_eq("Output is equal, regardless bulk request", bulk, split);

              return result;
           })};
}

BOTAN_REGISTER_TEST("rng", "hmac_drbg_unit", HMAC_DRBG_Unit_Tests);
BOTAN_REGISTER_TEST_FN("rng", "hmac_drbg_multi_request", hmac_drbg_multiple_requests);

#endif

#if defined(BOTAN_HAS_CHACHA_RNG)

class ChaCha_RNG_Unit_Tests final : public Stateful_RNG_Tests {
   public:
      std::string rng_name() const override { return "ChaCha_RNG"; }

      std::unique_ptr<Botan::Stateful_RNG> create_rng(Botan::RandomNumberGenerator* underlying_rng,
                                                      Botan::Entropy_Sources* underlying_es,
                                                      size_t reseed_interval) override {
         if(underlying_rng != nullptr && underlying_es != nullptr) {
            return std::make_unique<Botan::ChaCha_RNG>(*underlying_rng, *underlying_es, reseed_interval);
         } else if(underlying_rng != nullptr) {
            return std::make_unique<Botan::ChaCha_RNG>(*underlying_rng, reseed_interval);
         } else if(underlying_es != nullptr) {
            return std::make_unique<Botan::ChaCha_RNG>(*underlying_es, reseed_interval);
         } else if(reseed_interval == 0) {
            return std::make_unique<Botan::ChaCha_RNG>();
         } else {
            throw Test_Error("Invalid reseed interval in ChaCha_RNG unit test");
         }
      }

      Test::Result test_security_level() override {
         Test::Result result("ChaCha_RNG Security Level");
         Botan::ChaCha_RNG rng;
         result.test_eq("Expected security level", rng.security_level(), size_t(256));
         return result;
      }

      Test::Result test_max_number_of_bytes_per_request() override {
         Test::Result result("ChaCha_RNG max_number_of_bytes_per_request");
         // ChaCha_RNG doesn't have this notion
         return result;
      }

      Test::Result test_reseed_interval_limits() override {
         Test::Result result("ChaCha_RNG reseed_interval limits");
         // ChaCha_RNG doesn't apply any limits to reseed_interval
         return result;
      }

      Test::Result test_reseed_kat() override {
         Test::Result result("ChaCha_RNG Reseed KAT");

         Request_Counting_RNG counting_rng;
         auto rng = make_rng(counting_rng, 3);

         const Botan::secure_vector<uint8_t> seed_input(32);

         result.test_eq("is_seeded", rng->is_seeded(), false);

         rng->initialize_with(seed_input.data(), seed_input.size());

         Botan::secure_vector<uint8_t> out(32);

         rng->randomize(out.data(), out.size());
         result.test_eq("underlying RNG calls", counting_rng.randomize_count(), size_t(0));
         result.test_eq("out before reseed", out, "DEBC38FA382AF877C94999F25D460234F3EFED6D578C6C57EB8087999B337F3F");

         rng->randomize(out.data(), out.size());
         result.test_eq("underlying RNG calls", counting_rng.randomize_count(), size_t(0));
         result.test_eq("out before reseed", out, "3C450EA13C2CA57112805A7C7A76657DA7F19F2FCBA633A84CE816A296179C80");

         // reseed must happen here
         rng->randomize(out.data(), out.size());
         result.test_eq("underlying RNG calls", counting_rng.randomize_count(), size_t(1));
         result.test_eq("out after reseed", out, "F913E2A2D9B7E0CB016D53B43C36595DB7B5A11A48EC1341433FF57EC313A867");

         return result;
      }
};

BOTAN_REGISTER_TEST("rng", "chacha_rng_unit", ChaCha_RNG_Unit_Tests);

class ChaCha_RNG_FKE_Unit_Tests final : public Stateful_RNG_Tests {
   public:
      std::string rng_name() const override { return "ChaCha_RNG(FKE)"; }

      std::unique_ptr<Botan::Stateful_RNG> create_rng(Botan::RandomNumberGenerator* underlying_rng,
                                                      Botan::Entropy_Sources* underlying_es,
                                                      size_t reseed_interval) override {
         if(underlying_rng != nullptr && underlying_es != nullptr) {
            return std::make_unique<Botan::ChaCha_RNG>(*underlying_rng, *underlying_es, reseed_interval, true);
         } else if(underlying_rng != nullptr) {
            return std::make_unique<Botan::ChaCha_RNG>(*underlying_rng, reseed_interval, true);
         } else if(underlying_es != nullptr) {
            return std::make_unique<Botan::ChaCha_RNG>(*underlying_es, reseed_interval, true);
         } else if(reseed_interval == 0) {
            return std::make_unique<Botan::ChaCha_RNG>(true);
         } else {
            throw Test_Error("Invalid reseed interval in ChaCha_RNG(FKE) unit test");
         }
      }

      Test::Result test_security_level() override {
         Test::Result result("ChaCha_RNG(FKE) Security Level");
         Botan::ChaCha_RNG rng;
         result.test_eq("Expected security level", rng.security_level(), size_t(256));
         return result;
      }

      Test::Result test_max_number_of_bytes_per_request() override {
         Test::Result result("ChaCha_RNG(FKE) max_number_of_bytes_per_request");
         // ChaCha_RNG doesn't have this notion
         return result;
      }

      Test::Result test_reseed_interval_limits() override {
         Test::Result result("ChaCha_RNG(FKE) reseed_interval limits");
         // ChaCha_RNG doesn't apply any limits to reseed_interval
         return result;
      }

      Test::Result test_reseed_kat() override {
         Test::Result result("ChaCha_RNG(FKE) Reseed KAT");

         Request_Counting_RNG counting_rng;
         auto rng = make_rng(counting_rng, 3);

         const Botan::secure_vector<uint8_t> seed_input(32);

         result.test_eq("is_seeded", rng->is_seeded(), false);

         rng->initialize_with(seed_input.data(), seed_input.size());

         Botan::secure_vector<uint8_t> out(32);

         rng->randomize(out.data(), out.size());
         result.test_eq("underlying RNG calls", counting_rng.randomize_count(), size_t(0));
         result.test_eq("out before reseed", out, "12805A7C7A76657DA7F19F2FCBA633A84CE816A296179C805EBDA300C1CA100C");

         rng->randomize(out.data(), out.size());
         result.test_eq("underlying RNG calls", counting_rng.randomize_count(), size_t(0));
         result.test_eq("out before reseed", out, "06998802D70DFC5D1141E4C39A6A5498EB4E75923B5E2F78D3C780542C19753E");

         // reseed must happen here
         rng->randomize(out.data(), out.size());
         result.test_eq("underlying RNG calls", counting_rng.randomize_count(), size_t(1));
         result.test_eq("out after reseed", out, "D203EB11C3F14A0341C5A6D8F2FA7FAA10C1FD2162507CA679B45F2024E72890");

         return result;
      }
};

BOTAN_REGISTER_TEST("rng", "chacha_rng_fke_unit", ChaCha_RNG_FKE_Unit_Tests);

#endif

#if defined(BOTAN_HAS_AUTO_RNG)

class AutoSeeded_RNG_Tests final : public Test {
   private:
      static Test::Result auto_rng_tests() {
         Test::Result result("AutoSeeded_RNG");

         Botan::Null_RNG null_rng;

         result.test_eq("Null_RNG is null", null_rng.is_seeded(), false);

         try {
            Botan::AutoSeeded_RNG rng(null_rng);
         } catch(Botan::PRNG_Unseeded&) {
            result.test_success("AutoSeeded_RNG rejected useless RNG");
         }

   #if defined(BOTAN_HAS_ENTROPY_SOURCE)
         Botan::Entropy_Sources no_entropy_for_you;

         try {
            Botan::AutoSeeded_RNG rng(no_entropy_for_you);
            result.test_failure("AutoSeeded_RNG should have rejected useless entropy source");
         } catch(Botan::PRNG_Unseeded&) {
            result.test_success("AutoSeeded_RNG rejected empty entropy source");
         }

         try {
            Botan::AutoSeeded_RNG rng(null_rng, no_entropy_for_you);
         } catch(Botan::PRNG_Unseeded&) {
            result.test_success("AutoSeeded_RNG rejected useless RNG+entropy sources");
         }
   #endif

         Botan::AutoSeeded_RNG rng;

         result.confirm("AutoSeeded_RNG::name", rng.name().starts_with("HMAC_DRBG(HMAC(SHA-"));

         result.confirm("AutoSeeded_RNG starts seeded", rng.is_seeded());
         rng.random_vec(16);  // generate and discard output
         rng.clear();
         result.test_eq("AutoSeeded_RNG unseeded after calling clear", rng.is_seeded(), false);

         // AutoSeeded_RNG automatically reseeds as required:
         rng.random_vec(16);
         result.confirm("AutoSeeded_RNG can be reseeded", rng.is_seeded());

         result.confirm("AutoSeeded_RNG ", rng.is_seeded());
         rng.random_vec(16);  // generate and discard output
         rng.clear();
         result.test_eq("AutoSeeded_RNG unseeded after calling clear", rng.is_seeded(), false);

   #if defined(BOTAN_HAS_ENTROPY_SOURCE)
         const size_t no_entropy_bits = rng.reseed(no_entropy_for_you, 256, std::chrono::milliseconds(300));
         result.test_eq("AutoSeeded_RNG can't reseed from nothing", no_entropy_bits, 0);
         result.test_eq("AutoSeeded_RNG still unseeded", rng.is_seeded(), false);
   #endif

         rng.random_vec(16);  // generate and discard output
         result.confirm("AutoSeeded_RNG can be reseeded", rng.is_seeded());

         for(size_t i = 0; i != 4096; ++i) {
            std::vector<uint8_t> buf(i);
            rng.randomize(buf.data(), buf.size());
            rng.add_entropy(buf.data(), buf.size());

            result.test_success("AutoSeeded_RNG accepted input and output length");
         }

         rng.clear();

         return result;
      }

   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;
         results.push_back(auto_rng_tests());
         return results;
      }
};

BOTAN_REGISTER_TEST("rng", "auto_rng_unit", AutoSeeded_RNG_Tests);

#endif

#if defined(BOTAN_HAS_SYSTEM_RNG)

class System_RNG_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("System_RNG");

         Botan::System_RNG rng;

         result.test_gte("Some non-empty name is returned", rng.name().size(), 1);

         result.confirm("System RNG always seeded", rng.is_seeded());
         rng.clear();  // clear is a noop for system rng
         result.confirm("System RNG always seeded", rng.is_seeded());

   #if defined(BOTAN_HAS_ENTROPY_SOURCE)
         rng.reseed(Botan::Entropy_Sources::global_sources(), 256, std::chrono::milliseconds(100));
   #endif

         for(size_t i = 0; i != 128; ++i) {
            std::vector<uint8_t> out_buf(i);
            rng.randomize(out_buf.data(), out_buf.size());
            rng.add_entropy(out_buf.data(), out_buf.size());
         }

         if(Test::run_long_tests() && Test::run_memory_intensive_tests() && (sizeof(size_t) > 4)) {
            // Pass buffer with a size greater than 32bit
            const size_t size32BitsMax = std::numeric_limits<uint32_t>::max();
            const size_t checkSize = 1024;
            std::vector<uint8_t> large_buf(size32BitsMax + checkSize);
            std::memset(large_buf.data() + size32BitsMax, 0xFE, checkSize);

            rng.randomize(large_buf.data(), large_buf.size());

            std::vector<uint8_t> check_buf(checkSize, 0xFE);

            result.confirm("System RNG failed to write after 4GB boundary",
                           std::memcmp(large_buf.data() + size32BitsMax, check_buf.data(), checkSize) != 0);
         }

         return std::vector<Test::Result>{result};
      }
};

BOTAN_REGISTER_TEST("rng", "system_rng", System_RNG_Tests);

#endif

#if defined(BOTAN_HAS_PROCESSOR_RNG)

class Processor_RNG_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("Processor_RNG");

         if(Botan::Processor_RNG::available()) {
            Botan::Processor_RNG rng;

            result.test_ne("Has a name", rng.name(), "");
            result.confirm("CPU RNG always seeded", rng.is_seeded());
            rng.clear();  // clear is a noop for rdrand
            result.confirm("CPU RNG always seeded", rng.is_seeded());

   #if defined(BOTAN_HAS_ENTROPY_SOURCE)
            size_t reseed_bits = rng.reseed(Botan::Entropy_Sources::global_sources(), 256, std::chrono::seconds(1));
            result.test_eq("CPU RNG cannot consume inputs", reseed_bits, size_t(0));
   #endif

            /*
            Processor_RNG ignores add_entropy calls - confirm this by passing
            an invalid ptr/length field to add_entropy. If it examined its
            arguments, it would crash...
            */
            // NOLINTNEXTLINE(*-no-int-to-ptr)
            const uint8_t* invalid_ptr = reinterpret_cast<const uint8_t*>(static_cast<uintptr_t>(0xDEADC0DE));
            const size_t invalid_ptr_len = 64 * 1024;
            rng.add_entropy(invalid_ptr, invalid_ptr_len);

            for(size_t i = 0; i != 128; ++i) {
               std::vector<uint8_t> out_buf(i);
               rng.randomize(out_buf.data(), out_buf.size());
            }
         } else {
            result.test_throws("Processor_RNG throws if instruction not available", []() { Botan::Processor_RNG rng; });
         }

         return std::vector<Test::Result>{result};
      }
};

BOTAN_REGISTER_TEST("rng", "processor_rng", Processor_RNG_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
