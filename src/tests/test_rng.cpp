/*
* (C) 2014,2015 Jack Lloyd
* (C) 2016 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include "test_rng.h"

#if defined(BOTAN_HAS_HMAC_DRBG)
  #include <botan/hmac_drbg.h>
#endif

#if defined(BOTAN_HAS_X931_RNG)
  #include <botan/x931_rng.h>
#endif

#if defined(BOTAN_HAS_ENTROPY_SOURCE)
  #include <botan/entropy_src.h>
#endif

#if defined(BOTAN_TARGET_OS_TYPE_IS_UNIX)
  #include <unistd.h>
  #include <sys/wait.h>
#endif

#include <iostream>

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_X931_RNG)
class X931_RNG_Tests : public Text_Based_Test
   {
   public:
      X931_RNG_Tests() : Text_Based_Test("x931.vec", {"IKM", "Out"}) {}

      Test::Result run_one_test(const std::string& algo, const VarMap& vars) override
         {
         const std::vector<uint8_t> ikm      = get_req_bin(vars, "IKM");
         const std::vector<uint8_t> expected = get_req_bin(vars, "Out");

         Test::Result result("X9.31-RNG(" + algo + ")");

         std::unique_ptr<Botan::BlockCipher> bc = Botan::BlockCipher::create(algo);

         if(!bc)
            {
            result.note_missing("X9.31 cipher " + algo);
            return result;
            }

         Botan::ANSI_X931_RNG rng(bc.release(), new Fixed_Output_RNG(ikm));

         std::vector<uint8_t> output(expected.size());
         rng.randomize(output.data(), output.size());
         result.test_eq("rng", output, expected);

         return result;
         }

   };

BOTAN_REGISTER_TEST("x931_rng", X931_RNG_Tests);
#endif

#if defined(BOTAN_HAS_HMAC_DRBG)

class HMAC_DRBG_Tests : public Text_Based_Test
   {
   public:
      HMAC_DRBG_Tests() : Text_Based_Test("hmac_drbg.vec",
                                          {"EntropyInput", "EntropyInputReseed", "Out"},
                                          {"AdditionalInput1", "AdditionalInput2"}) {}

      Test::Result run_one_test(const std::string& algo, const VarMap& vars) override
         {
         const std::vector<byte> seed_input   = get_req_bin(vars, "EntropyInput");
         const std::vector<byte> reseed_input = get_req_bin(vars, "EntropyInputReseed");
         const std::vector<byte> expected     = get_req_bin(vars, "Out");

         const std::vector<byte> ad1 = get_opt_bin(vars, "AdditionalInput1");
         const std::vector<byte> ad2 = get_opt_bin(vars, "AdditionalInput2");

         Test::Result result("HMAC_DRBG(" + algo + ")");

         auto mac = Botan::MessageAuthenticationCode::create("HMAC(" + algo + ")");
         if(!mac)
            {
            result.note_missing("HMAC(" + algo + ")");
            return result;
            }

         std::unique_ptr<Botan::HMAC_DRBG> rng(new Botan::HMAC_DRBG(std::move(mac)));
         rng->initialize_with(seed_input.data(), seed_input.size());

         // now reseed
         rng->add_entropy(reseed_input.data(), reseed_input.size());

         std::vector<byte> out(expected.size());
         // first block is discarded
         rng->randomize_with_input(out.data(), out.size(), ad1.data(), ad1.size());
         rng->randomize_with_input(out.data(), out.size(), ad2.data(), ad2.size());

         result.test_eq("rng", out, expected);
         return result;
         }

   };

BOTAN_REGISTER_TEST("hmac_drbg", HMAC_DRBG_Tests);

class HMAC_DRBG_Unit_Tests : public Test
   {
   private:
      class Broken_Entropy_Source : public Botan::Entropy_Source
         {
         public:
            std::string name() const override { return "Broken Entropy Source"; }

            size_t poll(Botan::RandomNumberGenerator&) override
               {
               throw Botan::Exception("polling not available");
               }
         };

      class Insufficient_Entropy_Source : public Botan::Entropy_Source
         {
         public:
            std::string name() const override { return "Insufficient Entropy Source"; }

            size_t poll(Botan::RandomNumberGenerator&) override
               {
               return 0;
               }
         };

      class Request_Counting_RNG : public Botan::RandomNumberGenerator
         {
         public:
            Request_Counting_RNG() : m_randomize_count(0) {};

            bool is_seeded() const override { return true; }

            void clear() override {}

            void randomize(byte[], size_t) override
               {
               m_randomize_count++;
               }

            void add_entropy(const byte[], size_t) override {}

            std::string name() const override { return "Request_Counting_RNG"; }

            size_t randomize_count() { return m_randomize_count; }

         private:
            size_t m_randomize_count;
         };

   public:
      Test::Result test_reseed_kat()
         {
         Test::Result result("HMAC_DRBG Reseed KAT");

         auto mac = Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");
         if(!mac)
            {
            result.note_missing("HMAC(SHA-256)");
            return result;
            }

         Request_Counting_RNG counting_rng;
         Botan::HMAC_DRBG rng(std::move(mac), counting_rng, Botan::Entropy_Sources::global_sources(), 2);
         Botan::secure_vector<Botan::byte> seed_input(
               {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF});
         Botan::secure_vector<Botan::byte> output_after_initialization(
               {0x26,0x06,0x95,0xF4,0xB8,0x96,0x0D,0x0B,0x27,0x4E,0xA2,0x9E,0x8D,0x2B,0x5A,0x35});
         Botan::secure_vector<Botan::byte> output_without_reseed(
               {0xC4,0x90,0x04,0x5B,0x35,0x4F,0x50,0x09,0x68,0x45,0xF0,0x4B,0x11,0x03,0x58,0xF0});
         result.test_eq("is_seeded",rng.is_seeded(),false);

         rng.initialize_with(seed_input.data(), seed_input.size());

         Botan::secure_vector<Botan::byte> out(16);

         rng.randomize(out.data(), out.size());
         result.test_eq("underlying RNG calls", counting_rng.randomize_count(), size_t(0));
         result.test_eq("out before reseed", out, output_after_initialization);

         // reseed must happen here
         rng.randomize(out.data(), out.size());
         result.test_eq("underlying RNG calls", counting_rng.randomize_count(), size_t(1));
         result.test_ne("out after reseed", out, output_without_reseed);

         return result;
         }

      Test::Result test_reseed()
         {
         Test::Result result("HMAC_DRBG Reseed");

         auto mac = Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");
         if(!mac)
            {
            result.note_missing("HMAC(SHA-256)");
            return result;
            }

         // test reseed_interval is enforced
         Request_Counting_RNG counting_rng;
         Botan::HMAC_DRBG rng(std::move(mac), counting_rng, 2);

         rng.random_vec(7);
         result.test_eq("initial seeding", counting_rng.randomize_count(), 1);
         rng.random_vec(9);
         result.test_eq("still initial seed", counting_rng.randomize_count(), 1);

         rng.random_vec(1);
         result.test_eq("first reseed", counting_rng.randomize_count(), 2);
         rng.random_vec(15);
         result.test_eq("still first reseed", counting_rng.randomize_count(), 2);

         rng.random_vec(15);
         result.test_eq("second reseed", counting_rng.randomize_count(), 3);
         rng.random_vec(1);
         result.test_eq("still second reseed", counting_rng.randomize_count(), 3);

         // request > max_number_of_bits_per_request, do reseeds occur?
         rng.random_vec(64*1024 + 1);
         result.test_eq("request exceeds output limit", counting_rng.randomize_count(), 4);

         rng.random_vec(9*64*1024 + 1);
         result.test_eq("request exceeds output limit", counting_rng.randomize_count(), 9);

         return result;
         }

      Test::Result test_broken_entropy_input()
         {
         Test::Result result("HMAC_DRBG Broken Entropy Input");

         auto mac = Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");
         if(!mac)
            {
            result.note_missing("HMAC(SHA-256)");
            return result;
            }

         // make sure no output is generated when the entropy input source is broken

         const size_t reseed_interval = 1024;

         // underlying_rng throws exception
         Botan::Null_RNG broken_entropy_input_rng;
         Botan::HMAC_DRBG rng_with_broken_rng(std::move(mac), broken_entropy_input_rng, reseed_interval);

         result.test_throws("broken underlying rng", [&rng_with_broken_rng] () { rng_with_broken_rng.random_vec(16); });

         // entropy_sources throw exception
         std::unique_ptr<Broken_Entropy_Source> broken_entropy_source_1(new Broken_Entropy_Source());
         std::unique_ptr<Broken_Entropy_Source> broken_entropy_source_2(new Broken_Entropy_Source());

         Botan::Entropy_Sources broken_entropy_sources;
         broken_entropy_sources.add_source(std::move(broken_entropy_source_1));
         broken_entropy_sources.add_source(std::move(broken_entropy_source_2));

         mac = Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");
         Botan::HMAC_DRBG rng_with_broken_es(std::move(mac), broken_entropy_sources, reseed_interval);
         result.test_throws("broken entropy sources", [&rng_with_broken_es] () { rng_with_broken_es.random_vec(16); });

         // entropy source returns insufficient entropy
         Botan::Entropy_Sources insufficient_entropy_sources;
         std::unique_ptr<Insufficient_Entropy_Source> insufficient_entropy_source(new Insufficient_Entropy_Source());
         insufficient_entropy_sources.add_source(std::move(insufficient_entropy_source));

         mac = Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");
         Botan::HMAC_DRBG rng_with_insufficient_es(std::move(mac), insufficient_entropy_sources, reseed_interval);
         result.test_throws("insufficient entropy source", [&rng_with_insufficient_es] () { rng_with_insufficient_es.random_vec(16); });

         // one of or both underlying_rng and entropy_sources throw exception
         mac = Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");
         Botan::HMAC_DRBG rng_with_broken_rng_and_es(std::move(mac), broken_entropy_input_rng,
               Botan::Entropy_Sources::global_sources(), reseed_interval);
         result.test_throws("broken underlying rng but good entropy sources", [&rng_with_broken_rng_and_es] ()
                  { rng_with_broken_rng_and_es.random_vec(16); });

         mac = Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");
         Botan::HMAC_DRBG rng_with_rng_and_broken_es(std::move(mac), Test::rng(), broken_entropy_sources, reseed_interval);
         result.test_throws("good underlying rng but broken entropy sources", [&rng_with_rng_and_broken_es] ()
                  { rng_with_rng_and_broken_es.random_vec(16); });

         mac = Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");
         Botan::HMAC_DRBG rng_with_broken_rng_and_broken_es(std::move(mac), broken_entropy_input_rng, broken_entropy_sources, reseed_interval);
         result.test_throws("underlying rng and entropy sources broken", [&rng_with_broken_rng_and_broken_es] ()
                  { rng_with_broken_rng_and_broken_es.random_vec(16); });

         return result;
         }

      Test::Result test_check_nonce()
         {
         Test::Result result("HMAC_DRBG Nonce Check");

         auto mac = Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");
         if(!mac)
            {
            result.note_missing("HMAC(SHA-256)");
            return result;
            }

         // make sure the nonce has at least 1/2*security_strength bits

         // SHA-256 -> 128 bits security strength
         for( auto nonce_size : { 0, 4, 15, 16, 17, 32 } )
            {
            if(!mac)
               {
               mac = Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");
               }

            Botan::HMAC_DRBG rng(std::move(mac));
            result.test_eq("not seeded", rng.is_seeded(), false);
            std::vector<Botan::byte> nonce(nonce_size);
            rng.initialize_with(nonce.data(), nonce.size());

            if(nonce_size < 16)
               {
               result.test_eq("not seeded", rng.is_seeded(), false);
               result.test_throws("invalid nonce size", [&rng, &nonce] () { rng.random_vec(16); });
               }
            else
               {
               result.test_eq("is seeded", rng.is_seeded(), true);
               rng.random_vec(16);
               }
            }

         return result;
         }

      Test::Result test_prediction_resistance()
         {
         Test::Result result("HMAC_DRBG Prediction Resistance");

         auto mac = Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");
         if(!mac)
            {
            result.note_missing("HMAC(SHA-256)");
            return result;
            }

         // set reseed_interval = 1, forcing a reseed for every RNG request
         Request_Counting_RNG counting_rng;
         Botan::HMAC_DRBG rng(std::move(mac), counting_rng, 1);

         rng.random_vec(16);
         result.test_eq("first request", counting_rng.randomize_count(), size_t(1));

         rng.random_vec(16);
         result.test_eq("second request", counting_rng.randomize_count(), size_t(2));

         rng.random_vec(16);
         result.test_eq("third request", counting_rng.randomize_count(), size_t(3));

         return result;
         }

      Test::Result test_fork_safety()
         {
         Test::Result result("HMAC_DRBG Fork Safety");

#if defined(BOTAN_TARGET_OS_TYPE_IS_UNIX)
         auto mac = Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");
         if(!mac)
            {
            result.note_missing("HMAC(SHA-256)");
            return result;
            }

         const size_t reseed_interval = 1024;

         // make sure rng is reseeded after every fork
         Request_Counting_RNG counting_rng;
         Botan::HMAC_DRBG rng(std::move(mac), counting_rng, reseed_interval);

         rng.random_vec(16);
         result.test_eq("first request", counting_rng.randomize_count(), size_t(1));

         // fork and request from parent and child, both should output different sequences
         size_t count = counting_rng.randomize_count();
         Botan::secure_vector<byte> parent_bytes(16), child_bytes(16);
         int fd[2];
         int rc = pipe(fd);
         if(rc != 0)
            {
            result.test_failure("failed to create pipe");
            }

         pid_t pid = fork();
         if ( pid == -1 )
            {
            result.test_failure("failed to fork process");
            return result;
            }
         else if ( pid != 0 )
            {
            // parent process, wait for randomize_count from child's rng
            close(fd[1]);
            read(fd[0], &count, sizeof(count));
            close(fd[0]);


            result.test_eq("parent not reseeded",  counting_rng.randomize_count(), 1);
            result.test_eq("child reseed occurred", count, 2);

            parent_bytes = rng.random_vec(16);
            read(fd[0], &child_bytes[0], child_bytes.size());
            result.test_ne("parent and child output sequences differ", parent_bytes, child_bytes);
            close(fd[0]);

            int status = 0;
            ::waitpid(pid, &status, 0);
            }
         else
            {
            // child process, send randomize_count and first output sequence back to parent
            close(fd[0]);
            rng.randomize(&child_bytes[0], child_bytes.size());
            count = counting_rng.randomize_count();
            write(fd[1], &count, sizeof(count));
            rng.randomize(&child_bytes[0], child_bytes.size());
            write(fd[1], &child_bytes[0], child_bytes.size());
            close(fd[1]);
            _exit(0);
            }
#endif
         return result;
         }

      Test::Result test_randomize_with_ts_input()
         {
         Test::Result result("HMAC_DRBG Randomize With Timestamp Input");

         auto mac = Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");
         if(!mac)
            {
            result.note_missing("HMAC(SHA-256)");
            return result;
            }

         const size_t reseed_interval = 1024;
         const size_t request_bytes = 64;
         const std::vector<uint8_t> seed(128);

         // check that randomize_with_ts_input() creates different output based on a timestamp
         // and possibly additional data, such as process id
         Fixed_Output_RNG fixed_output_rng1(seed);
         Botan::HMAC_DRBG rng1(std::move(mac), fixed_output_rng1, reseed_interval);
         Botan::secure_vector<byte> output1(request_bytes);
         rng1.randomize(output1.data(), output1.size());

         mac = Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");
         Fixed_Output_RNG fixed_output_rng2(seed);
         Botan::HMAC_DRBG rng2(std::move(mac), fixed_output_rng2, reseed_interval);
         Botan::secure_vector<byte> output2(request_bytes);
         rng2.randomize(output2.data(), output2.size());

         result.test_eq("equal output due to same seed", output1, output2);

         rng1.randomize_with_ts_input(output1.data(), output1.size());
         rng2.randomize_with_ts_input(output2.data(), output2.size());

         result.test_ne("output differs due to different timestamp", output1, output2);

         return result;
         }

      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;
         results.push_back(test_reseed_kat());
         results.push_back(test_reseed());
         results.push_back(test_broken_entropy_input());
         results.push_back(test_check_nonce());
         results.push_back(test_prediction_resistance());
         results.push_back(test_fork_safety());
         results.push_back(test_randomize_with_ts_input());
         return results;
         }
   };

BOTAN_REGISTER_TEST("hmac_drbg_unit", HMAC_DRBG_Unit_Tests);

#endif

}

}
