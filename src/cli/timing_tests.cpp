/*
* Timing Analysis Tests
*
* These tests are not for performance, but verifying that two inputs are not handled
* in a way that is vulnerable to simple timing attacks.
*
* Produces output which can be analyzed with the Mona reporting library
*
* $ git clone https://github.com/seecurity/mona-timing-report.git
* $ cd mona-timing-report && ant
* $ java -jar ReportingTool.jar --lowerBound=0.4 --upperBound=0.5 --inputFile=$file --name=$file
*
* (C) 2016 Juraj Somorovsky - juraj.somorovsky@hackmanit.de
* (C) 2017 Neverhub
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"
#include <botan/hex.h>
#include <sstream>
#include <botan/internal/os_utils.h>

#if defined(BOTAN_HAS_SYSTEM_RNG)
   #include <botan/system_rng.h>
#endif

#if defined(BOTAN_HAS_AUTO_SEEDED_RNG)
   #include <botan/auto_rng.h>
#endif

#if defined(BOTAN_HAS_RSA) && defined(BOTAN_HAS_EME_RAW)
   #include <botan/pubkey.h>
   #include <botan/rsa.h>
#endif

#if defined(BOTAN_HAS_TLS_CBC)
   #include <botan/internal/tls_cbc.h>
   #include <botan/tls_exceptn.h>
#endif

#if defined(BOTAN_HAS_ECDSA)
   #include <botan/ecdsa.h>
   #include <botan/reducer.h>
   #include <botan/numthry.h>
#endif

namespace Botan_CLI {

typedef uint64_t ticks;

class Timing_Test
   {
   public:
      Timing_Test() = default;
      virtual ~Timing_Test() = default;

      std::vector<std::vector<ticks>> execute_evaluation(
                                      const std::vector<std::string>& inputs,
                                      size_t warmup_runs,
                                      size_t measurement_runs);

      virtual std::vector<uint8_t> prepare_input(std::string input) = 0;

      virtual ticks measure_critical_function(std::vector<uint8_t> input) = 0;

   protected:
      static ticks get_ticks()
         {
         // Returns CPU counter or best approximation (monotonic clock of some kind)
         return Botan::OS::get_high_resolution_clock();
         }

      static Botan::RandomNumberGenerator& timing_test_rng()
         {
#if defined(BOTAN_HAS_SYSTEM_RNG)
         return Botan::system_rng();
#elif defined(BOTAN_HAS_AUTO_SEEDED_RNG)
         static AutoSeeded_RNG static_timing_test_rng(Botan::Entropy_Sources::global_sources(), 0);
         return static_timing_test_rng;
#else
         // we could just use SHA-256 in OFB mode for these purposes
         throw CLI_Error("Timing tests require a PRNG");
#endif
         }

   };

#if defined(BOTAN_HAS_RSA) && defined(BOTAN_HAS_EME_PKCS1v15) && defined(BOTAN_HAS_EME_RAW)

class Bleichenbacker_Timing_Test : public Timing_Test
   {
   public:
      Bleichenbacker_Timing_Test(size_t keysize)
         : m_privkey(Timing_Test::timing_test_rng(), keysize)
         , m_pubkey(m_privkey)
         , m_enc(m_pubkey, Timing_Test::timing_test_rng(), "Raw")
         , m_dec(m_privkey, Timing_Test::timing_test_rng(), "PKCS1v15") {}

      std::vector<uint8_t> prepare_input(std::string input) override
         {
         const std::vector<uint8_t> input_vector = Botan::hex_decode(input);
         const std::vector<uint8_t> encrypted = m_enc.encrypt(input_vector, Timing_Test::timing_test_rng());
         return encrypted;
         }

      ticks measure_critical_function(std::vector<uint8_t> input) override
         {
         const ticks start = get_ticks();
         m_dec.decrypt_or_random(input.data(), m_ctext_length, m_expected_content_size, Timing_Test::timing_test_rng());
         const ticks end = get_ticks();
         return (end - start);
         }

   private:
      const size_t m_expected_content_size = 48;
      const size_t m_ctext_length = 256;
      Botan::RSA_PrivateKey m_privkey;
      Botan::RSA_PublicKey m_pubkey;
      Botan::PK_Encryptor_EME m_enc;
      Botan::PK_Decryptor_EME m_dec;
   };

#endif

#if defined(BOTAN_HAS_RSA) && defined(BOTAN_HAS_EME_OAEP) && defined(BOTAN_HAS_EME_RAW)

/*
* Test Manger OAEP side channel
*
* "A Chosen Ciphertext Attack on RSA Optimal Asymmetric Encryption
* Padding (OAEP) as Standardized in PKCS #1 v2.0" James Manger
* http://archiv.infsec.ethz.ch/education/fs08/secsem/Manger01.pdf
*/
class Manger_Timing_Test : public Timing_Test
   {
   public:
      Manger_Timing_Test(size_t keysize)
         : m_privkey(Timing_Test::timing_test_rng(), keysize)
         , m_pubkey(m_privkey)
         , m_enc(m_pubkey, Timing_Test::timing_test_rng(), m_encrypt_padding)
         , m_dec(m_privkey, Timing_Test::timing_test_rng(), m_decrypt_padding) {}

      std::vector<uint8_t> prepare_input(std::string input) override
         {
         const std::vector<uint8_t> input_vector = Botan::hex_decode(input);
         const std::vector<uint8_t> encrypted = m_enc.encrypt(input_vector, Timing_Test::timing_test_rng());
         return encrypted;
         }

      ticks measure_critical_function(std::vector<uint8_t> input) override
         {
         ticks start = get_ticks();
         try
            {
            m_dec.decrypt(input.data(), m_ctext_length);
            }
         catch(Botan::Decoding_Error&)
            {
            }
         ticks end = get_ticks();

         return (end - start);
         }

   private:
      const std::string m_encrypt_padding = "Raw";
      const std::string m_decrypt_padding = "EME1(SHA-256)";
      const size_t m_ctext_length = 256;
      Botan::RSA_PrivateKey m_privkey;
      Botan::RSA_PublicKey m_pubkey;
      Botan::PK_Encryptor_EME m_enc;
      Botan::PK_Decryptor_EME m_dec;
   };

#endif

#if defined(BOTAN_HAS_TLS_CBC)

/*
* Test handling of countermeasure to the Lucky13 attack
*/
class Lucky13_Timing_Test : public Timing_Test
   {
   public:
      Lucky13_Timing_Test(const std::string& mac_name, size_t mac_keylen)
         : m_mac_algo(mac_name)
         , m_mac_keylen(mac_keylen)
         , m_dec("AES-128", 16, m_mac_algo, m_mac_keylen, true, false) {}

      std::vector<uint8_t> prepare_input(std::string input) override;
      ticks measure_critical_function(std::vector<uint8_t> input) override;

   private:
      const std::string m_mac_algo;
      const size_t m_mac_keylen;
      Botan::TLS::TLS_CBC_HMAC_AEAD_Decryption m_dec;
   };

std::vector<uint8_t> Lucky13_Timing_Test::prepare_input(std::string input)
   {
   const std::vector<uint8_t> input_vector = Botan::hex_decode(input);
   const std::vector<uint8_t> key(16);
   const std::vector<uint8_t> iv(16);

   std::unique_ptr<Botan::Cipher_Mode> enc(Botan::get_cipher_mode("AES-128/CBC/NoPadding", Botan::ENCRYPTION));
   enc->set_key(key);
   enc->start(iv);
   Botan::secure_vector<uint8_t> buf(input_vector.begin(), input_vector.end());
   enc->finish(buf);

   return unlock(buf);
   }

ticks Lucky13_Timing_Test::measure_critical_function(std::vector<uint8_t> input)
   {
   Botan::secure_vector<uint8_t> data(input.begin(), input.end());
   Botan::secure_vector<uint8_t> aad(13);
   const Botan::secure_vector<uint8_t> iv(16);
   Botan::secure_vector<uint8_t> key(16 + m_mac_keylen);

   m_dec.set_key(unlock(key));
   m_dec.set_ad(unlock(aad));
   m_dec.start(unlock(iv));

   ticks start = get_ticks();
   try
      {
      m_dec.finish(data);
      }
   catch(Botan::TLS::TLS_Exception&)
      {
      }
   ticks end = get_ticks();
   return (end - start);
   }

#endif

#if defined(BOTAN_HAS_ECDSA)

class ECDSA_Timing_Test : public Timing_Test
   {
   public:
      ECDSA_Timing_Test(std::string ecgroup);

      std::vector<uint8_t> prepare_input(std::string input) override;
      ticks measure_critical_function(std::vector<uint8_t> input) override;

   private:
      const Botan::ECDSA_PrivateKey m_privkey;
      const Botan::BigInt m_order;
      Botan::Blinded_Point_Multiply m_base_point;
      const Botan::BigInt m_x;
      const Botan::Modular_Reducer m_mod_order;
   };

ECDSA_Timing_Test::ECDSA_Timing_Test(std::string ecgroup)
   : m_privkey(Timing_Test::timing_test_rng(), Botan::EC_Group(ecgroup))
   , m_order(m_privkey.domain().get_order())
   , m_base_point(m_privkey.domain().get_base_point(), m_order)
   , m_x(m_privkey.private_value())
   , m_mod_order(m_order) {}

std::vector<uint8_t> ECDSA_Timing_Test::prepare_input(std::string input)
   {
   const std::vector<uint8_t> input_vector = Botan::hex_decode(input);
   return input_vector;
   }

ticks ECDSA_Timing_Test::measure_critical_function(std::vector<uint8_t> input)
   {
   const Botan::BigInt k(input.data(), input.size());
   const Botan::BigInt msg(Timing_Test::timing_test_rng(), m_order.bits());

   ticks start = get_ticks();

   //The following ECDSA operations involve and should not leak any information about k.
   const Botan::PointGFp k_times_P = m_base_point.blinded_multiply(k, Timing_Test::timing_test_rng());
   const Botan::BigInt r = m_mod_order.reduce(k_times_P.get_affine_x());
   const Botan::BigInt s = m_mod_order.multiply(inverse_mod(k, m_order), mul_add(m_x, r, msg));

   ticks end = get_ticks();

   return (end - start);
   }

#endif

std::vector<std::vector<ticks>> Timing_Test::execute_evaluation(
                                const std::vector<std::string>& raw_inputs,
                                size_t warmup_runs, size_t measurement_runs)
   {
   std::vector<std::vector<ticks>> all_results(raw_inputs.size());
   std::vector<std::vector<uint8_t>> inputs(raw_inputs.size());

   for(auto& result : all_results)
      {
      result.reserve(measurement_runs);
      }

   for(size_t i = 0; i != inputs.size(); ++i)
      {
      inputs[i] = prepare_input(raw_inputs[i]);
      }

   // arbitrary upper bounds of 1 and 10 million resp
   if(warmup_runs > 1000000 || measurement_runs > 100000000)
      {
      throw CLI_Error("Requested execution counts too large, rejecting");
      }

   size_t total_runs = 0;
   while(total_runs < (warmup_runs + measurement_runs))
      {
      std::vector<ticks> results(inputs.size());

      for(size_t i = 0; i != inputs.size(); ++i)
         {
         results[i] = measure_critical_function(inputs[i]);
         }

      total_runs++;

      if(total_runs >= warmup_runs)
         {
         for(size_t i = 0; i != results.size(); ++i)
            {
            all_results[i].push_back(results[i]);
            }
         }
      }

   return all_results;
   }

class Timing_Test_Command : public Command
   {
   public:
      Timing_Test_Command()
         : Command("timing_test test_type --test-data-file= --test-data-dir=src/tests/data/timing "
                   "--warmup-runs=1000 --measurement-runs=10000") {}

      void go() override
         {
         const std::string test_type = get_arg("test_type");
         const size_t warmup_runs = get_arg_sz("warmup-runs");
         const size_t measurement_runs = get_arg_sz("measurement-runs");

         std::unique_ptr<Timing_Test> test = lookup_timing_test(test_type);

         if(!test)
            {
            throw CLI_Error("Unknown or unavailable test type '" + test_type + "'");
            }

         std::string filename = get_arg_or("test-data-file", "");

         if(filename.empty())
            {
            const std::string test_data_dir = get_arg("test-data-dir");
            filename = test_data_dir + "/" + test_type + ".vec";
            }

         std::vector<std::string> lines;

            {
            std::ifstream infile(filename);
            if(infile.good() == false)
               {
               throw CLI_Error("Error reading test data from '" + filename + "'");
               }
            std::string line;
            while(std::getline(infile, line))
               {
               if(line.size() > 0 && line.at(0) != '#')
                  {
                  lines.push_back(line);
                  }
               }
            }

         std::vector<std::vector<ticks>> results = test->execute_evaluation(lines, warmup_runs, measurement_runs);

         size_t unique_id = 0;
         std::ostringstream oss;
         for(size_t secret_id = 0; secret_id != results.size(); ++secret_id)
            {
            for(size_t i = 0; i != results[secret_id].size(); ++i)
               {
               oss << unique_id++ << ";" << secret_id << ";" << results[secret_id][i] << "\n";
               }
            }

         output() << oss.str();
         }
   private:
      std::unique_ptr<Timing_Test> lookup_timing_test(const std::string& test_type);

      std::string help_text() const override
         {
         // TODO check feature macros
         return (Command::help_text() +
                 "\ntest_type can take on values " +
                 "bleichenbacher " +
                 "manger "
                 "ecdsa " +
                 "lucky13sha1sec3 " +
                 "lucky13sha256sec3 " +
                 "lucky13sec4sha1 " +
                 "lucky13sec4sha256 " +
                 "lucky13sec4sha384 "
                );
         }
   };

BOTAN_REGISTER_COMMAND("timing_test", Timing_Test_Command);

std::unique_ptr<Timing_Test> Timing_Test_Command::lookup_timing_test(const std::string& test_type)
   {
#if defined(BOTAN_HAS_RSA) && defined(BOTAN_HAS_EME_PKCS1v15) && defined(BOTAN_HAS_EME_RAW)
   if(test_type == "bleichenbacher")
      {
      return std::unique_ptr<Timing_Test>(new Bleichenbacker_Timing_Test(2048));
      }
#endif

#if defined(BOTAN_HAS_RSA) && defined(BOTAN_HAS_EME_OAEP) && defined(BOTAN_HAS_EME_RAW)
   if(test_type == "manger")
      {
      return std::unique_ptr<Timing_Test>(new Manger_Timing_Test(2048));
      }
#endif

#if defined(BOTAN_HAS_ECDSA)
   if(test_type == "ecdsa")
      {
      return std::unique_ptr<Timing_Test>(new ECDSA_Timing_Test("secp384r1"));
      }
#endif

#if defined(BOTAN_HAS_TLS_CBC)
   if(test_type == "lucky13sha1sec3" || test_type == "lucky13sha1sec4")
      {
      return std::unique_ptr<Timing_Test>(new Lucky13_Timing_Test("SHA-1", 20));
      }
   if(test_type == "lucky13sha256sec3" || test_type == "lucky13sha256sec4")
      {
      return std::unique_ptr<Timing_Test>(new Lucky13_Timing_Test("SHA-256", 32));
      }
   if(test_type == "lucky13sha384")
      {
      return std::unique_ptr<Timing_Test>(new Lucky13_Timing_Test("SHA-384", 48));
      }
#endif

   BOTAN_UNUSED(test_type);

   return nullptr;
   }


}
