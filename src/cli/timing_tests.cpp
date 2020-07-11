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
* (C) 2017,2018,2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"
#include <botan/hex.h>
#include <sstream>
#include <fstream>

#include <botan/rng.h>
#include <botan/internal/os_utils.h>

#if defined(BOTAN_HAS_BIGINT)
   #include <botan/bigint.h>
#endif

#if defined(BOTAN_HAS_NUMBERTHEORY)
   #include <botan/numthry.h>
#endif

#if defined(BOTAN_HAS_ECC_GROUP)
   #include <botan/ec_group.h>
#endif

#if defined(BOTAN_HAS_DL_GROUP)
   #include <botan/dl_group.h>
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
   #include <botan/pubkey.h>
   #include <botan/ecdsa.h>
#endif

namespace Botan_CLI {

typedef uint64_t ticks;

class Timing_Test
   {
   public:
      Timing_Test()
         {
         /*
         A constant seed is ok here since the timing test rng just needs to be
         "random" but not cryptographically secure - even std::rand() would be ok.
         */
         const std::string drbg_seed(64, 'A');
         m_rng = cli_make_rng("", drbg_seed); // throws if it can't find anything to use
         }

      virtual ~Timing_Test() = default;

      std::vector<std::vector<ticks>> execute_evaluation(
                                      const std::vector<std::string>& inputs,
                                      size_t warmup_runs,
                                      size_t measurement_runs);

      virtual std::vector<uint8_t> prepare_input(const std::string& input)
         {
         return Botan::hex_decode(input);
         }

      virtual ticks measure_critical_function(const std::vector<uint8_t>& input) = 0;

   protected:
      static ticks get_ticks()
         {
         // Returns CPU counter or best approximation (monotonic clock of some kind)
         //return Botan::OS::get_high_resolution_clock();
         return Botan::OS::get_system_timestamp_ns();
         }

      Botan::RandomNumberGenerator& timing_test_rng()
         {
         return (*m_rng);
         }

   private:
      std::unique_ptr<Botan::RandomNumberGenerator> m_rng;
   };

#if defined(BOTAN_HAS_RSA) && defined(BOTAN_HAS_EME_PKCS1) && defined(BOTAN_HAS_EME_RAW)

class Bleichenbacker_Timing_Test final : public Timing_Test
   {
   public:
      Bleichenbacker_Timing_Test(size_t keysize)
         : m_privkey(timing_test_rng(), keysize)
         , m_pubkey(m_privkey)
         , m_enc(m_pubkey, timing_test_rng(), "Raw")
         , m_dec(m_privkey, timing_test_rng(), "PKCS1v15") {}

      std::vector<uint8_t> prepare_input(const std::string& input) override
         {
         const std::vector<uint8_t> input_vector = Botan::hex_decode(input);
         const std::vector<uint8_t> encrypted = m_enc.encrypt(input_vector, timing_test_rng());
         return encrypted;
         }

      ticks measure_critical_function(const std::vector<uint8_t>& input) override
         {
         const ticks start = get_ticks();
         m_dec.decrypt_or_random(input.data(), m_ctext_length, m_expected_content_size, timing_test_rng());
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
class Manger_Timing_Test final : public Timing_Test
   {
   public:
      Manger_Timing_Test(size_t keysize)
         : m_privkey(timing_test_rng(), keysize)
         , m_pubkey(m_privkey)
         , m_enc(m_pubkey, timing_test_rng(), m_encrypt_padding)
         , m_dec(m_privkey, timing_test_rng(), m_decrypt_padding) {}

      std::vector<uint8_t> prepare_input(const std::string& input) override
         {
         const std::vector<uint8_t> input_vector = Botan::hex_decode(input);
         const std::vector<uint8_t> encrypted = m_enc.encrypt(input_vector, timing_test_rng());
         return encrypted;
         }

      ticks measure_critical_function(const std::vector<uint8_t>& input) override
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
class Lucky13_Timing_Test final : public Timing_Test
   {
   public:
      Lucky13_Timing_Test(const std::string& mac_name, size_t mac_keylen)
         : m_mac_algo(mac_name)
         , m_mac_keylen(mac_keylen)
         , m_dec(Botan::BlockCipher::create_or_throw("AES-128"),
                 Botan::MessageAuthenticationCode::create_or_throw("HMAC(" + m_mac_algo + ")"),
                 16, m_mac_keylen, Botan::TLS::Protocol_Version::TLS_V11, false) {}

      std::vector<uint8_t> prepare_input(const std::string& input) override;
      ticks measure_critical_function(const std::vector<uint8_t>& input) override;

   private:
      const std::string m_mac_algo;
      const size_t m_mac_keylen;
      Botan::TLS::TLS_CBC_HMAC_AEAD_Decryption m_dec;
   };

std::vector<uint8_t> Lucky13_Timing_Test::prepare_input(const std::string& input)
   {
   const std::vector<uint8_t> input_vector = Botan::hex_decode(input);
   const std::vector<uint8_t> key(16);
   const std::vector<uint8_t> iv(16);

   std::unique_ptr<Botan::Cipher_Mode> enc(Botan::Cipher_Mode::create("AES-128/CBC/NoPadding", Botan::ENCRYPTION));
   enc->set_key(key);
   enc->start(iv);
   Botan::secure_vector<uint8_t> buf(input_vector.begin(), input_vector.end());
   enc->finish(buf);

   return unlock(buf);
   }

ticks Lucky13_Timing_Test::measure_critical_function(const std::vector<uint8_t>& input)
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

class ECDSA_Timing_Test final : public Timing_Test
   {
   public:
      ECDSA_Timing_Test(std::string ecgroup);

      ticks measure_critical_function(const std::vector<uint8_t>& input) override;

   private:
      const Botan::EC_Group m_group;
      const Botan::ECDSA_PrivateKey m_privkey;
      const Botan::BigInt& m_x;
      std::vector<Botan::BigInt> m_ws;
      Botan::BigInt m_b, m_b_inv;
   };

ECDSA_Timing_Test::ECDSA_Timing_Test(std::string ecgroup)
   : m_group(ecgroup)
   , m_privkey(timing_test_rng(), m_group)
   , m_x(m_privkey.private_value())
   {
      m_b = m_group.random_scalar(timing_test_rng());
      m_b_inv = m_group.inverse_mod_order(m_b);
   }

ticks ECDSA_Timing_Test::measure_critical_function(const std::vector<uint8_t>& input)
   {
   const Botan::BigInt k(input.data(), input.size());
   Botan::BigInt m(5); // fixed message to minimize noise

   ticks start = get_ticks();

   // the following ECDSA operations involve and should not leak any information about k
   const Botan::BigInt r = m_group.mod_order(
      m_group.blinded_base_point_multiply_x(k, timing_test_rng(), m_ws));
   const Botan::BigInt k_inv = m_group.inverse_mod_order(k);

   m_b = m_group.square_mod_order(m_b);
   m_b_inv = m_group.square_mod_order(m_b_inv);

   m = m_group.multiply_mod_order(m_b, m_group.mod_order(m));
   const Botan::BigInt xr_m = m_group.mod_order(m_group.multiply_mod_order(m_x, m_b, r) + m);

   const Botan::BigInt s = m_group.multiply_mod_order(k_inv, xr_m, m_b_inv);

   BOTAN_UNUSED(r, s);

   ticks end = get_ticks();

   return (end - start);
   }

#endif

#if defined(BOTAN_HAS_ECC_GROUP)

class ECC_Mul_Timing_Test final : public Timing_Test
   {
   public:
      ECC_Mul_Timing_Test(std::string ecgroup) :
         m_group(ecgroup)
         {}

      ticks measure_critical_function(const std::vector<uint8_t>& input) override;

   private:
      const Botan::EC_Group m_group;
      std::vector<Botan::BigInt> m_ws;
   };

ticks ECC_Mul_Timing_Test::measure_critical_function(const std::vector<uint8_t>& input)
   {
   const Botan::BigInt k(input.data(), input.size());

   ticks start = get_ticks();

   const Botan::PointGFp k_times_P = m_group.blinded_base_point_multiply(k, timing_test_rng(), m_ws);

   ticks end = get_ticks();

   return (end - start);
   }

#endif

#if defined(BOTAN_HAS_DL_GROUP)

class Powmod_Timing_Test final : public Timing_Test
   {
   public:
      Powmod_Timing_Test(const std::string& dl_group) : m_group(dl_group)
         {
         }

      ticks measure_critical_function(const std::vector<uint8_t>& input) override;
   private:
      Botan::DL_Group m_group;
   };

ticks Powmod_Timing_Test::measure_critical_function(const std::vector<uint8_t>& input)
   {
   const Botan::BigInt x(input.data(), input.size());
   const size_t max_x_bits = m_group.p_bits();

   ticks start = get_ticks();

   const Botan::BigInt g_x_p = m_group.power_g_p(x, max_x_bits);

   ticks end = get_ticks();

   return (end - start);
   }

#endif

#if defined(BOTAN_HAS_NUMBERTHEORY)

class Invmod_Timing_Test final : public Timing_Test
   {
   public:
      Invmod_Timing_Test(size_t p_bits)
         {
         m_p = Botan::random_prime(timing_test_rng(), p_bits);
         }

      ticks measure_critical_function(const std::vector<uint8_t>& input) override;

   private:
      Botan::BigInt m_p;
   };

ticks Invmod_Timing_Test::measure_critical_function(const std::vector<uint8_t>& input)
   {
   const Botan::BigInt k(input.data(), input.size());

   ticks start = get_ticks();

   const Botan::BigInt inv = inverse_mod(k, m_p);

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
   std::vector<ticks> results(inputs.size());

   while(total_runs < (warmup_runs + measurement_runs))
      {
      for(size_t i = 0; i != inputs.size(); ++i)
         {
         results[i] = measure_critical_function(inputs[i]);
         }

      total_runs++;

      if(total_runs > warmup_runs)
         {
         for(size_t i = 0; i != results.size(); ++i)
            {
            all_results[i].push_back(results[i]);
            }
         }
      }

   return all_results;
   }

class Timing_Test_Command final : public Command
   {
   public:
      Timing_Test_Command()
         : Command("timing_test test_type --test-data-file= --test-data-dir=src/tests/data/timing "
                   "--warmup-runs=5000 --measurement-runs=50000") {}

      std::string group() const override
         {
         return "misc";
         }

      std::string description() const override
         {
         return "Run various timing side channel tests";
         }

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

         std::vector<std::string> lines = read_testdata(filename);

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

      std::vector<std::string> read_testdata(const std::string& filename)
         {
         std::vector<std::string> lines;
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
         return lines;
         }

      std::unique_ptr<Timing_Test> lookup_timing_test(const std::string& test_type);

      std::string help_text() const override
         {
         // TODO check feature macros
         return (Command::help_text() +
                 "\ntest_type can take on values "
                 "bleichenbacher "
                 "manger "
                 "ecdsa "
                 "ecc_mul "
                 "inverse_mod "
                 "pow_mod "
                 "lucky13sec3 "
                 "lucky13sec4sha1 "
                 "lucky13sec4sha256 "
                 "lucky13sec4sha384 "
                );
         }
   };

BOTAN_REGISTER_COMMAND("timing_test", Timing_Test_Command);

std::unique_ptr<Timing_Test> Timing_Test_Command::lookup_timing_test(const std::string& test_type)
   {
#if defined(BOTAN_HAS_RSA) && defined(BOTAN_HAS_EME_PKCS1) && defined(BOTAN_HAS_EME_RAW)
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

#if defined(BOTAN_HAS_ECC_GROUP)
   if(test_type == "ecc_mul")
      {
      return std::unique_ptr<Timing_Test>(new ECC_Mul_Timing_Test("brainpool512r1"));
      }
#endif

#if defined(BOTAN_HAS_NUMBERTHEORY)
   if(test_type == "inverse_mod")
      {
      return std::unique_ptr<Timing_Test>(new Invmod_Timing_Test(512));
      }
#endif

#if defined(BOTAN_HAS_DL_GROUP)
   if(test_type == "pow_mod")
      {
      return std::unique_ptr<Timing_Test>(new Powmod_Timing_Test("modp/ietf/1024"));
      }
#endif

#if defined(BOTAN_HAS_TLS_CBC)
   if(test_type == "lucky13sec3" || test_type == "lucky13sec4sha1")
      {
      return std::unique_ptr<Timing_Test>(new Lucky13_Timing_Test("SHA-1", 20));
      }
   if(test_type == "lucky13sec4sha256")
      {
      return std::unique_ptr<Timing_Test>(new Lucky13_Timing_Test("SHA-256", 32));
      }
   if(test_type == "lucky13sec4sha384")
      {
      return std::unique_ptr<Timing_Test>(new Lucky13_Timing_Test("SHA-384", 48));
      }
#endif

   BOTAN_UNUSED(test_type);

   return nullptr;
   }


}
