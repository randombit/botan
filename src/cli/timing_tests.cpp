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
#include <botan/rng.h>
#include <botan/internal/filesystem.h>
#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/parsing.h>
#include <chrono>
#include <fstream>
#include <sstream>

#if defined(BOTAN_HAS_BIGINT)
   #include <botan/bigint.h>
#endif

#if defined(BOTAN_HAS_NUMBERTHEORY)
   #include <botan/numthry.h>
   #include <botan/internal/mod_inv.h>
#endif

#if defined(BOTAN_HAS_ECC_GROUP)
   #include <botan/ec_group.h>
#endif

#if defined(BOTAN_HAS_DL_GROUP)
   #include <botan/dl_group.h>
#endif

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO)
   #include <botan/pkcs8.h>
   #include <botan/pubkey.h>
#endif

#if defined(BOTAN_HAS_RSA)
   #include <botan/rsa.h>
#endif

#if defined(BOTAN_HAS_TLS_CBC)
   #include <botan/tls_exceptn.h>
   #include <botan/internal/tls_cbc.h>
#endif

#if defined(BOTAN_HAS_ECDSA)
   #include <botan/ecdsa.h>
#endif

namespace Botan_CLI {

namespace {

class TimingTestTimer {
   public:
      TimingTestTimer() { m_start = get_high_resolution_clock(); }

      uint64_t complete() const { return get_high_resolution_clock() - m_start; }

   private:
      static uint64_t get_high_resolution_clock() {
         // TODO use cpu clock where possible/relevant incl serializing instructions
         auto now = std::chrono::high_resolution_clock::now().time_since_epoch();
         return std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
      }

      uint64_t m_start;
};

}  // namespace

class Timing_Test {
   public:
      Timing_Test() {
         /*
         A constant seed is ok here since the timing test rng just needs to be
         "random" but not cryptographically secure - even std::rand() would be ok.
         */
         const std::string drbg_seed(64, 'A');
         m_rng = cli_make_rng("", drbg_seed);  // throws if it can't find anything to use
      }

      virtual ~Timing_Test() = default;

      Timing_Test(const Timing_Test& other) = delete;
      Timing_Test(Timing_Test&& other) = delete;
      Timing_Test& operator=(const Timing_Test& other) = delete;
      Timing_Test& operator=(Timing_Test&& other) = delete;

      std::vector<std::vector<uint64_t>> execute_evaluation(const std::vector<std::string>& inputs,
                                                            size_t warmup_runs,
                                                            size_t measurement_runs);

      virtual std::vector<uint8_t> prepare_input(const std::string& input) { return Botan::hex_decode(input); }

      virtual uint64_t measure_critical_function(const std::vector<uint8_t>& input) = 0;

   protected:
      Botan::RandomNumberGenerator& timing_test_rng() { return (*m_rng); }

   private:
      std::shared_ptr<Botan::RandomNumberGenerator> m_rng;
};

#if defined(BOTAN_HAS_RSA) && defined(BOTAN_HAS_EME_PKCS1) && defined(BOTAN_HAS_EME_RAW)

class Bleichenbacker_Timing_Test final : public Timing_Test {
   public:
      explicit Bleichenbacker_Timing_Test(size_t keysize) :
            m_privkey(timing_test_rng(), keysize),
            m_pubkey(m_privkey),
            m_enc(m_pubkey, timing_test_rng(), "Raw"),
            m_dec(m_privkey, timing_test_rng(), "PKCS1v15") {}

      std::vector<uint8_t> prepare_input(const std::string& input) override {
         const std::vector<uint8_t> input_vector = Botan::hex_decode(input);
         return m_enc.encrypt(input_vector, timing_test_rng());
      }

      uint64_t measure_critical_function(const std::vector<uint8_t>& input) override {
         TimingTestTimer timer;
         m_dec.decrypt_or_random(input.data(), m_ctext_length, m_expected_content_size, timing_test_rng());
         return timer.complete();
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
class Manger_Timing_Test final : public Timing_Test {
   public:
      explicit Manger_Timing_Test(size_t keysize) :
            m_privkey(timing_test_rng(), keysize),
            m_pubkey(m_privkey),
            m_enc(m_pubkey, timing_test_rng(), m_encrypt_padding),
            m_dec(m_privkey, timing_test_rng(), m_decrypt_padding) {}

      std::vector<uint8_t> prepare_input(const std::string& input) override {
         const std::vector<uint8_t> input_vector = Botan::hex_decode(input);
         return m_enc.encrypt(input_vector, timing_test_rng());
      }

      uint64_t measure_critical_function(const std::vector<uint8_t>& input) override {
         TimingTestTimer timer;
         try {
            m_dec.decrypt(input.data(), m_ctext_length);
         } catch(Botan::Decoding_Error&) {}
         return timer.complete();
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
class Lucky13_Timing_Test final : public Timing_Test {
   public:
      Lucky13_Timing_Test(const std::string& mac_name, size_t mac_keylen) :
            m_mac_algo(mac_name),
            m_mac_keylen(mac_keylen),
            m_dec(Botan::BlockCipher::create_or_throw("AES-128"),
                  Botan::MessageAuthenticationCode::create_or_throw("HMAC(" + m_mac_algo + ")"),
                  16,
                  m_mac_keylen,
                  Botan::TLS::Protocol_Version::TLS_V12,
                  false) {}

      std::vector<uint8_t> prepare_input(const std::string& input) override;
      uint64_t measure_critical_function(const std::vector<uint8_t>& input) override;

   private:
      const std::string m_mac_algo;
      const size_t m_mac_keylen;
      Botan::TLS::TLS_CBC_HMAC_AEAD_Decryption m_dec;
};

std::vector<uint8_t> Lucky13_Timing_Test::prepare_input(const std::string& input) {
   const std::vector<uint8_t> input_vector = Botan::hex_decode(input);
   const std::vector<uint8_t> key(16);
   const std::vector<uint8_t> iv(16);

   auto enc = Botan::Cipher_Mode::create("AES-128/CBC/NoPadding", Botan::Cipher_Dir::Encryption);
   enc->set_key(key);
   enc->start(iv);
   Botan::secure_vector<uint8_t> buf(input_vector.begin(), input_vector.end());
   enc->finish(buf);

   return unlock(buf);
}

uint64_t Lucky13_Timing_Test::measure_critical_function(const std::vector<uint8_t>& input) {
   Botan::secure_vector<uint8_t> data(input.begin(), input.end());
   Botan::secure_vector<uint8_t> aad(13);
   const Botan::secure_vector<uint8_t> iv(16);
   Botan::secure_vector<uint8_t> key(16 + m_mac_keylen);

   m_dec.set_key(unlock(key));
   m_dec.set_associated_data(aad);
   m_dec.start(unlock(iv));

   TimingTestTimer timer;
   try {
      m_dec.finish(data);
   } catch(Botan::TLS::TLS_Exception&) {}
   return timer.complete();
}

#endif

#if defined(BOTAN_HAS_ECDSA)

class ECDSA_Timing_Test final : public Timing_Test {
   public:
      explicit ECDSA_Timing_Test(const std::string& ecgroup);

      uint64_t measure_critical_function(const std::vector<uint8_t>& input) override;

   private:
      const Botan::EC_Group m_group;
      const Botan::ECDSA_PrivateKey m_privkey;
      const Botan::EC_Scalar m_x;
      Botan::EC_Scalar m_b;
      Botan::EC_Scalar m_b_inv;
      std::vector<Botan::BigInt> m_ws;
};

ECDSA_Timing_Test::ECDSA_Timing_Test(const std::string& ecgroup) :
      m_group(Botan::EC_Group::from_name(ecgroup)),
      m_privkey(timing_test_rng(), m_group),
      m_x(m_privkey._private_key()),
      m_b(Botan::EC_Scalar::random(m_group, timing_test_rng())),
      m_b_inv(m_b.invert()) {}

uint64_t ECDSA_Timing_Test::measure_critical_function(const std::vector<uint8_t>& input) {
   const auto k = Botan::EC_Scalar::from_bytes_with_trunc(m_group, input);
   // fixed message to minimize noise
   const auto m = Botan::EC_Scalar::from_bytes_with_trunc(m_group, std::vector<uint8_t>{5});

   TimingTestTimer timer;

   // the following ECDSA operations involve and should not leak any information about k
   const auto r = Botan::EC_Scalar::gk_x_mod_order(k, timing_test_rng(), m_ws);
   const auto k_inv = k.invert();
   m_b.square_self();
   m_b_inv.square_self();
   const auto xr_m = ((m_x * m_b) * r) + (m * m_b);
   const auto s = (k_inv * xr_m) * m_b_inv;
   BOTAN_UNUSED(r, s);

   return timer.complete();
}

#endif

#if defined(BOTAN_HAS_ECC_GROUP)

class ECC_Mul_Timing_Test final : public Timing_Test {
   public:
      explicit ECC_Mul_Timing_Test(std::string_view ecgroup) : m_group(Botan::EC_Group::from_name(ecgroup)) {}

      uint64_t measure_critical_function(const std::vector<uint8_t>& input) override;

   private:
      const Botan::EC_Group m_group;
      std::vector<Botan::BigInt> m_ws;
};

uint64_t ECC_Mul_Timing_Test::measure_critical_function(const std::vector<uint8_t>& input) {
   const auto k = Botan::EC_Scalar::from_bytes_with_trunc(m_group, input);

   TimingTestTimer timer;
   const auto kG = Botan::EC_AffinePoint::g_mul(k, timing_test_rng(), m_ws);
   return timer.complete();
}

#endif

#if defined(BOTAN_HAS_DL_GROUP)

class Powmod_Timing_Test final : public Timing_Test {
   public:
      explicit Powmod_Timing_Test(std::string_view dl_group) : m_group(Botan::DL_Group::from_name(dl_group)) {}

      uint64_t measure_critical_function(const std::vector<uint8_t>& input) override;

   private:
      Botan::DL_Group m_group;
};

uint64_t Powmod_Timing_Test::measure_critical_function(const std::vector<uint8_t>& input) {
   const Botan::BigInt x(input.data(), input.size());
   const size_t max_x_bits = m_group.p_bits();

   TimingTestTimer timer;

   const Botan::BigInt g_x_p = m_group.power_g_p(x, max_x_bits);

   return timer.complete();
}

#endif

#if defined(BOTAN_HAS_NUMBERTHEORY)

class Invmod_Timing_Test final : public Timing_Test {
   public:
      explicit Invmod_Timing_Test(size_t p_bits) { m_p = Botan::random_prime(timing_test_rng(), p_bits); }

      uint64_t measure_critical_function(const std::vector<uint8_t>& input) override;

   private:
      Botan::BigInt m_p;
};

uint64_t Invmod_Timing_Test::measure_critical_function(const std::vector<uint8_t>& input) {
   const Botan::BigInt k(input.data(), input.size());

   TimingTestTimer timer;
   const Botan::BigInt inv = Botan::inverse_mod_secret_prime(k, m_p);
   return timer.complete();
}

#endif

std::vector<std::vector<uint64_t>> Timing_Test::execute_evaluation(const std::vector<std::string>& raw_inputs,
                                                                   size_t warmup_runs,
                                                                   size_t measurement_runs) {
   std::vector<std::vector<uint64_t>> all_results(raw_inputs.size());
   std::vector<std::vector<uint8_t>> inputs(raw_inputs.size());

   for(auto& result : all_results) {
      result.reserve(measurement_runs);
   }

   for(size_t i = 0; i != inputs.size(); ++i) {
      inputs[i] = prepare_input(raw_inputs[i]);
   }

   // arbitrary upper bounds of 1 and 10 million resp
   if(warmup_runs > 1000000 || measurement_runs > 100000000) {
      throw CLI_Error("Requested execution counts too large, rejecting");
   }

   size_t total_runs = 0;
   std::vector<uint64_t> results(inputs.size());

   while(total_runs < (warmup_runs + measurement_runs)) {
      for(size_t i = 0; i != inputs.size(); ++i) {
         results[i] = measure_critical_function(inputs[i]);
      }

      total_runs++;

      if(total_runs > warmup_runs) {
         for(size_t i = 0; i != results.size(); ++i) {
            all_results[i].push_back(results[i]);
         }
      }
   }

   return all_results;
}

class Timing_Test_Command final : public Command {
   public:
      Timing_Test_Command() :
            Command(
               "timing_test test_type --test-data-file= --test-data-dir=src/tests/data/timing "
               "--warmup-runs=5000 --measurement-runs=50000") {}

      std::string group() const override { return "testing"; }

      std::string description() const override { return "Run various timing side channel tests"; }

      void go() override {
         const std::string test_type = get_arg("test_type");
         const size_t warmup_runs = get_arg_sz("warmup-runs");
         const size_t measurement_runs = get_arg_sz("measurement-runs");

         std::unique_ptr<Timing_Test> test = lookup_timing_test(test_type);

         if(!test) {
            throw CLI_Error("Unknown or unavailable test type '" + test_type + "'");
         }

         std::string filename = get_arg_or("test-data-file", "");

         if(filename.empty()) {
            const std::string test_data_dir = get_arg("test-data-dir");
            filename = test_data_dir + "/" + test_type + ".vec";
         }

         std::vector<std::string> lines = read_testdata(filename);

         std::vector<std::vector<uint64_t>> results = test->execute_evaluation(lines, warmup_runs, measurement_runs);

         size_t unique_id = 0;
         std::ostringstream oss;
         for(size_t secret_id = 0; secret_id != results.size(); ++secret_id) {
            for(size_t i = 0; i != results[secret_id].size(); ++i) {
               oss << unique_id++ << ";" << secret_id << ";" << results[secret_id][i] << "\n";
            }
         }

         output() << oss.str();
      }

   private:
      static std::vector<std::string> read_testdata(const std::string& filename) {
         std::vector<std::string> lines;
         std::ifstream infile(filename);
         if(infile.good() == false) {
            throw CLI_Error("Error reading test data from '" + filename + "'");
         }
         std::string line;
         while(std::getline(infile, line)) {
            if(!line.empty() && line.at(0) != '#') {
               lines.push_back(line);
            }
         }
         return lines;
      }

      static std::unique_ptr<Timing_Test> lookup_timing_test(std::string_view test_type);

      std::string help_text() const override {
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
                 "lucky13sec4sha384 ");
      }
};

std::unique_ptr<Timing_Test> Timing_Test_Command::lookup_timing_test(std::string_view test_type) {
#if defined(BOTAN_HAS_RSA) && defined(BOTAN_HAS_EME_PKCS1) && defined(BOTAN_HAS_EME_RAW)
   if(test_type == "bleichenbacher") {
      return std::make_unique<Bleichenbacker_Timing_Test>(2048);
   }
#endif

#if defined(BOTAN_HAS_RSA) && defined(BOTAN_HAS_EME_OAEP) && defined(BOTAN_HAS_EME_RAW)
   if(test_type == "manger") {
      return std::make_unique<Manger_Timing_Test>(2048);
   }
#endif

#if defined(BOTAN_HAS_ECDSA)
   if(test_type == "ecdsa") {
      return std::make_unique<ECDSA_Timing_Test>("secp384r1");
   }
#endif

#if defined(BOTAN_HAS_ECC_GROUP)
   if(test_type == "ecc_mul") {
      return std::make_unique<ECC_Mul_Timing_Test>("brainpool512r1");
   }
#endif

#if defined(BOTAN_HAS_NUMBERTHEORY)
   if(test_type == "inverse_mod") {
      return std::make_unique<Invmod_Timing_Test>(512);
   }
#endif

#if defined(BOTAN_HAS_DL_GROUP)
   if(test_type == "pow_mod") {
      return std::make_unique<Powmod_Timing_Test>("modp/ietf/1024");
   }
#endif

#if defined(BOTAN_HAS_TLS_CBC)
   if(test_type == "lucky13sec3" || test_type == "lucky13sec4sha1") {
      return std::make_unique<Lucky13_Timing_Test>("SHA-1", 20);
   }
   if(test_type == "lucky13sec4sha256") {
      return std::make_unique<Lucky13_Timing_Test>("SHA-256", 32);
   }
   if(test_type == "lucky13sec4sha384") {
      return std::make_unique<Lucky13_Timing_Test>("SHA-384", 48);
   }
#endif

   BOTAN_UNUSED(test_type);

   return nullptr;
}

BOTAN_REGISTER_COMMAND("timing_test", Timing_Test_Command);

#if defined(BOTAN_HAS_RSA) && defined(BOTAN_HAS_EME_PKCS1) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

class MARVIN_Test_Command final : public Command {
   public:
      MARVIN_Test_Command() : Command("marvin_test key_file ctext_dir --runs=10 --output-nsec --expect-pt-len=0") {}

      std::string group() const override { return "testing"; }

      std::string description() const override { return "Run a test for MARVIN attack"; }

      void go() override {
         const std::string key_file = get_arg("key_file");
         const std::string ctext_dir = get_arg("ctext_dir");
         const size_t measurement_runs = get_arg_sz("runs");
         const size_t expect_pt_len = get_arg_sz("expect-pt-len");
         const bool output_nsec = flag_set("output-nsec");

         Botan::DataSource_Stream key_src(key_file);
         const auto key = Botan::PKCS8::load_key(key_src);

         if(key->algo_name() != "RSA") {
            throw CLI_Usage_Error("Unexpected key type for MARVIN test");
         }

         const size_t modulus_bytes = (key->key_length() + 7) / 8;

         std::vector<std::string> names;
         std::vector<uint8_t> ciphertext_data;

         for(const auto& filename : Botan::get_files_recursive(ctext_dir)) {
            const auto contents = this->slurp_file(filename);

            if(contents.size() != modulus_bytes) {
               throw CLI_Usage_Error(
                  Botan::fmt("The ciphertext file {} had different size ({}) than the RSA modulus ({})",
                             filename,
                             contents.size(),
                             modulus_bytes));
            }

            const auto parts = Botan::split_on(filename, '/');

            names.push_back(parts[parts.size() - 1]);
            ciphertext_data.insert(ciphertext_data.end(), contents.begin(), contents.end());
         }

         if(names.empty()) {
            throw CLI_Usage_Error("Empty ciphertext directory for MARVIN test");
         }

         Botan::PK_Decryptor_EME op(*key, rng(), "PKCS1v15");

         std::vector<size_t> indexes;
         for(size_t i = 0; i != names.size(); ++i) {
            indexes.push_back(i);
         }

         std::vector<std::vector<uint64_t>> measurements(names.size());
         for(auto& m : measurements) {
            m.reserve(measurement_runs);
         }

         for(size_t r = 0; r != measurement_runs; ++r) {
            shuffle(indexes, rng());

            std::vector<uint8_t> ciphertext(modulus_bytes);
            for(size_t i = 0; i != indexes.size(); ++i) {
               const size_t testcase = indexes[i];

               // FIXME should this load be constant time?
               Botan::copy_mem(&ciphertext[0], &ciphertext_data[testcase * modulus_bytes], modulus_bytes);

               TimingTestTimer timer;
               op.decrypt_or_random(ciphertext.data(), modulus_bytes, expect_pt_len, rng());
               const uint64_t duration = timer.complete();
               BOTAN_ASSERT_NOMSG(measurements[testcase].size() == r);
               measurements[testcase].push_back(duration);
            }
         }

         for(size_t t = 0; t != names.size(); ++t) {
            if(t > 0) {
               output() << ",";
            }
            output() << names[t];
         }
         output() << "\n";

         for(size_t r = 0; r != measurement_runs; ++r) {
            for(size_t t = 0; t != names.size(); ++t) {
               if(t > 0) {
                  output() << ",";
               }

               const uint64_t dur_nsec = measurements[t][r];
               if(output_nsec) {
                  output() << dur_nsec;
               } else {
                  const double dur_s = static_cast<double>(dur_nsec) / 1000000000.0;
                  output() << dur_s;
               }
            }
            output() << "\n";
         }
      }

      template <typename T>
      void shuffle(std::vector<T>& vec, Botan::RandomNumberGenerator& rng) {
         const size_t n = vec.size();
         for(size_t i = 0; i != n; ++i) {
            uint8_t jb[sizeof(uint64_t)];
            rng.randomize(jb, sizeof(jb));
            uint64_t j8 = Botan::load_le<uint64_t>(jb, 0);
            size_t j = i + static_cast<size_t>(j8) % (n - i);
            std::swap(vec[i], vec[j]);
         }
      }
};

BOTAN_REGISTER_COMMAND("marvin_test", MARVIN_Test_Command);

#endif

}  // namespace Botan_CLI
