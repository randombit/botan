/*
* (C) 2009,2010,2014,2015,2017,2018,2024 Jack Lloyd
* (C) 2015 Simon Warta (Kullo GmbH)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"
#include "perf.h"

#include <algorithm>
#include <chrono>
#include <functional>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>

// Always available:
#include <botan/version.h>
#include <botan/internal/cpuid.h>
#include <botan/internal/fmt.h>
#include <botan/internal/os_utils.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/timer.h>

#if defined(BOTAN_HAS_BLOCK_CIPHER)
   #include <botan/block_cipher.h>
#endif

#if defined(BOTAN_HAS_STREAM_CIPHER)
   #include <botan/stream_cipher.h>
#endif

#if defined(BOTAN_HAS_HASH)
   #include <botan/hash.h>
#endif

#if defined(BOTAN_HAS_XOF)
   #include <botan/xof.h>
#endif

#if defined(BOTAN_HAS_CIPHER_MODES)
   #include <botan/cipher_mode.h>
#endif

#if defined(BOTAN_HAS_MAC)
   #include <botan/mac.h>
#endif

#if defined(BOTAN_HAS_ECC_GROUP)
   #include <botan/ec_group.h>
#endif

namespace Botan_CLI {

using Botan::Timer;

namespace {

class JSON_Output final {
   public:
      void add(const Timer& timer) { m_results.push_back(timer); }

      std::string print() const {
         std::ostringstream out;

         out << "[\n";

         for(size_t i = 0; i != m_results.size(); ++i) {
            const Timer& t = m_results[i];

            out << "{"
                << "\"algo\": \"" << t.get_name() << "\", "
                << "\"op\": \"" << t.doing() << "\", "
                << "\"events\": " << t.events() << ", ";

            if(t.cycles_consumed() > 0) {
               out << "\"cycles\": " << t.cycles_consumed() << ", ";
            }

            if(t.buf_size() > 0) {
               out << "\"bps\": " << static_cast<uint64_t>(t.events() / (t.value() / 1000000000.0)) << ", ";
               out << "\"buf_size\": " << t.buf_size() << ", ";
            }

            out << "\"nanos\": " << t.value() << "}";

            if(i != m_results.size() - 1) {
               out << ",";
            }

            out << "\n";
         }
         out << "]\n";

         return out.str();
      }

   private:
      std::vector<Timer> m_results;
};

class Summary final {
   public:
      Summary() = default;

      void add(const Timer& t) {
         if(t.buf_size() == 0) {
            m_ops_entries.push_back(t);
         } else {
            m_bps_entries[std::make_pair(t.doing(), t.get_name())].push_back(t);
         }
      }

      std::string print() {
         const size_t name_padding = 35;
         const size_t op_name_padding = 16;
         const size_t op_padding = 16;

         std::ostringstream result_ss;
         result_ss << std::fixed;

         if(!m_bps_entries.empty()) {
            result_ss << "\n";

            // add table header
            result_ss << std::setw(name_padding) << std::left << "algo" << std::setw(op_name_padding) << std::left
                      << "operation";

            for(const Timer& t : m_bps_entries.begin()->second) {
               result_ss << std::setw(op_padding) << std::right << (std::to_string(t.buf_size()) + " bytes");
            }
            result_ss << "\n";

            // add table entries
            for(const auto& entry : m_bps_entries) {
               if(entry.second.empty()) {
                  continue;
               }

               result_ss << std::setw(name_padding) << std::left << (entry.first.second) << std::setw(op_name_padding)
                         << std::left << (entry.first.first);

               for(const Timer& t : entry.second) {
                  if(t.events() == 0) {
                     result_ss << std::setw(op_padding) << std::right << "N/A";
                  } else {
                     result_ss << std::setw(op_padding) << std::right << std::setprecision(2)
                               << (t.bytes_per_second() / 1000.0);
                  }
               }

               result_ss << "\n";
            }

            result_ss << "\n[results are the number of 1000s bytes processed per second]\n";
         }

         if(!m_ops_entries.empty()) {
            result_ss << std::setprecision(6) << "\n";

            // sort entries
            std::sort(m_ops_entries.begin(), m_ops_entries.end());

            // add table header
            result_ss << std::setw(name_padding) << std::left << "algo" << std::setw(op_name_padding) << std::left
                      << "operation" << std::setw(op_padding) << std::right << "sec/op" << std::setw(op_padding)
                      << std::right << "op/sec"
                      << "\n";

            // add table entries
            for(const Timer& entry : m_ops_entries) {
               result_ss << std::setw(name_padding) << std::left << entry.get_name() << std::setw(op_name_padding)
                         << std::left << entry.doing() << std::setw(op_padding) << std::right
                         << entry.seconds_per_event() << std::setw(op_padding) << std::right
                         << entry.events_per_second() << "\n";
            }
         }

         return result_ss.str();
      }

   private:
      std::map<std::pair<std::string, std::string>, std::vector<Timer>> m_bps_entries;
      std::vector<Timer> m_ops_entries;
};

std::vector<size_t> unique_buffer_sizes(const std::string& cmdline_arg) {
   const size_t MAX_BUF_SIZE = 64 * 1024 * 1024;

   std::set<size_t> buf;
   for(const std::string& size_str : Command::split_on(cmdline_arg, ',')) {
      size_t x = 0;
      try {
         size_t converted = 0;
         x = static_cast<size_t>(std::stoul(size_str, &converted, 0));

         if(converted != size_str.size()) {
            throw CLI_Usage_Error("Invalid integer");
         }
      } catch(std::exception&) {
         throw CLI_Usage_Error("Invalid integer value '" + size_str + "' for option buf-size");
      }

      if(x == 0) {
         throw CLI_Usage_Error("Cannot have a zero-sized buffer");
      }

      if(x > MAX_BUF_SIZE) {
         throw CLI_Usage_Error("Specified buffer size is too large");
      }

      buf.insert(x);
   }

   return std::vector<size_t>(buf.begin(), buf.end());
}

}  // namespace

class Speed final : public Command {
   public:
      Speed() :
            Command(
               "speed --msec=500 --format=default --ecc-groups= --provider= --buf-size=1024 --clear-cpuid= --cpu-clock-speed=0 --cpu-clock-ratio=1.0 *algos") {
      }

      static std::vector<std::string> default_benchmark_list() {
         /*
         This is not intended to be exhaustive: it just hits the high
         points of the most interesting or widely used algorithms.
         */
         // clang-format off
         return {
            /* Block ciphers */
            "AES-128",
            "AES-192",
            "AES-256",
            "ARIA-128",
            "ARIA-192",
            "ARIA-256",
            "Blowfish",
            "CAST-128",
            "Camellia-128",
            "Camellia-192",
            "Camellia-256",
            "DES",
            "TripleDES",
            "GOST-28147-89",
            "IDEA",
            "Noekeon",
            "SHACAL2",
            "SM4",
            "Serpent",
            "Threefish-512",
            "Twofish",

            /* Cipher modes */
            "AES-128/CBC",
            "AES-128/CTR-BE",
            "AES-128/EAX",
            "AES-128/OCB",
            "AES-128/GCM",
            "AES-128/XTS",
            "AES-128/SIV",

            "Serpent/CBC",
            "Serpent/CTR-BE",
            "Serpent/EAX",
            "Serpent/OCB",
            "Serpent/GCM",
            "Serpent/XTS",
            "Serpent/SIV",

            "ChaCha20Poly1305",

            /* Stream ciphers */
            "RC4",
            "Salsa20",
            "ChaCha20",

            /* Hashes */
            "SHA-1",
            "SHA-256",
            "SHA-512",
            "SHA-3(256)",
            "SHA-3(512)",
            "RIPEMD-160",
            "Skein-512",
            "Blake2b",
            "Whirlpool",

            /* XOFs */
            "SHAKE-128",
            "SHAKE-256",

            /* MACs */
            "CMAC(AES-128)",
            "HMAC(SHA-256)",

            /* pubkey */
            "RSA",
            "DH",
            "ECDH",
            "ECDSA",
            "Ed25519",
            "Ed448",
            "X25519",
            "X448",
            "Kyber",
            "SPHINCS+",
            "FrodoKEM",
            "HSS-LMS",
         };
         // clang-format on
      }

      std::string group() const override { return "misc"; }

      std::string description() const override { return "Measures the speed of algorithms"; }

      void go() override {
         std::chrono::milliseconds msec(get_arg_sz("msec"));
         const std::string provider = get_arg("provider");
         std::vector<std::string> ecc_groups = Command::split_on(get_arg("ecc-groups"), ',');
         const std::string format = get_arg("format");
         const std::string clock_ratio = get_arg("cpu-clock-ratio");
         m_clock_speed = get_arg_sz("cpu-clock-speed");

         m_clock_cycle_ratio = std::strtod(clock_ratio.c_str(), nullptr);

         /*
         * This argument is intended to be the ratio between the cycle counter
         * and the actual machine cycles. It is extremely unlikely that there is
         * any machine where the cycle counter increments faster than the actual
         * clock.
         */
         if(m_clock_cycle_ratio < 0.0 || m_clock_cycle_ratio > 1.0) {
            throw CLI_Usage_Error("Unlikely CPU clock ratio of " + clock_ratio);
         }

         m_clock_cycle_ratio = 1.0 / m_clock_cycle_ratio;

         if(m_clock_speed != 0 && Botan::OS::get_cpu_cycle_counter() != 0) {
            error_output() << "The --cpu-clock-speed option is only intended to be used on "
                              "platforms without access to a cycle counter.\n"
                              "Expected incorrect results\n\n";
         }

         if(format == "table") {
            m_summary = std::make_unique<Summary>();
         } else if(format == "json") {
            m_json = std::make_unique<JSON_Output>();
         } else if(format != "default") {
            throw CLI_Usage_Error("Unknown --format type '" + format + "'");
         }

#if defined(BOTAN_HAS_ECC_GROUP)
         if(ecc_groups.empty()) {
            ecc_groups = {"secp256r1", "secp384r1", "secp521r1", "brainpool256r1", "brainpool384r1", "brainpool512r1"};
         } else if(ecc_groups.size() == 1 && ecc_groups[0] == "all") {
            auto all = Botan::EC_Group::known_named_groups();
            ecc_groups.assign(all.begin(), all.end());
         }
#endif

         std::vector<std::string> algos = get_arg_list("algos");

         const std::vector<size_t> buf_sizes = unique_buffer_sizes(get_arg("buf-size"));

         for(const std::string& cpuid_to_clear : Command::split_on(get_arg("clear-cpuid"), ',')) {
            auto bits = Botan::CPUID::bit_from_string(cpuid_to_clear);
            if(bits.empty()) {
               error_output() << "Warning don't know CPUID flag '" << cpuid_to_clear << "'\n";
            }

            for(auto bit : bits) {
               Botan::CPUID::clear_cpuid_bit(bit);
            }
         }

         if(verbose() || m_summary) {
            output() << Botan::version_string() << "\n"
                     << "CPUID: " << Botan::CPUID::to_string() << "\n\n";
         }

         const bool using_defaults = (algos.empty());
         if(using_defaults) {
            algos = default_benchmark_list();
         }

         class PerfConfig_Cli final : public PerfConfig {
            public:
               PerfConfig_Cli(std::chrono::milliseconds runtime,
                              const std::vector<std::string>& ecc_groups,
                              const std::vector<size_t>& buffer_sizes,
                              Speed* speed) :
                     m_runtime(runtime), m_ecc_groups(ecc_groups), m_buffer_sizes(buffer_sizes), m_speed(speed) {}

               const std::vector<size_t>& buffer_sizes() const override { return m_buffer_sizes; }

               const std::vector<std::string>& ecc_groups() const override { return m_ecc_groups; }

               std::chrono::milliseconds runtime() const override { return m_runtime; }

               std::ostream& error_output() const override { return m_speed->error_output(); }

               Botan::RandomNumberGenerator& rng() const override { return m_speed->rng(); }

               void record_result(const Botan::Timer& timer) const override { m_speed->record_result(timer); }

               std::unique_ptr<Botan::Timer> make_timer(const std::string& alg,
                                                        uint64_t event_mult,
                                                        const std::string& what,
                                                        const std::string& provider,
                                                        size_t buf_size) const override {
                  return m_speed->make_timer(alg, event_mult, what, provider, buf_size);
               }

            private:
               std::chrono::milliseconds m_runtime;
               std::vector<std::string> m_ecc_groups;
               std::vector<size_t> m_buffer_sizes;
               Speed* m_speed;
         };

         PerfConfig_Cli perf_config(msec, ecc_groups, buf_sizes, this);

         for(const auto& algo : algos) {
            using namespace std::placeholders;

            if(auto perf = PerfTest::get(algo)) {
               perf->go(perf_config);
            }
#if defined(BOTAN_HAS_HASH)
            else if(!Botan::HashFunction::providers(algo).empty()) {
               bench_providers_of<Botan::HashFunction>(
                  algo, provider, msec, buf_sizes, std::bind(&Speed::bench_hash, this, _1, _2, _3, _4));
            }
#endif
#if defined(BOTAN_HAS_XOF)
            else if(!Botan::XOF::providers(algo).empty()) {
               bench_providers_of<Botan::XOF>(
                  algo, provider, msec, buf_sizes, std::bind(&Speed::bench_xof, this, _1, _2, _3, _4));
            }
#endif
#if defined(BOTAN_HAS_BLOCK_CIPHER)
            else if(!Botan::BlockCipher::providers(algo).empty()) {
               bench_providers_of<Botan::BlockCipher>(
                  algo, provider, msec, buf_sizes, std::bind(&Speed::bench_block_cipher, this, _1, _2, _3, _4));
            }
#endif
#if defined(BOTAN_HAS_STREAM_CIPHER)
            else if(!Botan::StreamCipher::providers(algo).empty()) {
               bench_providers_of<Botan::StreamCipher>(
                  algo, provider, msec, buf_sizes, std::bind(&Speed::bench_stream_cipher, this, _1, _2, _3, _4));
            }
#endif
#if defined(BOTAN_HAS_CIPHER_MODES)
            else if(auto enc = Botan::Cipher_Mode::create(algo, Botan::Cipher_Dir::Encryption, provider)) {
               auto dec = Botan::Cipher_Mode::create_or_throw(algo, Botan::Cipher_Dir::Decryption, provider);
               bench_cipher_mode(*enc, *dec, msec, buf_sizes);
            }
#endif
#if defined(BOTAN_HAS_MAC)
            else if(!Botan::MessageAuthenticationCode::providers(algo).empty()) {
               bench_providers_of<Botan::MessageAuthenticationCode>(
                  algo, provider, msec, buf_sizes, std::bind(&Speed::bench_mac, this, _1, _2, _3, _4));
            }
#endif
            else {
               if(verbose() || !using_defaults) {
                  error_output() << "Unknown algorithm '" << algo << "'\n";
               }
            }
         }

         if(m_json) {
            output() << m_json->print();
         }
         if(m_summary) {
            output() << m_summary->print() << "\n";
         }

         if(verbose() && m_clock_speed == 0 && m_cycles_consumed > 0 && m_ns_taken > 0) {
            const double seconds = static_cast<double>(m_ns_taken) / 1000000000;
            const double Hz = static_cast<double>(m_cycles_consumed) / seconds;
            const double MHz = Hz / 1000000;
            output() << "\nEstimated clock speed " << MHz << " MHz\n";
         }
      }

   private:
      size_t m_clock_speed = 0;
      double m_clock_cycle_ratio = 0.0;
      uint64_t m_cycles_consumed = 0;
      uint64_t m_ns_taken = 0;
      std::unique_ptr<Summary> m_summary;
      std::unique_ptr<JSON_Output> m_json;

      void record_result(const Timer& t) {
         m_ns_taken += t.value();
         m_cycles_consumed += t.cycles_consumed();
         if(m_json) {
            m_json->add(t);
         } else {
            output() << t.to_string() << std::flush;
            if(m_summary) {
               m_summary->add(t);
            }
         }
      }

      void record_result(const std::unique_ptr<Timer>& t) { record_result(*t); }

      template <typename T>
      using bench_fn = std::function<void(T&, std::string, std::chrono::milliseconds, const std::vector<size_t>&)>;

      template <typename T>
      void bench_providers_of(const std::string& algo,
                              const std::string& provider, /* user request, if any */
                              const std::chrono::milliseconds runtime,
                              const std::vector<size_t>& buf_sizes,
                              bench_fn<T> bench_one) {
         for(const auto& prov : T::providers(algo)) {
            if(provider.empty() || provider == prov) {
               auto p = T::create(algo, prov);

               if(p) {
                  bench_one(*p, prov, runtime, buf_sizes);
               }
            }
         }
      }

      std::unique_ptr<Timer> make_timer(const std::string& name,
                                        uint64_t event_mult = 1,
                                        const std::string& what = "",
                                        const std::string& provider = "",
                                        size_t buf_size = 0) {
         return std::make_unique<Timer>(name, provider, what, event_mult, buf_size, m_clock_cycle_ratio, m_clock_speed);
      }

      std::unique_ptr<Timer> make_timer(const std::string& algo, const std::string& provider, const std::string& what) {
         return make_timer(algo, 1, what, provider, 0);
      }

#if defined(BOTAN_HAS_BLOCK_CIPHER)
      void bench_block_cipher(Botan::BlockCipher& cipher,
                              const std::string& provider,
                              std::chrono::milliseconds runtime,
                              const std::vector<size_t>& buf_sizes) {
         auto ks_timer = make_timer(cipher.name(), provider, "key schedule");

         const Botan::SymmetricKey key(rng(), cipher.maximum_keylength());
         ks_timer->run([&]() { cipher.set_key(key); });

         const size_t bs = cipher.block_size();
         std::set<size_t> buf_sizes_in_blocks;
         for(size_t buf_size : buf_sizes) {
            if(buf_size % bs == 0) {
               buf_sizes_in_blocks.insert(buf_size);
            } else {
               buf_sizes_in_blocks.insert(buf_size + bs - (buf_size % bs));
            }
         }

         for(size_t buf_size : buf_sizes_in_blocks) {
            std::vector<uint8_t> buffer(buf_size);
            const size_t mult = std::max<size_t>(1, 65536 / buf_size);
            const size_t blocks = buf_size / bs;

            auto encrypt_timer = make_timer(cipher.name(), mult * buffer.size(), "encrypt", provider, buf_size);
            auto decrypt_timer = make_timer(cipher.name(), mult * buffer.size(), "decrypt", provider, buf_size);

            encrypt_timer->run_until_elapsed(runtime, [&]() {
               for(size_t i = 0; i != mult; ++i) {
                  cipher.encrypt_n(&buffer[0], &buffer[0], blocks);
               }
            });
            record_result(encrypt_timer);

            decrypt_timer->run_until_elapsed(runtime, [&]() {
               for(size_t i = 0; i != mult; ++i) {
                  cipher.decrypt_n(&buffer[0], &buffer[0], blocks);
               }
            });
            record_result(decrypt_timer);
         }
      }
#endif

#if defined(BOTAN_HAS_STREAM_CIPHER)
      void bench_stream_cipher(Botan::StreamCipher& cipher,
                               const std::string& provider,
                               const std::chrono::milliseconds runtime,
                               const std::vector<size_t>& buf_sizes) {
         for(auto buf_size : buf_sizes) {
            const Botan::SymmetricKey key(rng(), cipher.maximum_keylength());
            cipher.set_key(key);

            if(cipher.valid_iv_length(12)) {
               const Botan::InitializationVector iv(rng(), 12);
               cipher.set_iv(iv.begin(), iv.size());
            }

            Botan::secure_vector<uint8_t> buffer = rng().random_vec(buf_size);

            const size_t mult = std::max<size_t>(1, 65536 / buf_size);

            auto encrypt_timer = make_timer(cipher.name(), mult * buffer.size(), "encrypt", provider, buf_size);

            encrypt_timer->run_until_elapsed(runtime, [&]() {
               for(size_t i = 0; i != mult; ++i) {
                  cipher.encipher(buffer);
               }
            });

            record_result(encrypt_timer);

            if(verbose()) {
               auto ks_timer = make_timer(cipher.name(), buffer.size(), "write_keystream", provider, buf_size);

               while(ks_timer->under(runtime)) {
                  ks_timer->run([&]() { cipher.write_keystream(buffer.data(), buffer.size()); });
               }
               record_result(ks_timer);
            }
         }
      }
#endif

#if defined(BOTAN_HAS_HASH)
      void bench_hash(Botan::HashFunction& hash,
                      const std::string& provider,
                      const std::chrono::milliseconds runtime,
                      const std::vector<size_t>& buf_sizes) {
         std::vector<uint8_t> output(hash.output_length());

         for(auto buf_size : buf_sizes) {
            Botan::secure_vector<uint8_t> buffer = rng().random_vec(buf_size);

            const size_t mult = std::max<size_t>(1, 65536 / buf_size);

            auto timer = make_timer(hash.name(), mult * buffer.size(), "hash", provider, buf_size);
            timer->run_until_elapsed(runtime, [&]() {
               for(size_t i = 0; i != mult; ++i) {
                  hash.update(buffer);
                  hash.final(output.data());
               }
            });
            record_result(timer);
         }
      }
#endif

#if defined(BOTAN_HAS_XOF)
      void bench_xof(Botan::XOF& xof,
                     const std::string& provider,
                     const std::chrono::milliseconds runtime,
                     const std::vector<size_t>& buf_sizes) {
         for(auto buf_size : buf_sizes) {
            Botan::secure_vector<uint8_t> in = rng().random_vec(buf_size);
            Botan::secure_vector<uint8_t> out(buf_size);

            auto in_timer = make_timer(xof.name(), in.size(), "input", provider, buf_size);
            in_timer->run_until_elapsed(runtime / 2, [&]() { xof.update(in); });

            auto out_timer = make_timer(xof.name(), out.size(), "output", provider, buf_size);
            out_timer->run_until_elapsed(runtime / 2, [&] { xof.output(out); });

            record_result(in_timer);
            record_result(out_timer);
         }
      }
#endif

#if defined(BOTAN_HAS_MAC)
      void bench_mac(Botan::MessageAuthenticationCode& mac,
                     const std::string& provider,
                     const std::chrono::milliseconds runtime,
                     const std::vector<size_t>& buf_sizes) {
         std::vector<uint8_t> output(mac.output_length());

         for(auto buf_size : buf_sizes) {
            Botan::secure_vector<uint8_t> buffer = rng().random_vec(buf_size);
            const size_t mult = std::max<size_t>(1, 65536 / buf_size);

            const Botan::SymmetricKey key(rng(), mac.maximum_keylength());
            mac.set_key(key);

            auto timer = make_timer(mac.name(), mult * buffer.size(), "mac", provider, buf_size);
            timer->run_until_elapsed(runtime, [&]() {
               for(size_t i = 0; i != mult; ++i) {
                  if(mac.fresh_key_required_per_message()) {
                     mac.set_key(key);
                  }
                  mac.start(nullptr, 0);
                  mac.update(buffer);
                  mac.final(output.data());
               }
            });

            record_result(timer);
         }
      }
#endif

#if defined(BOTAN_HAS_CIPHER_MODES)
      void bench_cipher_mode(Botan::Cipher_Mode& enc,
                             Botan::Cipher_Mode& dec,
                             const std::chrono::milliseconds runtime,
                             const std::vector<size_t>& buf_sizes) {
         auto ks_timer = make_timer(enc.name(), enc.provider(), "key schedule");

         const Botan::SymmetricKey key(rng(), enc.key_spec().maximum_keylength());

         ks_timer->run([&]() { enc.set_key(key); });
         ks_timer->run([&]() { dec.set_key(key); });

         record_result(ks_timer);

         for(auto buf_size : buf_sizes) {
            Botan::secure_vector<uint8_t> buffer = rng().random_vec(buf_size);
            const size_t mult = std::max<size_t>(1, 65536 / buf_size);

            auto encrypt_timer = make_timer(enc.name(), mult * buffer.size(), "encrypt", enc.provider(), buf_size);
            auto decrypt_timer = make_timer(dec.name(), mult * buffer.size(), "decrypt", dec.provider(), buf_size);

            Botan::secure_vector<uint8_t> iv = rng().random_vec(enc.default_nonce_length());

            if(buf_size >= enc.minimum_final_size()) {
               encrypt_timer->run_until_elapsed(runtime, [&]() {
                  for(size_t i = 0; i != mult; ++i) {
                     enc.start(iv);
                     enc.finish(buffer);
                     buffer.resize(buf_size);  // remove any tag or padding
                  }
               });

               while(decrypt_timer->under(runtime)) {
                  if(!iv.empty()) {
                     iv[iv.size() - 1] += 1;
                  }

                  // Create a valid ciphertext/tag for decryption to run on
                  buffer.resize(buf_size);
                  enc.start(iv);
                  enc.finish(buffer);

                  Botan::secure_vector<uint8_t> dbuffer;

                  decrypt_timer->run([&]() {
                     for(size_t i = 0; i != mult; ++i) {
                        dbuffer = buffer;
                        dec.start(iv);
                        dec.finish(dbuffer);
                     }
                  });
               }
            }
            record_result(encrypt_timer);
            record_result(decrypt_timer);
         }
      }
#endif
};

BOTAN_REGISTER_COMMAND("speed", Speed);

}  // namespace Botan_CLI
