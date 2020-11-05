/*
* (C) 2009,2010,2014,2015,2017,2018 Jack Lloyd
* (C) 2015 Simon Warta (Kullo GmbH)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"
#include "../tests/test_rng.h" // FIXME

#include <sstream>
#include <iomanip>
#include <chrono>
#include <functional>
#include <algorithm>
#include <map>
#include <set>

// Always available:
#include <botan/entropy_src.h>
#include <botan/parsing.h>
#include <botan/cpuid.h>
#include <botan/internal/os_utils.h>
#include <botan/internal/timer.h>
#include <botan/version.h>

#if defined(BOTAN_HAS_BIGINT)
   #include <botan/bigint.h>
   #include <botan/divide.h>
#endif

#if defined(BOTAN_HAS_BLOCK_CIPHER)
   #include <botan/block_cipher.h>
#endif

#if defined(BOTAN_HAS_STREAM_CIPHER)
   #include <botan/stream_cipher.h>
#endif

#if defined(BOTAN_HAS_HASH)
   #include <botan/hash.h>
#endif

#if defined(BOTAN_HAS_CIPHER_MODES)
   #include <botan/cipher_mode.h>
#endif

#if defined(BOTAN_HAS_MAC)
   #include <botan/mac.h>
#endif

#if defined(BOTAN_HAS_AUTO_SEEDING_RNG)
   #include <botan/auto_rng.h>
#endif

#if defined(BOTAN_HAS_SYSTEM_RNG)
   #include <botan/system_rng.h>
#endif

#if defined(BOTAN_HAS_HMAC_DRBG)
   #include <botan/hmac_drbg.h>
#endif

#if defined(BOTAN_HAS_PROCESSOR_RNG)
   #include <botan/processor_rng.h>
#endif

#if defined(BOTAN_HAS_CHACHA_RNG)
   #include <botan/chacha_rng.h>
#endif

#if defined(BOTAN_HAS_FPE_FE1)
   #include <botan/fpe_fe1.h>
#endif

#if defined(BOTAN_HAS_RFC3394_KEYWRAP)
   #include <botan/rfc3394.h>
#endif

#if defined(BOTAN_HAS_COMPRESSION)
   #include <botan/compression.h>
#endif

#if defined(BOTAN_HAS_POLY_DBL)
   #include <botan/internal/poly_dbl.h>
#endif

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO)
   #include <botan/pkcs8.h>
   #include <botan/pubkey.h>
   #include <botan/pk_algs.h>
   #include <botan/x509_key.h>
   #include <botan/workfactor.h>
#endif

#if defined(BOTAN_HAS_NUMBERTHEORY)
   #include <botan/numthry.h>
   #include <botan/reducer.h>
   #include <botan/curve_nistp.h>
   #include <botan/internal/primality.h>
#endif

#if defined(BOTAN_HAS_ECC_GROUP)
   #include <botan/ec_group.h>
#endif

#if defined(BOTAN_HAS_DL_GROUP)
   #include <botan/dl_group.h>
#endif

#if defined(BOTAN_HAS_MCELIECE)
   #include <botan/mceliece.h>
#endif

#if defined(BOTAN_HAS_ECDSA)
   #include <botan/ecdsa.h>
#endif

#if defined(BOTAN_HAS_NEWHOPE)
   #include <botan/newhope.h>
#endif

#if defined(BOTAN_HAS_SCRYPT)
   #include <botan/scrypt.h>
#endif

#if defined(BOTAN_HAS_ARGON2)
   #include <botan/argon2.h>
#endif

#if defined(BOTAN_HAS_BCRYPT)
   #include <botan/bcrypt.h>
#endif

#if defined(BOTAN_HAS_PASSHASH9)
   #include <botan/passhash9.h>
#endif

namespace Botan_CLI {

using Botan::Timer;

namespace {

class JSON_Output final
   {
   public:
      void add(const Timer& timer) { m_results.push_back(timer); }

      std::string print() const
         {
         std::ostringstream out;

         out << "[\n";

         for(size_t i = 0; i != m_results.size(); ++i)
            {
            if(i != 0)
               out << ",";

            const Timer& t = m_results[i];

            out << '{';
            out << "\"algo\": \"" << t.get_name() << "\", ";
            out << "\"op\": \"" << t.doing() << "\", ";

            out << "\"events\": " << t.events() << ", ";
            if(t.cycles_consumed() > 0)
               out << "\"cycles\": " << t.cycles_consumed() << ", ";
            if(t.buf_size() > 0)
               {
               out << "\"bps\": " << static_cast<uint64_t>(t.events() / (t.value() / 1000000000.0)) << ", ";
               out << "\"buf_size\": " << t.buf_size() << ", ";
               }

            out << "\"nanos\": " << t.value();

            out << "}\n";
            }
         out << "]\n";

         return out.str();
         }
   private:
      std::vector<Timer> m_results;
   };

class Summary final
   {
   public:
      Summary() {}

      void add(const Timer& t)
         {
         if(t.buf_size() == 0)
            {
            m_ops_entries.push_back(t);
            }
         else
            {
            m_bps_entries[std::make_pair(t.doing(), t.get_name())].push_back(t);
            }
         }

      std::string print()
         {
         const size_t name_padding = 35;
         const size_t op_name_padding = 16;
         const size_t op_padding = 16;

         std::ostringstream result_ss;
         result_ss << std::fixed;

         if(m_bps_entries.size() > 0)
            {
            result_ss << "\n";

            // add table header
            result_ss << std::setw(name_padding) << std::left << "algo"
                      << std::setw(op_name_padding) << std::left << "operation";

            for(const Timer& t : m_bps_entries.begin()->second)
               {
               result_ss << std::setw(op_padding) << std::right << (std::to_string(t.buf_size()) + " bytes");
               }
            result_ss << "\n";

            // add table entries
            for(const auto& entry : m_bps_entries)
               {
               if(entry.second.empty())
                  continue;

               result_ss << std::setw(name_padding) << std::left << (entry.first.second)
                         << std::setw(op_name_padding) << std::left << (entry.first.first);

               for(const Timer& t : entry.second)
                  {

                  if(t.events() == 0)
                     {
                     result_ss << std::setw(op_padding) << std::right << "N/A";
                     }
                  else
                     {
                     result_ss << std::setw(op_padding) << std::right
                               << std::setprecision(2) << (t.bytes_per_second() / 1000.0);
                     }
                  }

               result_ss << "\n";
               }

            result_ss << "\n[results are the number of 1000s bytes processed per second]\n";
            }

         if(m_ops_entries.size() > 0)
            {
            result_ss << std::setprecision(6) << "\n";

            // sort entries
            std::sort(m_ops_entries.begin(), m_ops_entries.end());

            // add table header
            result_ss << std::setw(name_padding) << std::left << "algo"
                      << std::setw(op_name_padding) << std::left << "operation"
                      << std::setw(op_padding) << std::right << "sec/op"
                      << std::setw(op_padding) << std::right << "op/sec"
                      << "\n";

            // add table entries
            for(const Timer& entry : m_ops_entries)
               {
               result_ss << std::setw(name_padding) << std::left << entry.get_name()
                         << std::setw(op_name_padding) << std::left << entry.doing()
                         << std::setw(op_padding) << std::right << entry.seconds_per_event()
                         << std::setw(op_padding) << std::right << entry.events_per_second()
                         << "\n";
               }
            }

         return result_ss.str();
         }

   private:
      std::map<std::pair<std::string, std::string>, std::vector<Timer>> m_bps_entries;
      std::vector<Timer> m_ops_entries;
   };

std::vector<size_t> unique_buffer_sizes(const std::string& cmdline_arg)
   {
   const size_t MAX_BUF_SIZE = 64*1024*1024;

   std::set<size_t> buf;
   for(std::string size_str : Botan::split_on(cmdline_arg, ','))
      {
      size_t x = 0;
      try
         {
         size_t converted = 0;
         x = static_cast<size_t>(std::stoul(size_str, &converted, 0));

         if(converted != size_str.size())
            throw CLI_Usage_Error("Invalid integer");
         }
      catch(std::exception&)
         {
         throw CLI_Usage_Error("Invalid integer value '" + size_str + "' for option buf-size");
         }

      if(x == 0)
         throw CLI_Usage_Error("Cannot have a zero-sized buffer");

      if(x > MAX_BUF_SIZE)
         throw CLI_Usage_Error("Specified buffer size is too large");

      buf.insert(x);
      }

   return std::vector<size_t>(buf.begin(), buf.end());
   }

}

class Speed final : public Command
   {
   public:
      Speed()
         : Command("speed --msec=500 --format=default --ecc-groups= --provider= --buf-size=1024 --clear-cpuid= --cpu-clock-speed=0 --cpu-clock-ratio=1.0 *algos") {}

      std::vector<std::string> default_benchmark_list()
         {
         /*
         This is not intended to be exhaustive: it just hits the high
         points of the most interesting or widely used algorithms.
         */

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
            "CAST-256",
            "Camellia-128",
            "Camellia-192",
            "Camellia-256",
            "DES",
            "TripleDES",
            "GOST-28147-89",
            "IDEA",
            "KASUMI",
            "MISTY1",
            "Noekeon",
            "SHACAL2",
            "SM4",
            "Serpent",
            "Threefish-512",
            "Twofish",
            "XTEA",

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
            "SHA-160",
            "SHA-256",
            "SHA-512",
            "SHA-3(256)",
            "SHA-3(512)",
            "RIPEMD-160",
            "Skein-512",
            "Blake2b",
            "Tiger",
            "Whirlpool",

            /* MACs */
            "CMAC(AES-128)",
            "HMAC(SHA-256)",

            /* pubkey */
            "RSA",
            "DH",
            "ECDH",
            "ECDSA",
            "Ed25519",
            "Curve25519",
            "NEWHOPE",
            "McEliece",
            };
         }

      std::string group() const override
         {
         return "misc";
         }

      std::string description() const override
         {
         return "Measures the speed of algorithms";
         }

      void go() override
         {
         std::chrono::milliseconds msec(get_arg_sz("msec"));
         const std::string provider = get_arg("provider");
         std::vector<std::string> ecc_groups = Botan::split_on(get_arg("ecc-groups"), ',');
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
         if(m_clock_cycle_ratio < 0.0 || m_clock_cycle_ratio > 1.0)
            throw CLI_Usage_Error("Unlikely CPU clock ratio of " + clock_ratio);

         m_clock_cycle_ratio = 1.0 / m_clock_cycle_ratio;

         if(m_clock_speed != 0 && Botan::OS::get_cpu_cycle_counter() != 0)
            {
            error_output() << "The --cpu-clock-speed option is only intended to be used on "
                              "platforms without access to a cycle counter.\n"
                              "Expected incorrect results\n\n";
            }

         if(format == "table")
            m_summary.reset(new Summary);
         else if(format == "json")
            m_json.reset(new JSON_Output);
         else if(format != "default")
            throw CLI_Usage_Error("Unknown --format type '" + format + "'");

#if defined(BOTAN_HAS_ECC_GROUP)
         if(ecc_groups.empty())
            {
            ecc_groups = { "secp256r1", "brainpool256r1",
                           "secp384r1", "brainpool384r1",
                           "secp521r1", "brainpool512r1" };
            }
         else if(ecc_groups.size() == 1 && ecc_groups[0] == "all")
            {
            auto all = Botan::EC_Group::known_named_groups();
            ecc_groups.assign(all.begin(), all.end());
            }
#endif

         std::vector<std::string> algos = get_arg_list("algos");

         const std::vector<size_t> buf_sizes = unique_buffer_sizes(get_arg("buf-size"));

         for(std::string cpuid_to_clear : Botan::split_on(get_arg("clear-cpuid"), ','))
            {
            auto bits = Botan::CPUID::bit_from_string(cpuid_to_clear);
            if(bits.empty())
               {
               error_output() << "Warning don't know CPUID flag '" << cpuid_to_clear << "'\n";
               }

            for(auto bit : bits)
               {
               Botan::CPUID::clear_cpuid_bit(bit);
               }
            }

         if(verbose() || m_summary)
            {
            output() << Botan::version_string() << "\n"
                     << "CPUID: " << Botan::CPUID::to_string() << "\n\n";
            }

         const bool using_defaults = (algos.empty());
         if(using_defaults)
            {
            algos = default_benchmark_list();
            }

         for(auto algo : algos)
            {
            using namespace std::placeholders;

            if(false)
               {
               // Since everything might be disabled, need a block to else if from
               }
#if defined(BOTAN_HAS_HASH)
            else if(Botan::HashFunction::providers(algo).size() > 0)
               {
               bench_providers_of<Botan::HashFunction>(
                  algo, provider, msec, buf_sizes,
                  std::bind(&Speed::bench_hash, this, _1, _2, _3, _4));
               }
#endif
#if defined(BOTAN_HAS_BLOCK_CIPHER)
            else if(Botan::BlockCipher::providers(algo).size() > 0)
               {
               bench_providers_of<Botan::BlockCipher>(
                  algo, provider, msec, buf_sizes,
                  std::bind(&Speed::bench_block_cipher, this, _1, _2, _3, _4));
               }
#endif
#if defined(BOTAN_HAS_STREAM_CIPHER)
            else if(Botan::StreamCipher::providers(algo).size() > 0)
               {
               bench_providers_of<Botan::StreamCipher>(
                  algo, provider, msec, buf_sizes,
                  std::bind(&Speed::bench_stream_cipher, this, _1, _2, _3, _4));
               }
#endif
#if defined(BOTAN_HAS_CIPHER_MODES)
            else if(auto enc = Botan::Cipher_Mode::create(algo, Botan::ENCRYPTION, provider))
               {
               auto dec = Botan::Cipher_Mode::create_or_throw(algo, Botan::DECRYPTION, provider);
               bench_cipher_mode(*enc, *dec, msec, buf_sizes);
               }
#endif
#if defined(BOTAN_HAS_MAC)
            else if(Botan::MessageAuthenticationCode::providers(algo).size() > 0)
               {
               bench_providers_of<Botan::MessageAuthenticationCode>(
                  algo, provider, msec, buf_sizes,
                  std::bind(&Speed::bench_mac, this, _1, _2, _3, _4));
               }
#endif
#if defined(BOTAN_HAS_RSA)
            else if(algo == "RSA")
               {
               bench_rsa(provider, msec);
               }
            else if(algo == "RSA_keygen")
               {
               bench_rsa_keygen(provider, msec);
               }
#endif
#if defined(BOTAN_HAS_ECDSA)
            else if(algo == "ECDSA")
               {
               bench_ecdsa(ecc_groups, provider, msec);
               }
            else if(algo == "ecdsa_recovery")
               {
               bench_ecdsa_recovery(ecc_groups, provider, msec);
               }
#endif
#if defined(BOTAN_HAS_SM2)
            else if(algo == "SM2")
               {
               bench_sm2(ecc_groups, provider, msec);
               }
#endif
#if defined(BOTAN_HAS_ECKCDSA)
            else if(algo == "ECKCDSA")
               {
               bench_eckcdsa(ecc_groups, provider, msec);
               }
#endif
#if defined(BOTAN_HAS_GOST_34_10_2001)
            else if(algo == "GOST-34.10")
               {
               bench_gost_3410(provider, msec);
               }
#endif
#if defined(BOTAN_HAS_ECGDSA)
            else if(algo == "ECGDSA")
               {
               bench_ecgdsa(ecc_groups, provider, msec);
               }
#endif
#if defined(BOTAN_HAS_ED25519)
            else if(algo == "Ed25519")
               {
               bench_ed25519(provider, msec);
               }
#endif
#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
            else if(algo == "DH")
               {
               bench_dh(provider, msec);
               }
#endif
#if defined(BOTAN_HAS_DSA)
            else if(algo == "DSA")
               {
               bench_dsa(provider, msec);
               }
#endif
#if defined(BOTAN_HAS_ELGAMAL)
            else if(algo == "ElGamal")
               {
               bench_elgamal(provider, msec);
               }
#endif
#if defined(BOTAN_HAS_ECDH)
            else if(algo == "ECDH")
               {
               bench_ecdh(ecc_groups, provider, msec);
               }
#endif
#if defined(BOTAN_HAS_CURVE_25519)
            else if(algo == "Curve25519")
               {
               bench_curve25519(provider, msec);
               }
#endif
#if defined(BOTAN_HAS_MCELIECE)
            else if(algo == "McEliece")
               {
               bench_mceliece(provider, msec);
               }
#endif
#if defined(BOTAN_HAS_XMSS_RFC8391)
            else if(algo == "XMSS")
               {
               bench_xmss(provider, msec);
               }
#endif
#if defined(BOTAN_HAS_NEWHOPE) && defined(BOTAN_HAS_CHACHA_RNG)
            else if(algo == "NEWHOPE")
               {
               bench_newhope(provider, msec);
               }
#endif
#if defined(BOTAN_HAS_SCRYPT)
            else if(algo == "scrypt")
               {
               bench_scrypt(provider, msec);
               }
#endif
#if defined(BOTAN_HAS_ARGON2)
            else if(algo == "argon2")
               {
               bench_argon2(provider, msec);
               }
#endif
#if defined(BOTAN_HAS_BCRYPT)
            else if(algo == "bcrypt")
               {
               bench_bcrypt();
               }
#endif
#if defined(BOTAN_HAS_PASSHASH9)
            else if(algo == "passhash9")
               {
               bench_passhash9();
               }
#endif
#if defined(BOTAN_HAS_POLY_DBL)
            else if(algo == "poly_dbl")
               {
               bench_poly_dbl(msec);
               }
#endif

#if defined(BOTAN_HAS_DL_GROUP)
            else if(algo == "modexp")
               {
               bench_modexp(msec);
               }
#endif

#if defined(BOTAN_HAS_BIGINT)
            else if(algo == "mp_mul")
               {
               bench_mp_mul(msec);
               }
            else if(algo == "mp_div")
               {
               bench_mp_div(msec);
               }
            else if(algo == "mp_div10")
               {
               bench_mp_div10(msec);
               }
#endif

#if defined(BOTAN_HAS_NUMBERTHEORY)
            else if(algo == "primality_test")
               {
               bench_primality_tests(msec);
               }
            else if(algo == "random_prime")
               {
               bench_random_prime(msec);
               }
            else if(algo == "inverse_mod")
               {
               bench_inverse_mod(msec);
               }
            else if(algo == "bn_redc")
               {
               bench_bn_redc(msec);
               }
            else if(algo == "nistp_redc")
               {
               bench_nistp_redc(msec);
               }
#endif

#if defined(BOTAN_HAS_FPE_FE1)
            else if(algo == "fpe_fe1")
               {
               bench_fpe_fe1(msec);
               }
#endif

#if defined(BOTAN_HAS_RFC3394_KEYWRAP)
            else if(algo == "rfc3394")
               {
               bench_rfc3394(msec);
               }
#endif

#if defined(BOTAN_HAS_ECC_GROUP)
            else if(algo == "ecc_mult")
               {
               bench_ecc_mult(ecc_groups, msec);
               }
            else if(algo == "ecc_ops")
               {
               bench_ecc_ops(ecc_groups, msec);
               }
            else if(algo == "ecc_init")
               {
               bench_ecc_init(ecc_groups, msec);
               }
            else if(algo == "os2ecp")
               {
               bench_os2ecp(ecc_groups, msec);
               }
#endif
            else if(algo == "RNG")
               {
#if defined(BOTAN_HAS_AUTO_SEEDING_RNG)
               Botan::AutoSeeded_RNG auto_rng;
               bench_rng(auto_rng, "AutoSeeded_RNG (with reseed)", msec, buf_sizes);
#endif

#if defined(BOTAN_HAS_SYSTEM_RNG)
               bench_rng(Botan::system_rng(), "System_RNG", msec, buf_sizes);
#endif

#if defined(BOTAN_HAS_PROCESSOR_RNG)
               if(Botan::Processor_RNG::available())
                  {
                  Botan::Processor_RNG hwrng;
                  bench_rng(hwrng, "Processor_RNG", msec, buf_sizes);
                  }
#endif

#if defined(BOTAN_HAS_HMAC_DRBG)
               for(std::string hash : { "SHA-256", "SHA-384", "SHA-512" })
                  {
                  Botan::HMAC_DRBG hmac_drbg(hash);
                  bench_rng(hmac_drbg, hmac_drbg.name(), msec, buf_sizes);
                  }
#endif

#if defined(BOTAN_HAS_CHACHA_RNG)
               // Provide a dummy seed
               Botan::ChaCha_RNG chacha_rng(Botan::secure_vector<uint8_t>(32));
               bench_rng(chacha_rng, "ChaCha_RNG", msec, buf_sizes);
#endif

               }
            else if(algo == "entropy")
               {
               bench_entropy_sources(msec);
               }
            else
               {
               if(verbose() || !using_defaults)
                  {
                  error_output() << "Unknown algorithm '" << algo << "'\n";
                  }
               }
            }

         if(m_json)
            {
            output() << m_json->print();
            }
         if(m_summary)
            {
            output() << m_summary->print() << "\n";
            }

         if(verbose() && m_clock_speed == 0 && m_cycles_consumed > 0 && m_ns_taken > 0)
            {
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

      void record_result(const std::unique_ptr<Timer>& t)
         {
         m_ns_taken += t->value();
         m_cycles_consumed += t->cycles_consumed();
         if(m_json)
            {
            m_json->add(*t);
            }
         else
            {
            output() << t->to_string() << std::flush;
            if(m_summary)
               m_summary->add(*t);
            }
         }

      template<typename T>
      using bench_fn = std::function<void (T&,
                                           std::string,
                                           std::chrono::milliseconds,
                                           const std::vector<size_t>&)>;

      template<typename T>
      void bench_providers_of(const std::string& algo,
                              const std::string& provider, /* user request, if any */
                              const std::chrono::milliseconds runtime,
                              const std::vector<size_t>& buf_sizes,
                              bench_fn<T> bench_one)
         {
         for(auto const& prov : T::providers(algo))
            {
            if(provider.empty() || provider == prov)
               {
               auto p = T::create(algo, prov);

               if(p)
                  {
                  bench_one(*p, prov, runtime, buf_sizes);
                  }
               }
            }
         }

      std::unique_ptr<Timer> make_timer(const std::string& name,
                                        uint64_t event_mult = 1,
                                        const std::string& what = "",
                                        const std::string& provider = "",
                                        size_t buf_size = 0)
         {
         return std::unique_ptr<Timer>(
            new Timer(name, provider, what, event_mult, buf_size,
                      m_clock_cycle_ratio, m_clock_speed));
         }

      std::unique_ptr<Timer> make_timer(const std::string& algo,
                                        const std::string& provider,
                                        const std::string& what)
         {
         return make_timer(algo, 1, what, provider, 0);
         }

#if defined(BOTAN_HAS_BLOCK_CIPHER)
      void bench_block_cipher(Botan::BlockCipher& cipher,
                              const std::string& provider,
                              std::chrono::milliseconds runtime,
                              const std::vector<size_t>& buf_sizes)
         {
         std::unique_ptr<Timer> ks_timer = make_timer(cipher.name(), provider, "key schedule");

         const Botan::SymmetricKey key(rng(), cipher.maximum_keylength());
         ks_timer->run([&]() { cipher.set_key(key); });

         const size_t bs = cipher.block_size();
         std::set<size_t> buf_sizes_in_blocks;
         for(size_t buf_size : buf_sizes)
            {
            if(buf_size % bs == 0)
               buf_sizes_in_blocks.insert(buf_size);
            else
               buf_sizes_in_blocks.insert(buf_size + bs - (buf_size % bs));
            }

         for(size_t buf_size : buf_sizes_in_blocks)
            {
            std::vector<uint8_t> buffer(buf_size);
            const size_t blocks = buf_size / bs;

            std::unique_ptr<Timer> encrypt_timer = make_timer(cipher.name(), buffer.size(), "encrypt", provider, buf_size);
            std::unique_ptr<Timer> decrypt_timer = make_timer(cipher.name(), buffer.size(), "decrypt", provider, buf_size);

            encrypt_timer->run_until_elapsed(runtime, [&]() { cipher.encrypt_n(&buffer[0], &buffer[0], blocks); });
            record_result(encrypt_timer);

            decrypt_timer->run_until_elapsed(runtime, [&]() { cipher.decrypt_n(&buffer[0], &buffer[0], blocks); });
            record_result(decrypt_timer);
            }
         }
#endif

#if defined(BOTAN_HAS_STREAM_CIPHER)
      void bench_stream_cipher(
         Botan::StreamCipher& cipher,
         const std::string& provider,
         const std::chrono::milliseconds runtime,
         const std::vector<size_t>& buf_sizes)
         {
         for(auto buf_size : buf_sizes)
            {
            Botan::secure_vector<uint8_t> buffer = rng().random_vec(buf_size);

            std::unique_ptr<Timer> encrypt_timer = make_timer(cipher.name(), buffer.size(), "encrypt", provider, buf_size);

            const Botan::SymmetricKey key(rng(), cipher.maximum_keylength());
            cipher.set_key(key);

            if(cipher.valid_iv_length(12))
               {
               const Botan::InitializationVector iv(rng(), 12);
               cipher.set_iv(iv.begin(), iv.size());
               }

            while(encrypt_timer->under(runtime))
               {
               encrypt_timer->run([&]() { cipher.encipher(buffer); });
               }

            record_result(encrypt_timer);
            }
         }
#endif

#if defined(BOTAN_HAS_HASH)
      void bench_hash(
         Botan::HashFunction& hash,
         const std::string& provider,
         const std::chrono::milliseconds runtime,
         const std::vector<size_t>& buf_sizes)
         {
         std::vector<uint8_t> output(hash.output_length());

         for(auto buf_size : buf_sizes)
            {
            Botan::secure_vector<uint8_t> buffer = rng().random_vec(buf_size);

            std::unique_ptr<Timer> timer = make_timer(hash.name(), buffer.size(), "hash", provider, buf_size);
            timer->run_until_elapsed(runtime, [&]() { hash.update(buffer); hash.final(output.data()); });
            record_result(timer);
            }
         }
#endif

#if defined(BOTAN_HAS_MAC)
      void bench_mac(
         Botan::MessageAuthenticationCode& mac,
         const std::string& provider,
         const std::chrono::milliseconds runtime,
         const std::vector<size_t>& buf_sizes)
         {
         std::vector<uint8_t> output(mac.output_length());

         for(auto buf_size : buf_sizes)
            {
            Botan::secure_vector<uint8_t> buffer = rng().random_vec(buf_size);

            const Botan::SymmetricKey key(rng(), mac.maximum_keylength());
            mac.set_key(key);
            mac.start(nullptr, 0);

            std::unique_ptr<Timer> timer = make_timer(mac.name(), buffer.size(), "mac", provider, buf_size);
            timer->run_until_elapsed(runtime, [&]() { mac.update(buffer); });
            timer->run([&]() { mac.final(output.data()); });
            record_result(timer);
            }
         }
#endif

#if defined(BOTAN_HAS_CIPHER_MODES)
      void bench_cipher_mode(
         Botan::Cipher_Mode& enc,
         Botan::Cipher_Mode& dec,
         const std::chrono::milliseconds runtime,
         const std::vector<size_t>& buf_sizes)
         {
         std::unique_ptr<Timer> ks_timer = make_timer(enc.name(), enc.provider(), "key schedule");

         const Botan::SymmetricKey key(rng(), enc.key_spec().maximum_keylength());

         ks_timer->run([&]() { enc.set_key(key); });
         ks_timer->run([&]() { dec.set_key(key); });

         record_result(ks_timer);

         for(auto buf_size : buf_sizes)
            {
            Botan::secure_vector<uint8_t> buffer = rng().random_vec(buf_size);

            std::unique_ptr<Timer> encrypt_timer = make_timer(enc.name(), buffer.size(), "encrypt", enc.provider(), buf_size);
            std::unique_ptr<Timer> decrypt_timer = make_timer(dec.name(), buffer.size(), "decrypt", dec.provider(), buf_size);

            Botan::secure_vector<uint8_t> iv = rng().random_vec(enc.default_nonce_length());

            if(buf_size >= enc.minimum_final_size())
               {
               while(encrypt_timer->under(runtime) && decrypt_timer->under(runtime))
                  {
                  // Must run in this order, or AEADs will reject the ciphertext
                  encrypt_timer->run([&]() { enc.start(iv); enc.finish(buffer); });

                  decrypt_timer->run([&]() { dec.start(iv); dec.finish(buffer); });

                  if(iv.size() > 0)
                     {
                     iv[iv.size()-1] += 1;
                     }
                  }
               }

            record_result(encrypt_timer);
            record_result(decrypt_timer);
            }
         }
#endif

      void bench_rng(
         Botan::RandomNumberGenerator& rng,
         const std::string& rng_name,
         const std::chrono::milliseconds runtime,
         const std::vector<size_t>& buf_sizes)
         {
         for(auto buf_size : buf_sizes)
            {
            Botan::secure_vector<uint8_t> buffer(buf_size);

#if defined(BOTAN_HAS_SYSTEM_RNG)
            rng.reseed_from_rng(Botan::system_rng(), 256);
#endif

            std::unique_ptr<Timer> timer = make_timer(rng_name, buffer.size(), "generate", "", buf_size);
            timer->run_until_elapsed(runtime, [&]() { rng.randomize(buffer.data(), buffer.size()); });
            record_result(timer);
            }
         }

      void bench_entropy_sources(const std::chrono::milliseconds)
         {
         Botan::Entropy_Sources& srcs = Botan::Entropy_Sources::global_sources();

         for(auto src : srcs.enabled_sources())
            {
            size_t entropy_bits = 0;
            Botan_Tests::SeedCapturing_RNG rng;

            std::unique_ptr<Timer> timer = make_timer(src, "", "bytes");
            timer->run([&]() { entropy_bits = srcs.poll_just(rng, src); });

            size_t compressed_size = 0;

#if defined(BOTAN_HAS_ZLIB)
            std::unique_ptr<Botan::Compression_Algorithm> comp(Botan::make_compressor("zlib"));

            if(comp)
               {
               Botan::secure_vector<uint8_t> compressed;
               compressed.assign(rng.seed_material().begin(), rng.seed_material().end());
               comp->start(9);
               comp->finish(compressed);

               compressed_size = compressed.size();
               }
#endif

            std::ostringstream msg;

            msg << "Entropy source " << src << " output " << rng.seed_material().size() << " bytes"
                << " estimated entropy " << entropy_bits << " in " << timer->milliseconds() << " ms";

            if(compressed_size > 0)
               {
               msg << " output compressed to " << compressed_size << " bytes";
               }

            msg << " total samples " << rng.samples() << "\n";

            timer->set_custom_msg(msg.str());

            record_result(timer);
            }
         }

#if defined(BOTAN_HAS_ECC_GROUP)
      void bench_ecc_ops(const std::vector<std::string>& groups, const std::chrono::milliseconds runtime)
         {
         for(std::string group_name : groups)
            {
            const Botan::EC_Group ec_group(group_name);

            std::unique_ptr<Timer> add_timer = make_timer(group_name + " add");
            std::unique_ptr<Timer> addf_timer = make_timer(group_name + " addf");
            std::unique_ptr<Timer> dbl_timer = make_timer(group_name + " dbl");

            const Botan::PointGFp& base_point = ec_group.get_base_point();
            Botan::PointGFp non_affine_pt = ec_group.get_base_point() * 1776; // create a non-affine point
            Botan::PointGFp pt = ec_group.get_base_point();

            std::vector<Botan::BigInt> ws(Botan::PointGFp::WORKSPACE_SIZE);

            while(add_timer->under(runtime) && addf_timer->under(runtime) && dbl_timer->under(runtime))
               {
               dbl_timer->run([&]() { pt.mult2(ws); });
               add_timer->run([&]() { pt.add(non_affine_pt, ws); });
               addf_timer->run([&]() { pt.add_affine(base_point, ws); });
               }

            record_result(dbl_timer);
            record_result(add_timer);
            record_result(addf_timer);
            }
         }

      void bench_ecc_init(const std::vector<std::string>& groups, const std::chrono::milliseconds runtime)
         {
         for(std::string group_name : groups)
            {
            std::unique_ptr<Timer> timer = make_timer(group_name + " initialization");

            while(timer->under(runtime))
               {
               Botan::EC_Group::clear_registered_curve_data();
               timer->run([&]() { Botan::EC_Group group(group_name); });
               }

            record_result(timer);
            }
         }

      void bench_ecc_mult(const std::vector<std::string>& groups, const std::chrono::milliseconds runtime)
         {
         for(std::string group_name : groups)
            {
            const Botan::EC_Group ec_group(group_name);

            std::unique_ptr<Timer> mult_timer = make_timer(group_name + " Montgomery ladder");
            std::unique_ptr<Timer> blinded_mult_timer = make_timer(group_name + " blinded comb");
            std::unique_ptr<Timer> blinded_var_mult_timer = make_timer(group_name + " blinded window");

            const Botan::PointGFp& base_point = ec_group.get_base_point();

            std::vector<Botan::BigInt> ws;

            while(mult_timer->under(runtime) &&
                  blinded_mult_timer->under(runtime) &&
                  blinded_var_mult_timer->under(runtime))
               {
               const Botan::BigInt scalar(rng(), ec_group.get_p_bits());

               const Botan::PointGFp r1 = mult_timer->run([&]() { return base_point * scalar; });

               const Botan::PointGFp r2 = blinded_mult_timer->run(
                  [&]() { return ec_group.blinded_base_point_multiply(scalar, rng(), ws); });

               const Botan::PointGFp r3 = blinded_var_mult_timer->run(
                  [&]() { return ec_group.blinded_var_point_multiply(base_point, scalar, rng(), ws); });

               BOTAN_ASSERT_EQUAL(r1, r2, "Same point computed by Montgomery and comb");
               BOTAN_ASSERT_EQUAL(r1, r3, "Same point computed by Montgomery and window");
               }

            record_result(mult_timer);
            record_result(blinded_mult_timer);
            record_result(blinded_var_mult_timer);
            }
         }

      void bench_os2ecp(const std::vector<std::string>& groups, const std::chrono::milliseconds runtime)
         {
         std::unique_ptr<Timer> uncmp_timer = make_timer("OS2ECP uncompressed");
         std::unique_ptr<Timer> cmp_timer = make_timer("OS2ECP compressed");

         for(std::string group_name : groups)
            {
            const Botan::EC_Group ec_group(group_name);

            while(uncmp_timer->under(runtime) && cmp_timer->under(runtime))
               {
               const Botan::BigInt k(rng(), 256);
               const Botan::PointGFp p = ec_group.get_base_point() * k;
               const std::vector<uint8_t> os_cmp = p.encode(Botan::PointGFp::COMPRESSED);
               const std::vector<uint8_t> os_uncmp = p.encode(Botan::PointGFp::UNCOMPRESSED);

               uncmp_timer->run([&]() { ec_group.OS2ECP(os_uncmp); });
               cmp_timer->run([&]() { ec_group.OS2ECP(os_cmp); });
               }

            record_result(uncmp_timer);
            record_result(cmp_timer);
            }
         }

#endif

#if defined(BOTAN_HAS_FPE_FE1)

      void bench_fpe_fe1(const std::chrono::milliseconds runtime)
         {
         const Botan::BigInt n = 1000000000000000;

         std::unique_ptr<Timer> enc_timer = make_timer("FPE_FE1 encrypt");
         std::unique_ptr<Timer> dec_timer = make_timer("FPE_FE1 decrypt");

         const Botan::SymmetricKey key(rng(), 32);
         const std::vector<uint8_t> tweak(8); // 8 zeros

         Botan::BigInt x = 1;

         Botan::FPE_FE1 fpe_fe1(n);
         fpe_fe1.set_key(key);

         while(enc_timer->under(runtime))
            {
            enc_timer->start();
            x = fpe_fe1.encrypt(x, tweak.data(), tweak.size());
            enc_timer->stop();
            }

         for(size_t i = 0; i != enc_timer->events(); ++i)
            {
            dec_timer->start();
            x = fpe_fe1.decrypt(x, tweak.data(), tweak.size());
            dec_timer->stop();
            }

         BOTAN_ASSERT(x == 1, "FPE works");

         record_result(enc_timer);
         record_result(dec_timer);
         }
#endif

#if defined(BOTAN_HAS_RFC3394_KEYWRAP)

      void bench_rfc3394(const std::chrono::milliseconds runtime)
         {
         std::unique_ptr<Timer> wrap_timer = make_timer("RFC3394 AES-256 key wrap");
         std::unique_ptr<Timer> unwrap_timer = make_timer("RFC3394 AES-256 key unwrap");

         const Botan::SymmetricKey kek(rng(), 32);
         Botan::secure_vector<uint8_t> key(64, 0);

         while(wrap_timer->under(runtime))
            {
            wrap_timer->start();
            key = Botan::rfc3394_keywrap(key, kek);
            wrap_timer->stop();

            unwrap_timer->start();
            key = Botan::rfc3394_keyunwrap(key, kek);
            unwrap_timer->stop();

            key[0] += 1;
            }

         record_result(wrap_timer);
         record_result(unwrap_timer);
         }
#endif

#if defined(BOTAN_HAS_BIGINT)

      void bench_mp_mul(const std::chrono::milliseconds runtime)
         {
         std::chrono::milliseconds runtime_per_size = runtime;
         for(size_t bits : { 256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096 })
            {
            std::unique_ptr<Timer> mul_timer = make_timer("BigInt mul " + std::to_string(bits));
            std::unique_ptr<Timer> sqr_timer = make_timer("BigInt sqr " + std::to_string(bits));

            const Botan::BigInt y(rng(), bits);
            Botan::secure_vector<Botan::word> ws;

            while(mul_timer->under(runtime_per_size))
               {
               Botan::BigInt x(rng(), bits);

               sqr_timer->start();
               x.square(ws);
               sqr_timer->stop();

               x.mask_bits(bits);

               mul_timer->start();
               x.mul(y, ws);
               mul_timer->stop();
               }

            record_result(mul_timer);
            record_result(sqr_timer);
            }

         }

      void bench_mp_div(const std::chrono::milliseconds runtime)
         {
         std::chrono::milliseconds runtime_per_size = runtime;

         for(size_t n_bits : { 256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096 })
            {
            const size_t q_bits = n_bits / 2;
            const std::string bit_descr = std::to_string(n_bits) + "/" + std::to_string(q_bits);

            std::unique_ptr<Timer> div_timer = make_timer("BigInt div " + bit_descr);
            std::unique_ptr<Timer> ct_div_timer = make_timer("BigInt ct_div " + bit_descr);

            Botan::BigInt y;
            Botan::BigInt x;
            Botan::secure_vector<Botan::word> ws;

            Botan::BigInt q1, r1, q2, r2;

            while(ct_div_timer->under(runtime_per_size))
               {
               x.randomize(rng(), n_bits);
               y.randomize(rng(), q_bits);

               div_timer->start();
               Botan::vartime_divide(x, y, q1, r1);
               div_timer->stop();

               ct_div_timer->start();
               Botan::ct_divide(x, y, q2, r2);
               ct_div_timer->stop();

               BOTAN_ASSERT_EQUAL(q1, q2, "Quotient ok");
               BOTAN_ASSERT_EQUAL(r1, r2, "Remainder ok");
               }

            record_result(div_timer);
            record_result(ct_div_timer);
            }
         }

      void bench_mp_div10(const std::chrono::milliseconds runtime)
         {
         std::chrono::milliseconds runtime_per_size = runtime;

         for(size_t n_bits : { 256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096 })
            {
            const std::string bit_descr = std::to_string(n_bits) + "/10";

            std::unique_ptr<Timer> div_timer = make_timer("BigInt div " + bit_descr);
            std::unique_ptr<Timer> ct_div_timer = make_timer("BigInt ct_div " + bit_descr);

            Botan::BigInt x;
            Botan::secure_vector<Botan::word> ws;

            const Botan::BigInt ten(10);
            Botan::BigInt q1, r1, q2;
            uint8_t r2;

            while(ct_div_timer->under(runtime_per_size))
               {
               x.randomize(rng(), n_bits);

               div_timer->start();
               Botan::vartime_divide(x, ten, q1, r1);
               div_timer->stop();

               ct_div_timer->start();
               Botan::ct_divide_u8(x, 10, q2, r2);
               ct_div_timer->stop();

               BOTAN_ASSERT_EQUAL(q1, q2, "Quotient ok");
               BOTAN_ASSERT_EQUAL(r1, r2, "Remainder ok");
               }

            record_result(div_timer);
            record_result(ct_div_timer);
            }
         }

#endif

#if defined(BOTAN_HAS_DL_GROUP)

      void bench_modexp(const std::chrono::milliseconds runtime)
         {
         for(size_t group_bits : { 1024, 1536, 2048, 3072, 4096 })
            {
            const std::string group_bits_str = std::to_string(group_bits);
            const Botan::DL_Group group("modp/srp/" + group_bits_str);

            const size_t e_bits = Botan::dl_exponent_size(group_bits);
            const size_t f_bits = group_bits - 1;

            const Botan::BigInt random_e(rng(), e_bits);
            const Botan::BigInt random_f(rng(), f_bits);

            std::unique_ptr<Timer> e_timer = make_timer(group_bits_str + " short exponent");
            std::unique_ptr<Timer> f_timer = make_timer(group_bits_str + "  full exponent");

            while(f_timer->under(runtime))
               {
               e_timer->run([&]() { group.power_g_p(random_e); });
               f_timer->run([&]() { group.power_g_p(random_f); });
               }

            record_result(e_timer);
            record_result(f_timer);
            }
         }
#endif

#if defined(BOTAN_HAS_NUMBERTHEORY)
      void bench_nistp_redc(const std::chrono::milliseconds runtime)
         {
         Botan::secure_vector<Botan::word> ws;

         std::unique_ptr<Timer> p192_timer = make_timer("P-192 redc");
         Botan::BigInt r192(rng(), 192*2 - 1);
         while(p192_timer->under(runtime))
            {
            Botan::BigInt r = r192;
            p192_timer->run([&]() { Botan::redc_p192(r, ws); });
            r192 += 1;
            }
         record_result(p192_timer);

         std::unique_ptr<Timer> p224_timer = make_timer("P-224 redc");
         Botan::BigInt r224(rng(), 224*2 - 1);
         while(p224_timer->under(runtime))
            {
            Botan::BigInt r = r224;
            p224_timer->run([&]() { Botan::redc_p224(r, ws); });
            r224 += 1;
            }
         record_result(p224_timer);

         std::unique_ptr<Timer> p256_timer = make_timer("P-256 redc");
         Botan::BigInt r256(rng(), 256*2 - 1);
         while(p256_timer->under(runtime))
            {
            Botan::BigInt r = r256;
            p256_timer->run([&]() { Botan::redc_p256(r, ws); });
            r256 += 1;
            }
         record_result(p256_timer);

         std::unique_ptr<Timer> p384_timer = make_timer("P-384 redc");
         Botan::BigInt r384(rng(), 384*2 - 1);
         while(p384_timer->under(runtime))
            {
            Botan::BigInt r = r384;
            p384_timer->run([&]() { Botan::redc_p384(r384, ws); });
            r384 += 1;
            }
         record_result(p384_timer);

         std::unique_ptr<Timer> p521_timer = make_timer("P-521 redc");
         Botan::BigInt r521(rng(), 521*2 - 1);
         while(p521_timer->under(runtime))
            {
            Botan::BigInt r = r521;
            p521_timer->run([&]() { Botan::redc_p521(r521, ws); });
            r521 += 1;
            }
         record_result(p521_timer);
         }

      void bench_bn_redc(const std::chrono::milliseconds runtime)
         {
         for(size_t bitsize : { 512, 1024, 2048, 4096 })
            {
            Botan::BigInt p(rng(), bitsize);

            std::string bit_str = std::to_string(bitsize);
            std::unique_ptr<Timer> barrett_timer = make_timer("Barrett-" + bit_str);
            std::unique_ptr<Timer> schoolbook_timer = make_timer("Schoolbook-" + bit_str);

            Botan::Modular_Reducer mod_p(p);

            while(schoolbook_timer->under(runtime))
               {
               const Botan::BigInt x(rng(), p.bits() * 2 - 2);

               const Botan::BigInt r1 = barrett_timer->run(
                  [&] { return mod_p.reduce(x); });
               const Botan::BigInt r2 = schoolbook_timer->run(
                  [&] { return x % p; });

               BOTAN_ASSERT(r1 == r2, "Computed different results");
               }

            record_result(barrett_timer);
            record_result(schoolbook_timer);
            }
         }

      void bench_inverse_mod(const std::chrono::milliseconds runtime)
         {
         for(size_t bits : { 256, 384, 512, 1024, 2048 })
            {
            const std::string bit_str = std::to_string(bits);

            std::unique_ptr<Timer> timer = make_timer("inverse_mod-" + bit_str);

            while(timer->under(runtime))
               {
               const Botan::BigInt x(rng(), bits - 1);
               Botan::BigInt mod(rng(), bits);

               const Botan::BigInt x_inv = timer->run(
                  [&] { return Botan::inverse_mod(x, mod); });

               if(x_inv == 0)
                  {
                  const Botan::BigInt g = gcd(x, mod);
                  BOTAN_ASSERT(g != 1, "Inversion only fails if gcd(x, mod) > 1");
                  }
               else
                  {
                  const Botan::BigInt check = (x_inv*x) % mod;
                  BOTAN_ASSERT_EQUAL(check, 1, "Const time inversion correct");
                  }
               }

            record_result(timer);
            }
         }

      void bench_primality_tests(const std::chrono::milliseconds runtime)
         {
         for(size_t bits : { 256, 512, 1024 })
            {
            std::unique_ptr<Timer> mr_timer = make_timer("Miller-Rabin-" + std::to_string(bits));
            std::unique_ptr<Timer> bpsw_timer = make_timer("Bailie-PSW-" + std::to_string(bits));
            std::unique_ptr<Timer> lucas_timer = make_timer("Lucas-" + std::to_string(bits));

            Botan::BigInt n = Botan::random_prime(rng(), bits);

            while(lucas_timer->under(runtime))
               {
               Botan::Modular_Reducer mod_n(n);

               mr_timer->run([&]() {
                  return Botan::is_miller_rabin_probable_prime(n, mod_n, rng(), 2); });

               bpsw_timer->run([&]() {
                  return Botan::is_bailie_psw_probable_prime(n, mod_n); });

               lucas_timer->run([&]() {
                  return Botan::is_lucas_probable_prime(n, mod_n); });

               n += 2;
               }

            record_result(mr_timer);
            record_result(bpsw_timer);
            record_result(lucas_timer);
            }
         }

      void bench_random_prime(const std::chrono::milliseconds runtime)
         {
         const size_t coprime = 65537; // simulates RSA key gen

         for(size_t bits : { 256, 384, 512, 768, 1024, 1536 })
            {
            std::unique_ptr<Timer> genprime_timer = make_timer("random_prime " + std::to_string(bits));
            std::unique_ptr<Timer> gensafe_timer = make_timer("random_safe_prime " + std::to_string(bits));
            std::unique_ptr<Timer> is_prime_timer = make_timer("is_prime " + std::to_string(bits));

            while(gensafe_timer->under(runtime))
               {
               const Botan::BigInt p = genprime_timer->run([&]
                  {
                  return Botan::random_prime(rng(), bits, coprime);
                  });

               if(!is_prime_timer->run([&] { return Botan::is_prime(p, rng(), 64, true); }))
                  {
                  error_output() << "Generated prime " << p << " which failed a primality test";
                  }

               const Botan::BigInt sg = gensafe_timer->run([&]
                  {
                  return Botan::random_safe_prime(rng(), bits);
                  });

               if(!is_prime_timer->run([&] { return Botan::is_prime(sg, rng(), 64, true); }))
                  {
                  error_output() << "Generated safe prime " << sg << " which failed a primality test";
                  }

               if(!is_prime_timer->run([&] { return Botan::is_prime(sg / 2, rng(), 64, true); }))
                  {
                  error_output() << "Generated prime " << sg/2 << " which failed a primality test";
                  }

               // Now test p+2, p+4, ... which may or may not be prime
               for(size_t i = 2; i <= 64; i += 2)
                  {
                  is_prime_timer->run([&]() { Botan::is_prime(p + i, rng(), 64, true); });
                  }
               }

            record_result(genprime_timer);
            record_result(gensafe_timer);
            record_result(is_prime_timer);
            }
         }
#endif

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO)
      void bench_pk_enc(
         const Botan::Private_Key& key,
         const std::string& nm,
         const std::string& provider,
         const std::string& padding,
         std::chrono::milliseconds msec)
         {
         std::vector<uint8_t> plaintext, ciphertext;

         Botan::PK_Encryptor_EME enc(key, rng(), padding, provider);
         Botan::PK_Decryptor_EME dec(key, rng(), padding, provider);

         std::unique_ptr<Timer> enc_timer = make_timer(nm + " " + padding, provider, "encrypt");
         std::unique_ptr<Timer> dec_timer = make_timer(nm + " " + padding, provider, "decrypt");

         while(enc_timer->under(msec) || dec_timer->under(msec))
            {
            // Generate a new random ciphertext to decrypt
            if(ciphertext.empty() || enc_timer->under(msec))
               {
               rng().random_vec(plaintext, enc.maximum_input_size());
               ciphertext = enc_timer->run([&]() { return enc.encrypt(plaintext, rng()); });
               }

            if(dec_timer->under(msec))
               {
               const auto dec_pt = dec_timer->run([&]() { return dec.decrypt(ciphertext); });

               if(!(dec_pt == plaintext)) // sanity check
                  {
                  error_output() << "Bad roundtrip in PK encrypt/decrypt bench\n";
                  }
               }
            }

         record_result(enc_timer);
         record_result(dec_timer);
         }

      void bench_pk_ka(const std::string& algo,
                       const std::string& nm,
                       const std::string& params,
                       const std::string& provider,
                       std::chrono::milliseconds msec)
         {
         const std::string kdf = "KDF2(SHA-256)"; // arbitrary choice

         std::unique_ptr<Timer> keygen_timer = make_timer(nm, provider, "keygen");

         std::unique_ptr<Botan::Private_Key> key1(keygen_timer->run([&]
            {
            return Botan::create_private_key(algo, rng(), params);
            }));
         std::unique_ptr<Botan::Private_Key> key2(keygen_timer->run([&]
            {
            return Botan::create_private_key(algo, rng(), params);
            }));

         record_result(keygen_timer);

         const Botan::PK_Key_Agreement_Key& ka_key1 = dynamic_cast<const Botan::PK_Key_Agreement_Key&>(*key1);
         const Botan::PK_Key_Agreement_Key& ka_key2 = dynamic_cast<const Botan::PK_Key_Agreement_Key&>(*key2);

         Botan::PK_Key_Agreement ka1(ka_key1, rng(), kdf, provider);
         Botan::PK_Key_Agreement ka2(ka_key2, rng(), kdf, provider);

         const std::vector<uint8_t> ka1_pub = ka_key1.public_value();
         const std::vector<uint8_t> ka2_pub = ka_key2.public_value();

         std::unique_ptr<Timer> ka_timer = make_timer(nm, provider, "key agreements");

         while(ka_timer->under(msec))
            {
            Botan::SymmetricKey symkey1 = ka_timer->run([&]() { return ka1.derive_key(32, ka2_pub); });
            Botan::SymmetricKey symkey2 = ka_timer->run([&]() { return ka2.derive_key(32, ka1_pub); });

            if(symkey1 != symkey2)
               {
               error_output() << "Key agreement mismatch in PK bench\n";
               }
            }

         record_result(ka_timer);
         }

      void bench_pk_kem(const Botan::Private_Key& key,
                        const std::string& nm,
                        const std::string& provider,
                        const std::string& kdf,
                        std::chrono::milliseconds msec)
         {
         Botan::PK_KEM_Decryptor dec(key, rng(), kdf, provider);
         Botan::PK_KEM_Encryptor enc(key, rng(), kdf, provider);

         std::unique_ptr<Timer> kem_enc_timer = make_timer(nm, provider, "KEM encrypt");
         std::unique_ptr<Timer> kem_dec_timer = make_timer(nm, provider, "KEM decrypt");

         while(kem_enc_timer->under(msec) && kem_dec_timer->under(msec))
            {
            Botan::secure_vector<uint8_t> encap_key, enc_shared_key;
            Botan::secure_vector<uint8_t> salt = rng().random_vec(16);

            kem_enc_timer->start();
            enc.encrypt(encap_key, enc_shared_key, 64, rng(), salt);
            kem_enc_timer->stop();

            kem_dec_timer->start();
            Botan::secure_vector<uint8_t> dec_shared_key = dec.decrypt(encap_key, 64, salt);
            kem_dec_timer->stop();

            if(enc_shared_key != dec_shared_key)
               {
               error_output() << "KEM mismatch in PK bench\n";
               }
            }

         record_result(kem_enc_timer);
         record_result(kem_dec_timer);
         }

      void bench_pk_sig_ecc(const std::string& algo,
                            const std::string& emsa,
                            const std::string& provider,
                            const std::vector<std::string>& params,
                            std::chrono::milliseconds msec)
         {
         for(std::string grp : params)
            {
            const std::string nm = grp.empty() ? algo : (algo + "-" + grp);

            std::unique_ptr<Timer> keygen_timer = make_timer(nm, provider, "keygen");

            std::unique_ptr<Botan::Private_Key> key(keygen_timer->run([&]
               {
               return Botan::create_private_key(algo, rng(), grp);
               }));

            record_result(keygen_timer);
            bench_pk_sig(*key, nm, provider, emsa, msec);
            }
         }

      size_t bench_pk_sig(const Botan::Private_Key& key,
                          const std::string& nm,
                          const std::string& provider,
                          const std::string& padding,
                          std::chrono::milliseconds msec)
         {
         std::vector<uint8_t> message, signature, bad_signature;

         Botan::PK_Signer   sig(key, rng(), padding, Botan::IEEE_1363, provider);
         Botan::PK_Verifier ver(key, padding, Botan::IEEE_1363, provider);

         std::unique_ptr<Timer> sig_timer = make_timer(nm + " " + padding, provider, "sign");
         std::unique_ptr<Timer> ver_timer = make_timer(nm + " " + padding, provider, "verify");

         size_t invalid_sigs = 0;

         while(ver_timer->under(msec) || sig_timer->under(msec))
            {
            if(signature.empty() || sig_timer->under(msec))
               {
               /*
               Length here is kind of arbitrary, but 48 bytes fits into a single
               hash block so minimizes hashing overhead versus the PK op itself.
               */
               rng().random_vec(message, 48);

               signature = sig_timer->run([&]() { return sig.sign_message(message, rng()); });

               bad_signature = signature;
               bad_signature[rng().next_byte() % bad_signature.size()] ^= rng().next_nonzero_byte();
               }

            if(ver_timer->under(msec))
               {
               const bool verified = ver_timer->run([&]
                  {
                  return ver.verify_message(message, signature);
                  });

               if(!verified)
                  {
                  invalid_sigs += 1;
                  }

               const bool verified_bad = ver_timer->run([&]
                  {
                  return ver.verify_message(message, bad_signature);
                  });

               if(verified_bad)
                  {
                  error_output() << "Bad signature accepted in PK signature bench\n";
                  }
               }
            }

         if(invalid_sigs > 0)
            error_output() << invalid_sigs << " generated signatures rejected in PK signature bench\n";

         const size_t events = static_cast<size_t>(std::min(sig_timer->events(), ver_timer->events()));

         record_result(sig_timer);
         record_result(ver_timer);

         return events;
         }
#endif

#if defined(BOTAN_HAS_RSA)
      void bench_rsa_keygen(const std::string& provider,
                            std::chrono::milliseconds msec)
         {
         for(size_t keylen : { 1024, 2048, 3072, 4096 })
            {
            const std::string nm = "RSA-" + std::to_string(keylen);
            std::unique_ptr<Timer> keygen_timer = make_timer(nm, provider, "keygen");

            while(keygen_timer->under(msec))
               {
               std::unique_ptr<Botan::Private_Key> key(keygen_timer->run([&] {
                  return Botan::create_private_key("RSA", rng(), std::to_string(keylen));
                  }));

               BOTAN_ASSERT(key->check_key(rng(), true), "Key is ok");
               }

            record_result(keygen_timer);
            }
         }

      void bench_rsa(const std::string& provider,
                     std::chrono::milliseconds msec)
         {
         for(size_t keylen : { 1024, 2048, 3072, 4096 })
            {
            const std::string nm = "RSA-" + std::to_string(keylen);

            std::unique_ptr<Timer> keygen_timer = make_timer(nm, provider, "keygen");

            std::unique_ptr<Botan::Private_Key> key(keygen_timer->run([&]
               {
               return Botan::create_private_key("RSA", rng(), std::to_string(keylen));
               }));

            record_result(keygen_timer);

            // Using PKCS #1 padding so OpenSSL provider can play along
            bench_pk_sig(*key, nm, provider, "EMSA-PKCS1-v1_5(SHA-256)", msec);

            //bench_pk_sig(*key, nm, provider, "PSSR(SHA-256)", msec);
            //bench_pk_enc(*key, nm, provider, "EME-PKCS1-v1_5", msec);
            //bench_pk_enc(*key, nm, provider, "OAEP(SHA-1)", msec);
            }
         }
#endif

#if defined(BOTAN_HAS_ECDSA)
      void bench_ecdsa(const std::vector<std::string>& groups,
                       const std::string& provider,
                       std::chrono::milliseconds msec)
         {
         return bench_pk_sig_ecc("ECDSA", "EMSA1(SHA-256)", provider, groups, msec);
         }

      void bench_ecdsa_recovery(const std::vector<std::string>& groups,
                                const std::string&,
                                std::chrono::milliseconds msec)
         {
         for(std::string group_name : groups)
            {
            Botan::EC_Group group(group_name);
            std::unique_ptr<Timer> recovery_timer = make_timer("ECDSA recovery " + group_name);

            while(recovery_timer->under(msec))
               {
               Botan::ECDSA_PrivateKey key(rng(), group);

               std::vector<uint8_t> message(group.get_order_bits() / 8);
               rng().randomize(message.data(), message.size());

               Botan::PK_Signer signer(key, rng(), "Raw");
               signer.update(message);
               std::vector<uint8_t> signature = signer.signature(rng());

               Botan::PK_Verifier verifier(key, "Raw", Botan::IEEE_1363, "base");
               verifier.update(message);
               BOTAN_ASSERT(verifier.check_signature(signature), "Valid signature");

               Botan::BigInt r(signature.data(), signature.size()/2);
               Botan::BigInt s(signature.data() + signature.size()/2, signature.size()/2);

               const uint8_t v = key.recovery_param(message, r, s);

               recovery_timer->run([&]() {
                  Botan::ECDSA_PublicKey pubkey(group, message, r, s, v);
                  BOTAN_ASSERT(pubkey.public_point() == key.public_point(), "Recovered public key");
                  });
               }

            record_result(recovery_timer);
            }

         }

#endif

#if defined(BOTAN_HAS_ECKCDSA)
      void bench_eckcdsa(const std::vector<std::string>& groups,
                         const std::string& provider,
                         std::chrono::milliseconds msec)
         {
         return bench_pk_sig_ecc("ECKCDSA", "EMSA1(SHA-256)", provider, groups, msec);
         }
#endif

#if defined(BOTAN_HAS_GOST_34_10_2001)
      void bench_gost_3410(const std::string& provider,
                           std::chrono::milliseconds msec)
         {
         return bench_pk_sig_ecc("GOST-34.10", "EMSA1(GOST-34.11)", provider, {"gost_256A"}, msec);
         }
#endif

#if defined(BOTAN_HAS_SM2)
      void bench_sm2(const std::vector<std::string>& groups,
                     const std::string& provider,
                     std::chrono::milliseconds msec)
         {
         return bench_pk_sig_ecc("SM2_Sig", "SM3", provider, groups, msec);
         }
#endif

#if defined(BOTAN_HAS_ECGDSA)
      void bench_ecgdsa(const std::vector<std::string>& groups,
                        const std::string& provider,
                        std::chrono::milliseconds msec)
         {
         return bench_pk_sig_ecc("ECGDSA", "EMSA1(SHA-256)", provider, groups, msec);
         }
#endif

#if defined(BOTAN_HAS_ED25519)
      void bench_ed25519(const std::string& provider,
                         std::chrono::milliseconds msec)
         {
         return bench_pk_sig_ecc("Ed25519", "Pure", provider, std::vector<std::string>{""}, msec);
         }
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
      void bench_dh(const std::string& provider,
                    std::chrono::milliseconds msec)
         {
         for(size_t bits : { 1024, 1536, 2048, 3072, 4096, 6144, 8192 })
            {
            bench_pk_ka("DH",
                        "DH-" + std::to_string(bits),
                        "modp/ietf/" + std::to_string(bits),
                        provider, msec);
            }
         }
#endif

#if defined(BOTAN_HAS_DSA)
      void bench_dsa(const std::string& provider, std::chrono::milliseconds msec)
         {
         for(size_t bits : { 1024, 2048, 3072 })
            {
            const std::string nm = "DSA-" + std::to_string(bits);

            const std::string params =
               (bits == 1024) ? "dsa/jce/1024" : ("dsa/botan/" + std::to_string(bits));

            std::unique_ptr<Timer> keygen_timer = make_timer(nm, provider, "keygen");

            std::unique_ptr<Botan::Private_Key> key(keygen_timer->run([&]
               {
               return Botan::create_private_key("DSA", rng(), params);
               }));

            record_result(keygen_timer);

            bench_pk_sig(*key, nm, provider, "EMSA1(SHA-256)", msec);
            }
         }
#endif

#if defined(BOTAN_HAS_ELGAMAL)
      void bench_elgamal(const std::string& provider, std::chrono::milliseconds msec)
         {
         for(size_t keylen : { 1024, 2048, 3072, 4096 })
            {
            const std::string nm = "ElGamal-" + std::to_string(keylen);

            const std::string params = "modp/ietf/" + std::to_string(keylen);

            std::unique_ptr<Timer> keygen_timer = make_timer(nm, provider, "keygen");

            std::unique_ptr<Botan::Private_Key> key(keygen_timer->run([&]
               {
               return Botan::create_private_key("ElGamal", rng(), params);
               }));

            record_result(keygen_timer);

            bench_pk_enc(*key, nm, provider, "EME-PKCS1-v1_5", msec);
            }
         }
#endif

#if defined(BOTAN_HAS_ECDH)
      void bench_ecdh(const std::vector<std::string>& groups,
                      const std::string& provider,
                      std::chrono::milliseconds msec)
         {
         for(std::string grp : groups)
            {
            bench_pk_ka("ECDH", "ECDH-" + grp, grp, provider, msec);
            }
         }
#endif

#if defined(BOTAN_HAS_CURVE_25519)
      void bench_curve25519(const std::string& provider,
                            std::chrono::milliseconds msec)
         {
         bench_pk_ka("Curve25519", "Curve25519", "", provider, msec);
         }
#endif

#if defined(BOTAN_HAS_MCELIECE)
      void bench_mceliece(const std::string& provider,
                          std::chrono::milliseconds msec)
         {
         /*
         SL=80 n=1632 t=33 - 59 KB pubkey 140 KB privkey
         SL=107 n=2480 t=45 - 128 KB pubkey 300 KB privkey
         SL=128 n=2960 t=57 - 195 KB pubkey 459 KB privkey
         SL=147 n=3408 t=67 - 265 KB pubkey 622 KB privkey
         SL=191 n=4624 t=95 - 516 KB pubkey 1234 KB privkey
         SL=256 n=6624 t=115 - 942 KB pubkey 2184 KB privkey
         */

         const std::vector<std::pair<size_t, size_t>> mce_params =
            {
               { 2480, 45 },
               { 2960, 57 },
               { 3408, 67 },
               { 4624, 95 },
               { 6624, 115 }
            };

         for(auto params : mce_params)
            {
            size_t n = params.first;
            size_t t = params.second;

            const std::string nm = "McEliece-" + std::to_string(n) + "," + std::to_string(t) +
                                   " (WF=" + std::to_string(Botan::mceliece_work_factor(n, t)) + ")";

            std::unique_ptr<Timer> keygen_timer = make_timer(nm, provider, "keygen");

            std::unique_ptr<Botan::Private_Key> key(keygen_timer->run([&]
               {
               return new Botan::McEliece_PrivateKey(rng(), n, t);
               }));

            record_result(keygen_timer);
            bench_pk_kem(*key, nm, provider, "KDF2(SHA-256)", msec);
            }
         }
#endif

#if defined(BOTAN_HAS_XMSS_RFC8391)
      void bench_xmss(const std::string& provider,
                      std::chrono::milliseconds msec)
         {
         /*
         We only test H10 signatures here since already they are quite slow (a
         few seconds per signature). On a fast machine, H16 signatures take 1-2
         minutes to generate and H20 signatures take 5-10 minutes to generate
         */
         std::vector<std::string> xmss_params
            {
            "XMSS-SHA2_10_256",
            "XMSS-SHAKE_10_256",
            "XMSS-SHA2_10_512",
            "XMSS-SHAKE_10_512",
            };

         for(std::string params : xmss_params)
            {
            std::unique_ptr<Timer> keygen_timer = make_timer(params, provider, "keygen");

            std::unique_ptr<Botan::Private_Key> key(keygen_timer->run([&]
               {
               return Botan::create_private_key("XMSS", rng(), params);
               }));

            record_result(keygen_timer);
            if(bench_pk_sig(*key, params, provider, "", msec) == 1)
               break;
            }
         }
#endif

#if defined(BOTAN_HAS_POLY_DBL)
      void bench_poly_dbl(std::chrono::milliseconds msec)
         {
         for(size_t sz : { 8, 16, 24, 32, 64, 128 })
            {
            std::unique_ptr<Timer> be_timer = make_timer("poly_dbl_be_" + std::to_string(sz));
            std::unique_ptr<Timer> le_timer = make_timer("poly_dbl_le_" + std::to_string(sz));

            std::vector<uint8_t> buf(sz);
            rng().randomize(buf.data(), sz);

            be_timer->run_until_elapsed(msec, [&]() { Botan::poly_double_n(buf.data(), buf.data(), sz); });
            le_timer->run_until_elapsed(msec, [&]() { Botan::poly_double_n_le(buf.data(), buf.data(), sz); });

            record_result(be_timer);
            record_result(le_timer);
            }
         }
#endif

#if defined(BOTAN_HAS_BCRYPT)

      void bench_bcrypt()
         {
         const std::string password = "not a very good password";

         for(uint8_t work_factor = 4; work_factor <= 14; ++work_factor)
            {
            std::unique_ptr<Timer> timer = make_timer("bcrypt wf=" + std::to_string(work_factor));

            timer->run([&] {
               Botan::generate_bcrypt(password, rng(), work_factor);
                  });

            record_result(timer);
            }
         }
#endif

#if defined(BOTAN_HAS_PASSHASH9)

      void bench_passhash9()
         {
         const std::string password = "not a very good password";

         for(uint8_t alg = 0; alg <= 4; ++alg)
            {
            if(Botan::is_passhash9_alg_supported(alg) == false)
               continue;

            for(auto work_factor : { 10, 15 })
               {
               std::unique_ptr<Timer> timer = make_timer("passhash9 alg=" + std::to_string(alg) +
                                                         " wf=" + std::to_string(work_factor));

               timer->run([&] {
                  Botan::generate_passhash9(password, rng(), static_cast<uint8_t>(work_factor), alg);
                  });

               record_result(timer);
               }
            }
         }
#endif

#if defined(BOTAN_HAS_SCRYPT)

      void bench_scrypt(const std::string& /*provider*/,
                        std::chrono::milliseconds msec)
         {

         for(size_t N : { 8192, 16384, 32768, 65536 })
            {
            for(size_t r : { 1, 8, 16 })
               {
               for(size_t p : { 1, 4 })
                  {
                  std::unique_ptr<Timer> scrypt_timer = make_timer(
                     "scrypt-" + std::to_string(N) + "-" +
                     std::to_string(r) + "-" + std::to_string(p) +
                     " (" + std::to_string(Botan::scrypt_memory_usage(N, r, p) / (1024*1024)) + " MiB)");

                  uint8_t out[64];
                  uint8_t salt[8];
                  rng().randomize(salt, sizeof(salt));

                  while(scrypt_timer->under(msec))
                     {
                     scrypt_timer->run([&] {
                        Botan::scrypt(out, sizeof(out), "password",
                                      salt, sizeof(salt), N, r, p);
                        });
                     }

                  record_result(scrypt_timer);

                  if(scrypt_timer->events() == 1)
                     break;
                  }
               }
            }

         }

#endif

#if defined(BOTAN_HAS_ARGON2)

      void bench_argon2(const std::string& /*provider*/,
                        std::chrono::milliseconds msec)
         {
         const uint8_t mode = 2; // Argon2id

         for(size_t M : { 8*1024, 64*1024, 256*1024 })
            {
            for(size_t t : { 1, 2, 4 })
               {
               for(size_t p : { 1 })
                  {
                  std::unique_ptr<Timer> timer = make_timer(
                     "Argon2id M=" + std::to_string(M) + " t=" + std::to_string(t) + " p=" + std::to_string(p));

                  uint8_t out[64];
                  uint8_t salt[16];
                  rng().randomize(salt, sizeof(salt));

                  while(timer->under(msec))
                     {
                     timer->run([&] {
                                Botan::argon2(out, sizeof(out), "password", 8,
                                              salt, sizeof(salt), nullptr, 0, nullptr, 0,
                                              mode, p, M, t);
                                });
                     }

                  record_result(timer);
                  }
               }
            }
         }

#endif

#if defined(BOTAN_HAS_NEWHOPE) && defined(BOTAN_HAS_CHACHA_RNG)
      void bench_newhope(const std::string& /*provider*/,
                         std::chrono::milliseconds msec)
         {
         const std::string nm = "NEWHOPE";

         std::unique_ptr<Timer> keygen_timer = make_timer(nm, "", "keygen");
         std::unique_ptr<Timer> shareda_timer = make_timer(nm, "", "shareda");
         std::unique_ptr<Timer> sharedb_timer = make_timer(nm, "", "sharedb");

         Botan::ChaCha_RNG nh_rng(Botan::secure_vector<uint8_t>(32));

         while(sharedb_timer->under(msec))
            {
            std::vector<uint8_t> send_a(Botan::NEWHOPE_SENDABYTES), send_b(Botan::NEWHOPE_SENDBBYTES);
            std::vector<uint8_t> shared_a(32), shared_b(32);

            Botan::newhope_poly sk_a;

            keygen_timer->start();
            Botan::newhope_keygen(send_a.data(), &sk_a, nh_rng);
            keygen_timer->stop();

            sharedb_timer->start();
            Botan::newhope_sharedb(shared_b.data(), send_b.data(), send_a.data(), nh_rng);
            sharedb_timer->stop();

            shareda_timer->start();
            Botan::newhope_shareda(shared_a.data(), &sk_a, send_b.data());
            shareda_timer->stop();

            BOTAN_ASSERT(shared_a == shared_b, "Same derived key");
            }

         record_result(keygen_timer);
         record_result(shareda_timer);
         record_result(sharedb_timer);
         }
#endif

   };

BOTAN_REGISTER_COMMAND("speed", Speed);

}
