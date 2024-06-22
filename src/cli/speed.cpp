/*
* (C) 2009,2010,2014,2015,2017,2018 Jack Lloyd
* (C) 2015 Simon Warta (Kullo GmbH)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "../tests/test_rng.h"  // FIXME
#include "cli.h"

#include <algorithm>
#include <chrono>
#include <functional>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>

// Always available:
#include <botan/entropy_src.h>
#include <botan/version.h>
#include <botan/internal/cpuid.h>
#include <botan/internal/fmt.h>
#include <botan/internal/os_utils.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/timer.h>

#if defined(BOTAN_HAS_BIGINT)
   #include <botan/bigint.h>
   #include <botan/internal/divide.h>
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

#if defined(BOTAN_HAS_XOF)
   #include <botan/xof.h>
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
   #include <botan/pk_algs.h>
   #include <botan/pkcs8.h>
   #include <botan/pubkey.h>
   #include <botan/x509_key.h>
   #include <botan/internal/workfactor.h>
#endif

#if defined(BOTAN_HAS_NUMBERTHEORY)
   #include <botan/numthry.h>
   #include <botan/reducer.h>
   #include <botan/internal/curve_nistp.h>
   #include <botan/internal/primality.h>
#endif

#if defined(BOTAN_HAS_ECC_GROUP)
   #include <botan/ec_group.h>
#endif

#if defined(BOTAN_HAS_PCURVES)
   #include <botan/internal/pcurves.h>
#endif

#if defined(BOTAN_HAS_DL_GROUP)
   #include <botan/dl_group.h>
#endif

#if defined(BOTAN_HAS_MCELIECE)
   #include <botan/mceliece.h>
#endif

#if defined(BOTAN_HAS_KYBER) || defined(BOTAN_HAS_KYBER_90S)
   #include <botan/kyber.h>
#endif

#if defined(BOTAN_HAS_DILITHIUM) || defined(BOTAN_HAS_DILITHIUM_AES)
   #include <botan/dilithium.h>
#endif

#if defined(BOTAN_HAS_HSS_LMS)
   #include <botan/hss_lms.h>
#endif

#if defined(BOTAN_HAS_SPHINCS_PLUS_WITH_SHA2) || defined(BOTAN_HAS_SPHINCS_PLUS_WITH_SHAKE)
   #include <botan/sphincsplus.h>
#endif

#if defined(BOTAN_HAS_FRODOKEM)
   #include <botan/frodokem.h>
#endif

#if defined(BOTAN_HAS_ECDSA)
   #include <botan/ecdsa.h>
#endif

#if defined(BOTAN_HAS_BCRYPT)
   #include <botan/bcrypt.h>
#endif

#if defined(BOTAN_HAS_PASSHASH9)
   #include <botan/passhash9.h>
#endif

#if defined(BOTAN_HAS_PASSWORD_HASHING)
   #include <botan/pwdhash.h>
#endif

#if defined(BOTAN_HAS_ZFEC)
   #include <botan/zfec.h>
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
            "McEliece",
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

         for(const auto& algo : algos) {
            using namespace std::placeholders;

            if(false) {
               // Since everything might be disabled, need a block to else if from
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
#if defined(BOTAN_HAS_RSA)
            else if(algo == "RSA") {
               bench_rsa(provider, msec);
            } else if(algo == "RSA_keygen") {
               bench_rsa_keygen(provider, msec);
            }
#endif

#if defined(BOTAN_HAS_PCURVES)
            else if(algo == "ECDSA-pcurves") {
               bench_pcurve_ecdsa(ecc_groups, msec);
            } else if(algo == "ECDH-pcurves") {
               bench_pcurve_ecdh(ecc_groups, msec);
            } else if(algo == "pcurves") {
               bench_pcurves(ecc_groups, msec);
            }
#endif

#if defined(BOTAN_HAS_ECDSA)
            else if(algo == "ECDSA") {
               bench_ecdsa(ecc_groups, provider, msec);
            } else if(algo == "ecdsa_recovery") {
               bench_ecdsa_recovery(ecc_groups, provider, msec);
            }
#endif
#if defined(BOTAN_HAS_SM2)
            else if(algo == "SM2") {
               bench_sm2(ecc_groups, provider, msec);
            }
#endif
#if defined(BOTAN_HAS_ECKCDSA)
            else if(algo == "ECKCDSA") {
               bench_eckcdsa(ecc_groups, provider, msec);
            }
#endif
#if defined(BOTAN_HAS_GOST_34_10_2001)
            else if(algo == "GOST-34.10") {
               bench_gost_3410(provider, msec);
            }
#endif
#if defined(BOTAN_HAS_ECGDSA)
            else if(algo == "ECGDSA") {
               bench_ecgdsa(ecc_groups, provider, msec);
            }
#endif
#if defined(BOTAN_HAS_ED25519)
            else if(algo == "Ed25519") {
               bench_ed25519(provider, msec);
            }
#endif
#if defined(BOTAN_HAS_ED448)
            else if(algo == "Ed448") {
               bench_ed448(provider, msec);
            }
#endif
#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
            else if(algo == "DH") {
               bench_dh(provider, msec);
            }
#endif
#if defined(BOTAN_HAS_DSA)
            else if(algo == "DSA") {
               bench_dsa(provider, msec);
            }
#endif
#if defined(BOTAN_HAS_ELGAMAL)
            else if(algo == "ElGamal") {
               bench_elgamal(provider, msec);
            }
#endif
#if defined(BOTAN_HAS_ECDH)
            else if(algo == "ECDH") {
               bench_ecdh(ecc_groups, provider, msec);
            }
#endif
#if defined(BOTAN_HAS_X25519)
            else if(algo == "X25519") {
               bench_x25519(provider, msec);
            }
#endif
#if defined(BOTAN_HAS_X448)
            else if(algo == "X448") {
               bench_x448(provider, msec);
            }
#endif
#if defined(BOTAN_HAS_MCELIECE)
            else if(algo == "McEliece") {
               bench_mceliece(provider, msec);
            }
#endif
#if defined(BOTAN_HAS_KYBER) || defined(BOTAN_HAS_KYBER_90S)
            else if(algo == "Kyber") {
               bench_kyber(provider, msec);
            }
#endif
#if defined(BOTAN_HAS_DILITHIUM) || defined(BOTAN_HAS_DILITHIUM_AES)
            else if(algo == "Dilithium") {
               bench_dilithium(provider, msec);
            }
#endif
#if defined(BOTAN_HAS_XMSS_RFC8391)
            else if(algo == "XMSS") {
               bench_xmss(provider, msec);
            }
#endif
#if defined(BOTAN_HAS_HSS_LMS)
            else if(algo == "HSS-LMS") {
               bench_hss_lms(provider, msec);
            }
#endif
#if defined(BOTAN_HAS_SPHINCS_PLUS_WITH_SHA2) || defined(BOTAN_HAS_SPHINCS_PLUS_WITH_SHAKE)
            else if(algo == "SPHINCS+") {
               bench_sphincs_plus(provider, msec);
            }
#endif
#if defined(BOTAN_HAS_FRODOKEM)
            else if(algo == "FrodoKEM") {
               bench_frodokem(provider, msec);
            }
#endif
#if defined(BOTAN_HAS_SCRYPT)
            else if(algo == "scrypt") {
               bench_scrypt(provider, msec);
            }
#endif
#if defined(BOTAN_HAS_ARGON2)
            else if(algo == "argon2") {
               bench_argon2(provider, msec);
            }
#endif
#if defined(BOTAN_HAS_BCRYPT)
            else if(algo == "bcrypt") {
               bench_bcrypt();
            }
#endif
#if defined(BOTAN_HAS_PASSHASH9)
            else if(algo == "passhash9") {
               bench_passhash9();
            }
#endif
#if defined(BOTAN_HAS_ZFEC)
            else if(algo == "zfec") {
               bench_zfec(msec);
            }
#endif
#if defined(BOTAN_HAS_POLY_DBL)
            else if(algo == "poly_dbl") {
               bench_poly_dbl(msec);
            }
#endif

#if defined(BOTAN_HAS_DL_GROUP)
            else if(algo == "modexp") {
               bench_modexp(msec);
            }
#endif

#if defined(BOTAN_HAS_BIGINT)
            else if(algo == "mp_mul") {
               bench_mp_mul(msec);
            } else if(algo == "mp_div") {
               bench_mp_div(msec);
            } else if(algo == "mp_div10") {
               bench_mp_div10(msec);
            }
#endif

#if defined(BOTAN_HAS_NUMBERTHEORY)
            else if(algo == "primality_test") {
               bench_primality_tests(msec);
            } else if(algo == "random_prime") {
               bench_random_prime(msec);
            } else if(algo == "inverse_mod") {
               bench_inverse_mod(msec);
            } else if(algo == "bn_redc") {
               bench_bn_redc(msec);
            } else if(algo == "nistp_redc") {
               bench_nistp_redc(msec);
            }
#endif

#if defined(BOTAN_HAS_FPE_FE1)
            else if(algo == "fpe_fe1") {
               bench_fpe_fe1(msec);
            }
#endif

#if defined(BOTAN_HAS_RFC3394_KEYWRAP)
            else if(algo == "rfc3394") {
               bench_rfc3394(msec);
            }
#endif

#if defined(BOTAN_HAS_ECC_GROUP)
            else if(algo == "ecc_mult") {
               bench_ecc_mult(ecc_groups, msec);
            } else if(algo == "ecc_init") {
               bench_ecc_init(ecc_groups, msec);
            } else if(algo == "os2ecp") {
               bench_os2ecp(ecc_groups, msec);
            }
#endif
#if defined(BOTAN_HAS_EC_HASH_TO_CURVE)
            else if(algo == "ec_h2c") {
               bench_ec_h2c(msec);
            }
#endif
            else if(algo == "RNG") {
#if defined(BOTAN_HAS_AUTO_SEEDING_RNG)
               Botan::AutoSeeded_RNG auto_rng;
               bench_rng(auto_rng, "AutoSeeded_RNG (with reseed)", msec, buf_sizes);
#endif

#if defined(BOTAN_HAS_SYSTEM_RNG)
               bench_rng(Botan::system_rng(), "System_RNG", msec, buf_sizes);
#endif

#if defined(BOTAN_HAS_PROCESSOR_RNG)
               if(Botan::Processor_RNG::available()) {
                  Botan::Processor_RNG hwrng;
                  bench_rng(hwrng, "Processor_RNG", msec, buf_sizes);
               }
#endif

#if defined(BOTAN_HAS_HMAC_DRBG)
               for(std::string hash : {"SHA-256", "SHA-384", "SHA-512"}) {
                  Botan::HMAC_DRBG hmac_drbg(hash);
                  bench_rng(hmac_drbg, hmac_drbg.name(), msec, buf_sizes);
               }
#endif

#if defined(BOTAN_HAS_CHACHA_RNG)
               // Provide a dummy seed
               Botan::ChaCha_RNG chacha_rng(Botan::secure_vector<uint8_t>(32));
               bench_rng(chacha_rng, "ChaCha_RNG", msec, buf_sizes);
#endif

            } else if(algo == "entropy") {
               bench_entropy_sources(msec);
            } else {
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

      void record_result(const std::unique_ptr<Timer>& t) {
         m_ns_taken += t->value();
         m_cycles_consumed += t->cycles_consumed();
         if(m_json) {
            m_json->add(*t);
         } else {
            output() << t->to_string() << std::flush;
            if(m_summary) {
               m_summary->add(*t);
            }
         }
      }

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
            const size_t blocks = buf_size / bs;

            auto encrypt_timer = make_timer(cipher.name(), buffer.size(), "encrypt", provider, buf_size);
            auto decrypt_timer = make_timer(cipher.name(), buffer.size(), "decrypt", provider, buf_size);

            encrypt_timer->run_until_elapsed(runtime, [&]() { cipher.encrypt_n(&buffer[0], &buffer[0], blocks); });
            record_result(encrypt_timer);

            decrypt_timer->run_until_elapsed(runtime, [&]() { cipher.decrypt_n(&buffer[0], &buffer[0], blocks); });
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
            Botan::secure_vector<uint8_t> buffer = rng().random_vec(buf_size);

            auto encrypt_timer = make_timer(cipher.name(), buffer.size(), "encrypt", provider, buf_size);

            const Botan::SymmetricKey key(rng(), cipher.maximum_keylength());
            cipher.set_key(key);

            if(cipher.valid_iv_length(12)) {
               const Botan::InitializationVector iv(rng(), 12);
               cipher.set_iv(iv.begin(), iv.size());
            }

            while(encrypt_timer->under(runtime)) {
               encrypt_timer->run([&]() { cipher.encipher(buffer); });
            }

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

            auto timer = make_timer(hash.name(), buffer.size(), "hash", provider, buf_size);
            timer->run_until_elapsed(runtime, [&]() {
               hash.update(buffer);
               hash.final(output.data());
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

            const Botan::SymmetricKey key(rng(), mac.maximum_keylength());
            mac.set_key(key);
            mac.start(nullptr, 0);

            auto timer = make_timer(mac.name(), buffer.size(), "mac", provider, buf_size);
            timer->run_until_elapsed(runtime, [&]() { mac.update(buffer); });
            timer->run([&]() { mac.final(output.data()); });
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

            auto encrypt_timer = make_timer(enc.name(), buffer.size(), "encrypt", enc.provider(), buf_size);
            auto decrypt_timer = make_timer(dec.name(), buffer.size(), "decrypt", dec.provider(), buf_size);

            Botan::secure_vector<uint8_t> iv = rng().random_vec(enc.default_nonce_length());

            if(buf_size >= enc.minimum_final_size()) {
               while(encrypt_timer->under(runtime) && decrypt_timer->under(runtime)) {
                  // Must run in this order, or AEADs will reject the ciphertext
                  encrypt_timer->run([&]() {
                     enc.start(iv);
                     enc.finish(buffer);
                  });

                  decrypt_timer->run([&]() {
                     dec.start(iv);
                     dec.finish(buffer);
                  });

                  if(!iv.empty()) {
                     iv[iv.size() - 1] += 1;
                  }
               }
            }

            record_result(encrypt_timer);
            record_result(decrypt_timer);
         }
      }
#endif

      void bench_rng(Botan::RandomNumberGenerator& rng,
                     const std::string& rng_name,
                     const std::chrono::milliseconds runtime,
                     const std::vector<size_t>& buf_sizes) {
         for(auto buf_size : buf_sizes) {
            Botan::secure_vector<uint8_t> buffer(buf_size);

#if defined(BOTAN_HAS_SYSTEM_RNG)
            rng.reseed_from_rng(Botan::system_rng(), 256);
#endif

            auto timer = make_timer(rng_name, buffer.size(), "generate", "", buf_size);
            timer->run_until_elapsed(runtime, [&]() { rng.randomize(buffer.data(), buffer.size()); });
            record_result(timer);
         }
      }

      void bench_entropy_sources(const std::chrono::milliseconds /*unused*/) {
         Botan::Entropy_Sources& srcs = Botan::Entropy_Sources::global_sources();

         for(auto src : srcs.enabled_sources()) {
            size_t entropy_bits = 0;
            Botan_Tests::SeedCapturing_RNG rng;

            auto timer = make_timer(src, "", "bytes");
            timer->run([&]() { entropy_bits = srcs.poll_just(rng, src); });

            size_t compressed_size = 0;

#if defined(BOTAN_HAS_ZLIB)
            auto comp = Botan::Compression_Algorithm::create("zlib");

            if(comp) {
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

            if(compressed_size > 0) {
               msg << " output compressed to " << compressed_size << " bytes";
            }

            msg << " total samples " << rng.samples() << "\n";

            timer->set_custom_msg(msg.str());

            record_result(timer);
         }
      }

#if defined(BOTAN_HAS_ECC_GROUP)
      void bench_ecc_init(const std::vector<std::string>& groups, const std::chrono::milliseconds runtime) {
         for(std::string group_name : groups) {
            auto timer = make_timer(group_name + " initialization");

            while(timer->under(runtime)) {
               Botan::EC_Group::clear_registered_curve_data();
               timer->run([&]() { Botan::EC_Group::from_name(group_name); });
            }

            record_result(timer);
         }
      }

      void bench_ecc_mult(const std::vector<std::string>& groups, const std::chrono::milliseconds runtime) {
         for(const std::string& group_name : groups) {
            const auto ec_group = Botan::EC_Group::from_name(group_name);

            auto mult_timer = make_timer(group_name + " Montgomery ladder");
            auto blinded_mult_timer = make_timer(group_name + " blinded comb");
            auto blinded_var_mult_timer = make_timer(group_name + " blinded window");

            const Botan::EC_Point& base_point = ec_group.get_base_point();

            std::vector<Botan::BigInt> ws;

            while(mult_timer->under(runtime) && blinded_mult_timer->under(runtime) &&
                  blinded_var_mult_timer->under(runtime)) {
               const Botan::BigInt scalar = ec_group.random_scalar(rng());

               const Botan::EC_Point r1 = mult_timer->run([&]() { return base_point * scalar; });

               const Botan::EC_Point r2 = blinded_mult_timer->run([&]() {
                  auto pt = ec_group.blinded_base_point_multiply(scalar, rng(), ws);
                  pt.force_affine();
                  return pt;
               });

               const Botan::EC_Point r3 = blinded_var_mult_timer->run([&]() {
                  auto pt = ec_group.blinded_var_point_multiply(base_point, scalar, rng(), ws);
                  pt.force_affine();
                  return pt;
               });

               BOTAN_ASSERT_EQUAL(r1, r2, "Same point computed by Montgomery and comb");
               BOTAN_ASSERT_EQUAL(r1, r3, "Same point computed by Montgomery and window");
            }

            record_result(mult_timer);
            record_result(blinded_mult_timer);
            record_result(blinded_var_mult_timer);
         }
      }

      void bench_os2ecp(const std::vector<std::string>& groups, const std::chrono::milliseconds runtime) {
         for(const std::string& group_name : groups) {
            auto uncmp_timer = make_timer("OS2ECP uncompressed " + group_name);
            auto cmp_timer = make_timer("OS2ECP compressed " + group_name);

            const auto ec_group = Botan::EC_Group::from_name(group_name);

            while(uncmp_timer->under(runtime) && cmp_timer->under(runtime)) {
               const Botan::BigInt k(rng(), 256);
               const Botan::EC_Point p = ec_group.get_base_point() * k;
               const std::vector<uint8_t> os_cmp = p.encode(Botan::EC_Point_Format::Compressed);
               const std::vector<uint8_t> os_uncmp = p.encode(Botan::EC_Point_Format::Uncompressed);

               uncmp_timer->run([&]() { ec_group.OS2ECP(os_uncmp); });
               cmp_timer->run([&]() { ec_group.OS2ECP(os_cmp); });
            }

            record_result(uncmp_timer);
            record_result(cmp_timer);
         }
      }

#endif

#if defined(BOTAN_HAS_EC_HASH_TO_CURVE)
      void bench_ec_h2c(const std::chrono::milliseconds runtime) {
         for(std::string group_name : {"secp256r1", "secp384r1", "secp521r1"}) {
            auto h2c_ro_timer = make_timer(group_name + "-RO", "", "hash to curve");
            auto h2c_nu_timer = make_timer(group_name + "-NU", "", "hash to curve");

            const auto group = Botan::EC_Group::from_name(group_name);

            while(h2c_ro_timer->under(runtime)) {
               std::vector<uint8_t> input(32);

               rng().randomize(input.data(), input.size());

               const Botan::EC_Point p1 = h2c_ro_timer->run(
                  [&]() { return group.hash_to_curve("SHA-256", input.data(), input.size(), nullptr, 0, true); });

               BOTAN_ASSERT_NOMSG(p1.on_the_curve());

               const Botan::EC_Point p2 = h2c_nu_timer->run(
                  [&]() { return group.hash_to_curve("SHA-256", input.data(), input.size(), nullptr, 0, false); });

               BOTAN_ASSERT_NOMSG(p2.on_the_curve());
            }

            record_result(h2c_ro_timer);
            record_result(h2c_nu_timer);
         }
      }
#endif

#if defined(BOTAN_HAS_PCURVES)

      void bench_pcurves(const std::vector<std::string>& groups, const std::chrono::milliseconds runtime) {
         for(const auto& group_name : groups) {
            if(auto curve = Botan::PCurve::PrimeOrderCurve::from_name(group_name)) {
               auto base_timer = make_timer(group_name + " pcurve base mul");
               auto var_timer = make_timer(group_name + " pcurve var mul");
               auto mul2_setup_timer = make_timer(group_name + " pcurve mul2 setup");
               auto mul2_timer = make_timer(group_name + " pcurve mul2");

               auto scalar_invert = make_timer(group_name + " pcurve scalar invert");
               auto to_affine = make_timer(group_name + " pcurve proj->affine");

               auto g = curve->generator();
               auto h = curve->mul(g, curve->random_scalar(rng()), rng()).to_affine();
               auto gh_tab = curve->mul2_setup(g, h);

               while(base_timer->under(runtime)) {
                  const auto scalar = curve->random_scalar(rng());
                  base_timer->run([&]() { return curve->mul_by_g(scalar, rng()).to_affine(); });
               }

               while(var_timer->under(runtime)) {
                  const auto scalar = curve->random_scalar(rng());
                  var_timer->run([&]() { return curve->mul(h, scalar, rng()).to_affine(); });
               }

               while(mul2_setup_timer->under(runtime)) {
                  mul2_setup_timer->run([&]() { return curve->mul2_setup(g, h); });
               }

               while(mul2_timer->under(runtime)) {
                  const auto scalar = curve->random_scalar(rng());
                  const auto scalar2 = curve->random_scalar(rng());
                  mul2_timer->run([&]() -> std::optional<Botan::PCurve::PrimeOrderCurve::AffinePoint> {
                     if(auto pt = curve->mul2_vartime(*gh_tab, scalar, scalar2)) {
                        return pt->to_affine();
                     } else {
                        return {};
                     }
                  });
               }

               auto pt = curve->mul(g, curve->random_scalar(rng()), rng());
               to_affine->run_until_elapsed(runtime, [&]() { pt.to_affine(); });

               while(scalar_invert->under(runtime)) {
                  const auto scalar = curve->random_scalar(rng());
                  scalar_invert->run([&]() { scalar.invert(); });
               }

               record_result(base_timer);
               record_result(var_timer);
               record_result(mul2_setup_timer);
               record_result(mul2_timer);
               record_result(to_affine);
               record_result(scalar_invert);
            }
         }
      }

      void bench_pcurve_ecdsa(const std::vector<std::string>& groups, const std::chrono::milliseconds runtime) {
         for(const auto& group_name : groups) {
            auto curve = Botan::PCurve::PrimeOrderCurve::from_name(group_name);
            if(!curve) {
               continue;
            }

            // Setup (not timed)
            const auto g = curve->generator();
            const auto x = curve->random_scalar(rng());
            const auto y = curve->mul_by_g(x, rng()).to_affine();
            const auto e = curve->random_scalar(rng());

            const auto gy_tab = curve->mul2_setup(g, y);

            auto b = curve->random_scalar(rng());
            auto b_inv = b.invert();

            auto sign_timer = make_timer("ECDSA sign pcurves " + group_name);
            auto verify_timer = make_timer("ECDSA verify pcurves " + group_name);

            while(sign_timer->under(runtime)) {
               sign_timer->start();

               const auto signature = [&]() {
                  const auto k = curve->random_scalar(rng());
                  const auto r = curve->base_point_mul_x_mod_order(k, rng());
                  const auto k_inv = k.invert();
                  b = b.square();
                  b_inv = b_inv.square();
                  const auto be = b * e;
                  const auto bx = b * x;
                  const auto bxr_e = (bx * r) + be;
                  const auto s = (k_inv * bxr_e) * b_inv;

                  return Botan::concat(r.serialize(), s.serialize());
               }();

               sign_timer->stop();

               verify_timer->start();

               auto result = [&](std::span<const uint8_t> sig) {
                  const size_t scalar_bytes = curve->scalar_bytes();
                  if(sig.size() != 2 * scalar_bytes) {
                     return false;
                  }

                  const auto r = curve->deserialize_scalar(sig.first(scalar_bytes));
                  const auto s = curve->deserialize_scalar(sig.last(scalar_bytes));

                  if(r && s) {
                     if(r->is_zero() || s->is_zero()) {
                        return false;
                     }

                     auto w = s->invert();

                     auto u1 = e * w;
                     auto u2 = *r * w;

                     auto v = curve->mul2_vartime_x_mod_order(*gy_tab, u1, u2);

                     return (r == v);
                  }

                  return false;
               }(signature);

               BOTAN_ASSERT(result, "ECDSA-pcurves signature ok");

               verify_timer->stop();
            }

            record_result(sign_timer);
            record_result(verify_timer);
         }
      }

      void bench_pcurve_ecdh(const std::vector<std::string>& groups, const std::chrono::milliseconds runtime) {
         for(const auto& group_name : groups) {
            auto curve = Botan::PCurve::PrimeOrderCurve::from_name(group_name);
            if(!curve) {
               continue;
            }

            auto ka_timer = make_timer("ECDH agree pcurves " + group_name);

            auto agree = [&](const Botan::PCurve::PrimeOrderCurve::Scalar& sk, std::span<const uint8_t> pt_bytes) {
               const auto pt = curve->deserialize_point(pt_bytes);
               if(pt) {
                  return curve->mul(*pt, sk, rng()).to_affine().serialize();
               } else {
                  return std::vector<uint8_t>();
               }
            };

            while(ka_timer->under(runtime)) {
               const auto g = curve->generator();
               const auto x1 = curve->random_scalar(rng());
               const auto x2 = curve->random_scalar(rng());

               const auto y1 = curve->mul_by_g(x1, rng()).to_affine().serialize();
               const auto y2 = curve->mul_by_g(x2, rng()).to_affine().serialize();

               ka_timer->start();
               const auto ss1 = agree(x1, y2);
               ka_timer->stop();

               ka_timer->start();
               const auto ss2 = agree(x1, y2);
               ka_timer->stop();

               BOTAN_ASSERT(ss1 == ss2, "Key agreement worked");
            }

            record_result(ka_timer);
         }
      }

#endif

#if defined(BOTAN_HAS_FPE_FE1)

      void bench_fpe_fe1(const std::chrono::milliseconds runtime) {
         const auto n = Botan::BigInt::from_u64(1000000000000000);

         auto enc_timer = make_timer("FPE_FE1 encrypt");
         auto dec_timer = make_timer("FPE_FE1 decrypt");

         const Botan::SymmetricKey key(rng(), 32);
         const std::vector<uint8_t> tweak(8);  // 8 zeros

         auto x = Botan::BigInt::one();

         Botan::FPE_FE1 fpe_fe1(n);
         fpe_fe1.set_key(key);

         while(enc_timer->under(runtime)) {
            enc_timer->start();
            x = fpe_fe1.encrypt(x, tweak.data(), tweak.size());
            enc_timer->stop();
         }

         for(size_t i = 0; i != enc_timer->events(); ++i) {
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

      void bench_rfc3394(const std::chrono::milliseconds runtime) {
         auto wrap_timer = make_timer("RFC3394 AES-256 key wrap");
         auto unwrap_timer = make_timer("RFC3394 AES-256 key unwrap");

         const Botan::SymmetricKey kek(rng(), 32);
         Botan::secure_vector<uint8_t> key(64, 0);

         while(wrap_timer->under(runtime)) {
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

      void bench_mp_mul(const std::chrono::milliseconds runtime) {
         std::chrono::milliseconds runtime_per_size = runtime;
         for(size_t bits : {256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096}) {
            auto mul_timer = make_timer("BigInt mul " + std::to_string(bits));
            auto sqr_timer = make_timer("BigInt sqr " + std::to_string(bits));

            const Botan::BigInt y(rng(), bits);
            Botan::secure_vector<Botan::word> ws;

            while(mul_timer->under(runtime_per_size)) {
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

      void bench_mp_div(const std::chrono::milliseconds runtime) {
         std::chrono::milliseconds runtime_per_size = runtime;

         for(size_t n_bits : {256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096}) {
            const size_t q_bits = n_bits / 2;
            const std::string bit_descr = std::to_string(n_bits) + "/" + std::to_string(q_bits);

            auto div_timer = make_timer("BigInt div " + bit_descr);
            auto ct_div_timer = make_timer("BigInt ct_div " + bit_descr);

            Botan::BigInt y;
            Botan::BigInt x;
            Botan::secure_vector<Botan::word> ws;

            Botan::BigInt q1, r1, q2, r2;

            while(ct_div_timer->under(runtime_per_size)) {
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

      void bench_mp_div10(const std::chrono::milliseconds runtime) {
         std::chrono::milliseconds runtime_per_size = runtime;

         for(size_t n_bits : {256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096}) {
            const std::string bit_descr = std::to_string(n_bits) + "/10";

            auto div_timer = make_timer("BigInt div " + bit_descr);
            auto ct_div_timer = make_timer("BigInt ct_div " + bit_descr);

            Botan::BigInt x;
            Botan::secure_vector<Botan::word> ws;

            const auto ten = Botan::BigInt::from_word(10);
            Botan::BigInt q1, r1, q2;
            Botan::word r2;

            while(ct_div_timer->under(runtime_per_size)) {
               x.randomize(rng(), n_bits);

               div_timer->start();
               Botan::vartime_divide(x, ten, q1, r1);
               div_timer->stop();

               ct_div_timer->start();
               Botan::ct_divide_word(x, 10, q2, r2);
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

      void bench_modexp(const std::chrono::milliseconds runtime) {
         for(size_t group_bits : {1024, 1536, 2048, 3072, 4096}) {
            const std::string group_bits_str = std::to_string(group_bits);
            const Botan::DL_Group group("modp/srp/" + group_bits_str);

            const size_t e_bits = Botan::dl_exponent_size(group_bits);
            const size_t f_bits = group_bits - 1;

            const Botan::BigInt random_e(rng(), e_bits);
            const Botan::BigInt random_f(rng(), f_bits);

            auto e_timer = make_timer(group_bits_str + " short exponent");
            auto f_timer = make_timer(group_bits_str + "  full exponent");

            while(f_timer->under(runtime)) {
               e_timer->run([&]() { group.power_g_p(random_e); });
               f_timer->run([&]() { group.power_g_p(random_f); });
            }

            record_result(e_timer);
            record_result(f_timer);
         }
      }
#endif

#if defined(BOTAN_HAS_NUMBERTHEORY)
      void bench_nistp_redc(const std::chrono::milliseconds runtime) {
         Botan::secure_vector<Botan::word> ws;

         auto p192_timer = make_timer("P-192 redc");
         Botan::BigInt r192(rng(), 192 * 2 - 1);
         while(p192_timer->under(runtime)) {
            Botan::BigInt r = r192;
            p192_timer->run([&]() { Botan::redc_p192(r, ws); });
            r192 += 1;
         }
         record_result(p192_timer);

         auto p224_timer = make_timer("P-224 redc");
         Botan::BigInt r224(rng(), 224 * 2 - 1);
         while(p224_timer->under(runtime)) {
            Botan::BigInt r = r224;
            p224_timer->run([&]() { Botan::redc_p224(r, ws); });
            r224 += 1;
         }
         record_result(p224_timer);

         auto p256_timer = make_timer("P-256 redc");
         Botan::BigInt r256(rng(), 256 * 2 - 1);
         while(p256_timer->under(runtime)) {
            Botan::BigInt r = r256;
            p256_timer->run([&]() { Botan::redc_p256(r, ws); });
            r256 += 1;
         }
         record_result(p256_timer);

         auto p384_timer = make_timer("P-384 redc");
         Botan::BigInt r384(rng(), 384 * 2 - 1);
         while(p384_timer->under(runtime)) {
            Botan::BigInt r = r384;
            p384_timer->run([&]() { Botan::redc_p384(r384, ws); });
            r384 += 1;
         }
         record_result(p384_timer);

         auto p521_timer = make_timer("P-521 redc");
         Botan::BigInt r521(rng(), 521 * 2 - 1);
         while(p521_timer->under(runtime)) {
            Botan::BigInt r = r521;
            p521_timer->run([&]() { Botan::redc_p521(r521, ws); });
            r521 += 1;
         }
         record_result(p521_timer);
      }

      void bench_bn_redc(const std::chrono::milliseconds runtime) {
         for(size_t bitsize : {512, 1024, 2048, 4096}) {
            Botan::BigInt p(rng(), bitsize);

            std::string bit_str = std::to_string(bitsize);
            auto barrett_timer = make_timer("Barrett-" + bit_str);
            auto schoolbook_timer = make_timer("Schoolbook-" + bit_str);

            Botan::Modular_Reducer mod_p(p);

            while(schoolbook_timer->under(runtime)) {
               const Botan::BigInt x(rng(), p.bits() * 2 - 2);

               const Botan::BigInt r1 = barrett_timer->run([&] { return mod_p.reduce(x); });
               const Botan::BigInt r2 = schoolbook_timer->run([&] { return x % p; });

               BOTAN_ASSERT(r1 == r2, "Computed different results");
            }

            record_result(barrett_timer);
            record_result(schoolbook_timer);
         }
      }

      void bench_inverse_mod(const std::chrono::milliseconds runtime) {
         for(size_t bits : {256, 384, 512, 1024, 2048}) {
            const std::string bit_str = std::to_string(bits);

            auto timer = make_timer("inverse_mod-" + bit_str);
            auto gcd_timer = make_timer("gcd-" + bit_str);

            while(timer->under(runtime) && gcd_timer->under(runtime)) {
               const Botan::BigInt x(rng(), bits - 1);
               Botan::BigInt mod(rng(), bits);

               const Botan::BigInt x_inv = timer->run([&] { return Botan::inverse_mod(x, mod); });

               const Botan::BigInt g = gcd_timer->run([&] { return gcd(x, mod); });

               if(x_inv == 0) {
                  BOTAN_ASSERT(g != 1, "Inversion only fails if gcd(x, mod) > 1");
               } else {
                  BOTAN_ASSERT(g == 1, "Inversion succeeds only if gcd != 1");
                  const Botan::BigInt check = (x_inv * x) % mod;
                  BOTAN_ASSERT_EQUAL(check, 1, "Const time inversion correct");
               }
            }

            record_result(timer);
            record_result(gcd_timer);
         }
      }

      void bench_primality_tests(const std::chrono::milliseconds runtime) {
         for(size_t bits : {256, 512, 1024}) {
            auto mr_timer = make_timer("Miller-Rabin-" + std::to_string(bits));
            auto bpsw_timer = make_timer("Bailie-PSW-" + std::to_string(bits));
            auto lucas_timer = make_timer("Lucas-" + std::to_string(bits));

            Botan::BigInt n = Botan::random_prime(rng(), bits);

            while(lucas_timer->under(runtime)) {
               Botan::Modular_Reducer mod_n(n);

               mr_timer->run([&]() { return Botan::is_miller_rabin_probable_prime(n, mod_n, rng(), 2); });

               bpsw_timer->run([&]() { return Botan::is_bailie_psw_probable_prime(n, mod_n); });

               lucas_timer->run([&]() { return Botan::is_lucas_probable_prime(n, mod_n); });

               n += 2;
            }

            record_result(mr_timer);
            record_result(bpsw_timer);
            record_result(lucas_timer);
         }
      }

      void bench_random_prime(const std::chrono::milliseconds runtime) {
         const auto coprime = Botan::BigInt::from_word(0x10001);

         for(size_t bits : {256, 384, 512, 768, 1024, 1536}) {
            auto genprime_timer = make_timer("random_prime " + std::to_string(bits));
            auto gensafe_timer = make_timer("random_safe_prime " + std::to_string(bits));
            auto is_prime_timer = make_timer("is_prime " + std::to_string(bits));

            while(gensafe_timer->under(runtime)) {
               const Botan::BigInt p = genprime_timer->run([&] { return Botan::random_prime(rng(), bits, coprime); });

               if(!is_prime_timer->run([&] { return Botan::is_prime(p, rng(), 64, true); })) {
                  error_output() << "Generated prime " << p << " which failed a primality test";
               }

               const Botan::BigInt sg = gensafe_timer->run([&] { return Botan::random_safe_prime(rng(), bits); });

               if(!is_prime_timer->run([&] { return Botan::is_prime(sg, rng(), 64, true); })) {
                  error_output() << "Generated safe prime " << sg << " which failed a primality test";
               }

               if(!is_prime_timer->run([&] { return Botan::is_prime(sg / 2, rng(), 64, true); })) {
                  error_output() << "Generated prime " << sg / 2 << " which failed a primality test";
               }

               // Now test p+2, p+4, ... which may or may not be prime
               for(size_t i = 2; i <= 64; i += 2) {
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
      void bench_pk_enc(const Botan::Private_Key& key,
                        const std::string& nm,
                        const std::string& provider,
                        const std::string& padding,
                        std::chrono::milliseconds msec) {
         std::vector<uint8_t> plaintext, ciphertext;

         Botan::PK_Encryptor_EME enc(key, rng(), padding, provider);
         Botan::PK_Decryptor_EME dec(key, rng(), padding, provider);

         auto enc_timer = make_timer(nm + " " + padding, provider, "encrypt");
         auto dec_timer = make_timer(nm + " " + padding, provider, "decrypt");

         while(enc_timer->under(msec) || dec_timer->under(msec)) {
            // Generate a new random ciphertext to decrypt
            if(ciphertext.empty() || enc_timer->under(msec)) {
               rng().random_vec(plaintext, enc.maximum_input_size());
               ciphertext = enc_timer->run([&]() { return enc.encrypt(plaintext, rng()); });
            }

            if(dec_timer->under(msec)) {
               const auto dec_pt = dec_timer->run([&]() { return dec.decrypt(ciphertext); });

               if(!(Botan::unlock(dec_pt) == plaintext))  // sanity check
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
                       std::chrono::milliseconds msec) {
         const std::string kdf = "KDF2(SHA-256)";  // arbitrary choice

         auto keygen_timer = make_timer(nm, provider, "keygen");

         std::unique_ptr<Botan::Private_Key> key1(
            keygen_timer->run([&] { return Botan::create_private_key(algo, rng(), params); }));
         std::unique_ptr<Botan::Private_Key> key2(
            keygen_timer->run([&] { return Botan::create_private_key(algo, rng(), params); }));

         record_result(keygen_timer);

         const Botan::PK_Key_Agreement_Key& ka_key1 = dynamic_cast<const Botan::PK_Key_Agreement_Key&>(*key1);
         const Botan::PK_Key_Agreement_Key& ka_key2 = dynamic_cast<const Botan::PK_Key_Agreement_Key&>(*key2);

         Botan::PK_Key_Agreement ka1(ka_key1, rng(), kdf, provider);
         Botan::PK_Key_Agreement ka2(ka_key2, rng(), kdf, provider);

         const std::vector<uint8_t> ka1_pub = ka_key1.public_value();
         const std::vector<uint8_t> ka2_pub = ka_key2.public_value();

         auto ka_timer = make_timer(nm, provider, "key agreements");

         while(ka_timer->under(msec)) {
            Botan::SymmetricKey symkey1 = ka_timer->run([&]() { return ka1.derive_key(32, ka2_pub); });
            Botan::SymmetricKey symkey2 = ka_timer->run([&]() { return ka2.derive_key(32, ka1_pub); });

            if(symkey1 != symkey2) {
               error_output() << "Key agreement mismatch in PK bench\n";
            }
         }

         record_result(ka_timer);
      }

      void bench_pk_kem(const Botan::Private_Key& key,
                        const std::string& nm,
                        const std::string& provider,
                        const std::string& kdf,
                        std::chrono::milliseconds msec) {
         Botan::PK_KEM_Decryptor dec(key, rng(), kdf, provider);
         Botan::PK_KEM_Encryptor enc(key, kdf, provider);

         auto kem_enc_timer = make_timer(nm, provider, "KEM encrypt");
         auto kem_dec_timer = make_timer(nm, provider, "KEM decrypt");

         while(kem_enc_timer->under(msec) && kem_dec_timer->under(msec)) {
            Botan::secure_vector<uint8_t> salt = rng().random_vec(16);

            kem_enc_timer->start();
            const auto kem_result = enc.encrypt(rng(), 64, salt);
            kem_enc_timer->stop();

            kem_dec_timer->start();
            Botan::secure_vector<uint8_t> dec_shared_key = dec.decrypt(kem_result.encapsulated_shared_key(), 64, salt);
            kem_dec_timer->stop();

            if(kem_result.shared_key() != dec_shared_key) {
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
                            std::chrono::milliseconds msec) {
         for(std::string grp : params) {
            const std::string nm = grp.empty() ? algo : Botan::fmt("{}-{}", algo, grp);

            auto keygen_timer = make_timer(nm, provider, "keygen");

            std::unique_ptr<Botan::Private_Key> key(
               keygen_timer->run([&] { return Botan::create_private_key(algo, rng(), grp); }));

            record_result(keygen_timer);
            bench_pk_sig(*key, nm, provider, emsa, msec);
         }
      }

      size_t bench_pk_sig(const Botan::Private_Key& key,
                          const std::string& nm,
                          const std::string& provider,
                          const std::string& padding,
                          std::chrono::milliseconds msec) {
         std::vector<uint8_t> message, signature, bad_signature;

         Botan::PK_Signer sig(key, rng(), padding, Botan::Signature_Format::Standard, provider);
         Botan::PK_Verifier ver(key, padding, Botan::Signature_Format::Standard, provider);

         auto sig_timer = make_timer(nm + " " + padding, provider, "sign");
         auto ver_timer = make_timer(nm + " " + padding, provider, "verify");

         size_t invalid_sigs = 0;

         while(ver_timer->under(msec) || sig_timer->under(msec)) {
            if(signature.empty() || sig_timer->under(msec)) {
               /*
               Length here is kind of arbitrary, but 48 bytes fits into a single
               hash block so minimizes hashing overhead versus the PK op itself.
               */
               rng().random_vec(message, 48);

               signature = sig_timer->run([&]() { return sig.sign_message(message, rng()); });

               bad_signature = signature;
               bad_signature[rng().next_byte() % bad_signature.size()] ^= rng().next_nonzero_byte();
            }

            if(ver_timer->under(msec)) {
               const bool verified = ver_timer->run([&] { return ver.verify_message(message, signature); });

               if(!verified) {
                  invalid_sigs += 1;
               }

               const bool verified_bad = ver_timer->run([&] { return ver.verify_message(message, bad_signature); });

               if(verified_bad) {
                  error_output() << "Bad signature accepted in " << nm << " signature bench\n";
               }
            }
         }

         if(invalid_sigs > 0) {
            error_output() << invalid_sigs << " generated signatures rejected in " << nm << " signature bench\n";
         }

         const size_t events = static_cast<size_t>(std::min(sig_timer->events(), ver_timer->events()));

         record_result(sig_timer);
         record_result(ver_timer);

         return events;
      }
#endif

#if defined(BOTAN_HAS_RSA)
      void bench_rsa_keygen(const std::string& provider, std::chrono::milliseconds msec) {
         for(size_t keylen : {1024, 2048, 3072, 4096}) {
            const std::string nm = "RSA-" + std::to_string(keylen);
            auto keygen_timer = make_timer(nm, provider, "keygen");

            while(keygen_timer->under(msec)) {
               std::unique_ptr<Botan::Private_Key> key(
                  keygen_timer->run([&] { return Botan::create_private_key("RSA", rng(), std::to_string(keylen)); }));

               BOTAN_ASSERT(key->check_key(rng(), true), "Key is ok");
            }

            record_result(keygen_timer);
         }
      }

      void bench_rsa(const std::string& provider, std::chrono::milliseconds msec) {
         for(size_t keylen : {1024, 2048, 3072, 4096}) {
            const std::string nm = "RSA-" + std::to_string(keylen);

            auto keygen_timer = make_timer(nm, provider, "keygen");

            std::unique_ptr<Botan::Private_Key> key(
               keygen_timer->run([&] { return Botan::create_private_key("RSA", rng(), std::to_string(keylen)); }));

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
                       std::chrono::milliseconds msec) {
         return bench_pk_sig_ecc("ECDSA", "SHA-256", provider, groups, msec);
      }

      void bench_ecdsa_recovery(const std::vector<std::string>& groups,
                                const std::string& /*unused*/,
                                std::chrono::milliseconds msec) {
         for(const std::string& group_name : groups) {
            const auto group = Botan::EC_Group::from_name(group_name);
            auto recovery_timer = make_timer("ECDSA recovery " + group_name);

            while(recovery_timer->under(msec)) {
               Botan::ECDSA_PrivateKey key(rng(), group);

               std::vector<uint8_t> message(group.get_order_bits() / 8);
               rng().randomize(message.data(), message.size());

               Botan::PK_Signer signer(key, rng(), "Raw");
               signer.update(message);
               std::vector<uint8_t> signature = signer.signature(rng());

               Botan::PK_Verifier verifier(key, "Raw", Botan::Signature_Format::Standard, "base");
               verifier.update(message);
               BOTAN_ASSERT(verifier.check_signature(signature), "Valid signature");

               Botan::BigInt r(signature.data(), signature.size() / 2);
               Botan::BigInt s(signature.data() + signature.size() / 2, signature.size() / 2);

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
                         std::chrono::milliseconds msec) {
         return bench_pk_sig_ecc("ECKCDSA", "SHA-256", provider, groups, msec);
      }
#endif

#if defined(BOTAN_HAS_GOST_34_10_2001)
      void bench_gost_3410(const std::string& provider, std::chrono::milliseconds msec) {
         return bench_pk_sig_ecc("GOST-34.10", "GOST-34.11", provider, {"gost_256A"}, msec);
      }
#endif

#if defined(BOTAN_HAS_SM2)
      void bench_sm2(const std::vector<std::string>& groups,
                     const std::string& provider,
                     std::chrono::milliseconds msec) {
         return bench_pk_sig_ecc("SM2_Sig", "SM3", provider, groups, msec);
      }
#endif

#if defined(BOTAN_HAS_ECGDSA)
      void bench_ecgdsa(const std::vector<std::string>& groups,
                        const std::string& provider,
                        std::chrono::milliseconds msec) {
         return bench_pk_sig_ecc("ECGDSA", "SHA-256", provider, groups, msec);
      }
#endif

#if defined(BOTAN_HAS_ED25519)
      void bench_ed25519(const std::string& provider, std::chrono::milliseconds msec) {
         return bench_pk_sig_ecc("Ed25519", "Pure", provider, std::vector<std::string>{""}, msec);
      }
#endif

#if defined(BOTAN_HAS_ED448)
      void bench_ed448(const std::string& provider, std::chrono::milliseconds msec) {
         return bench_pk_sig_ecc("Ed448", "Pure", provider, std::vector<std::string>{""}, msec);
      }
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
      void bench_dh(const std::string& provider, std::chrono::milliseconds msec) {
         for(size_t bits : {2048, 3072, 4096, 6144, 8192}) {
            bench_pk_ka("DH", "DH-" + std::to_string(bits), "ffdhe/ietf/" + std::to_string(bits), provider, msec);
         }
      }
#endif

#if defined(BOTAN_HAS_DSA)
      void bench_dsa(const std::string& provider, std::chrono::milliseconds msec) {
         for(size_t bits : {1024, 2048, 3072}) {
            const std::string nm = "DSA-" + std::to_string(bits);

            const std::string params = (bits == 1024) ? "dsa/jce/1024" : ("dsa/botan/" + std::to_string(bits));

            auto keygen_timer = make_timer(nm, provider, "keygen");

            std::unique_ptr<Botan::Private_Key> key(
               keygen_timer->run([&] { return Botan::create_private_key("DSA", rng(), params); }));

            record_result(keygen_timer);

            bench_pk_sig(*key, nm, provider, "SHA-256", msec);
         }
      }
#endif

#if defined(BOTAN_HAS_ELGAMAL)
      void bench_elgamal(const std::string& provider, std::chrono::milliseconds msec) {
         for(size_t keylen : {1024, 2048, 3072, 4096}) {
            const std::string nm = "ElGamal-" + std::to_string(keylen);

            const std::string params = "modp/ietf/" + std::to_string(keylen);

            auto keygen_timer = make_timer(nm, provider, "keygen");

            std::unique_ptr<Botan::Private_Key> key(
               keygen_timer->run([&] { return Botan::create_private_key("ElGamal", rng(), params); }));

            record_result(keygen_timer);

            bench_pk_enc(*key, nm, provider, "EME-PKCS1-v1_5", msec);
         }
      }
#endif

#if defined(BOTAN_HAS_ECDH)
      void bench_ecdh(const std::vector<std::string>& groups,
                      const std::string& provider,
                      std::chrono::milliseconds msec) {
         for(const std::string& grp : groups) {
            bench_pk_ka("ECDH", "ECDH-" + grp, grp, provider, msec);
         }
      }
#endif

#if defined(BOTAN_HAS_X25519)
      void bench_x25519(const std::string& provider, std::chrono::milliseconds msec) {
         bench_pk_ka("X25519", "X25519", "", provider, msec);
      }
#endif

#if defined(BOTAN_HAS_X448)
      void bench_x448(const std::string& provider, std::chrono::milliseconds msec) {
         bench_pk_ka("X448", "X448", "", provider, msec);
      }
#endif

#if defined(BOTAN_HAS_MCELIECE)
      void bench_mceliece(const std::string& provider, std::chrono::milliseconds msec) {
         /*
         SL=80 n=1632 t=33 - 59 KB pubkey 140 KB privkey
         SL=107 n=2480 t=45 - 128 KB pubkey 300 KB privkey
         SL=128 n=2960 t=57 - 195 KB pubkey 459 KB privkey
         SL=147 n=3408 t=67 - 265 KB pubkey 622 KB privkey
         SL=191 n=4624 t=95 - 516 KB pubkey 1234 KB privkey
         SL=256 n=6624 t=115 - 942 KB pubkey 2184 KB privkey
         */

         const std::vector<std::pair<size_t, size_t>> mce_params = {
            {2480, 45}, {2960, 57}, {3408, 67}, {4624, 95}, {6624, 115}};

         for(auto params : mce_params) {
            size_t n = params.first;
            size_t t = params.second;

            const std::string nm = "McEliece-" + std::to_string(n) + "," + std::to_string(t) +
                                   " (WF=" + std::to_string(Botan::mceliece_work_factor(n, t)) + ")";

            auto keygen_timer = make_timer(nm, provider, "keygen");

            std::unique_ptr<Botan::Private_Key> key =
               keygen_timer->run([&] { return std::make_unique<Botan::McEliece_PrivateKey>(rng(), n, t); });

            record_result(keygen_timer);
            bench_pk_kem(*key, nm, provider, "KDF2(SHA-256)", msec);
         }
      }
#endif

#if defined(BOTAN_HAS_KYBER) || defined(BOTAN_HAS_KYBER_90S)
      void bench_kyber(const std::string& provider, std::chrono::milliseconds msec) {
         const Botan::KyberMode::Mode all_modes[] = {
            Botan::KyberMode::Kyber512_R3,
            Botan::KyberMode::Kyber512_90s,
            Botan::KyberMode::Kyber768_R3,
            Botan::KyberMode::Kyber768_90s,
            Botan::KyberMode::Kyber1024_R3,
            Botan::KyberMode::Kyber1024_90s,
         };

         for(auto modet : all_modes) {
            Botan::KyberMode mode(modet);

   #if !defined(BOTAN_HAS_KYBER)
            if(mode.is_modern())
               continue;
   #endif

   #if !defined(BOTAN_HAS_KYBER_90S)
            if(mode.is_90s())
               continue;
   #endif

            auto keygen_timer = make_timer(mode.to_string(), provider, "keygen");

            auto key = keygen_timer->run([&] { return Botan::Kyber_PrivateKey(rng(), mode); });

            record_result(keygen_timer);

            bench_pk_kem(key, mode.to_string(), provider, "KDF2(SHA-256)", msec);
         }
      }
#endif

#if defined(BOTAN_HAS_DILITHIUM) || defined(BOTAN_HAS_DILITHIUM_AES)
      void bench_dilithium(const std::string& provider, std::chrono::milliseconds msec) {
         const Botan::DilithiumMode::Mode all_modes[] = {Botan::DilithiumMode::Dilithium4x4,
                                                         Botan::DilithiumMode::Dilithium4x4_AES,
                                                         Botan::DilithiumMode::Dilithium6x5,
                                                         Botan::DilithiumMode::Dilithium6x5_AES,
                                                         Botan::DilithiumMode::Dilithium8x7,
                                                         Botan::DilithiumMode::Dilithium8x7_AES};

         for(auto modet : all_modes) {
            Botan::DilithiumMode mode(modet);

   #if !defined(BOTAN_HAS_DILITHIUM)
            if(mode.is_modern())
               continue;
   #endif

   #if !defined(BOTAN_HAS_DILITHIUM_AES)
            if(mode.is_aes())
               continue;
   #endif

            auto keygen_timer = make_timer(mode.to_string(), provider, "keygen");

            auto key = keygen_timer->run([&] { return Botan::Dilithium_PrivateKey(rng(), mode); });

            record_result(keygen_timer);

            bench_pk_sig(key, mode.to_string(), provider, "", msec);
         }
      }
#endif

#if defined(BOTAN_HAS_SPHINCS_PLUS_WITH_SHA2) || defined(BOTAN_HAS_SPHINCS_PLUS_WITH_SHAKE)
      void bench_sphincs_plus(const std::string& provider, std::chrono::milliseconds msec) {
         // Sphincs_Parameter_Set set, Sphincs_Hash_Type hash
         std::vector<std::string> sphincs_params{"SphincsPlus-sha2-128s-r3.1",
                                                 "SphincsPlus-sha2-128f-r3.1",
                                                 "SphincsPlus-sha2-192s-r3.1",
                                                 "SphincsPlus-sha2-192f-r3.1",
                                                 "SphincsPlus-sha2-256s-r3.1",
                                                 "SphincsPlus-sha2-256f-r3.1",
                                                 "SphincsPlus-shake-128s-r3.1",
                                                 "SphincsPlus-shake-128f-r3.1",
                                                 "SphincsPlus-shake-192s-r3.1",
                                                 "SphincsPlus-shake-192f-r3.1",
                                                 "SphincsPlus-shake-256s-r3.1",
                                                 "SphincsPlus-shake-256f-r3.1"};

         for(auto params : sphincs_params) {
            try {
               auto keygen_timer = make_timer(params, provider, "keygen");

               std::unique_ptr<Botan::Private_Key> key(
                  keygen_timer->run([&] { return Botan::create_private_key("SPHINCS+", rng(), params); }));

               record_result(keygen_timer);
               if(bench_pk_sig(*key, params, provider, "", msec) == 1) {
                  break;
               }
            } catch(Botan::Not_Implemented&) {
               continue;
            }
         }
      }
#endif

#if defined(BOTAN_HAS_FRODOKEM)
      void bench_frodokem(const std::string& provider, std::chrono::milliseconds msec) {
         std::vector<Botan::FrodoKEMMode> frodo_modes{
            Botan::FrodoKEMMode::FrodoKEM640_SHAKE,
            Botan::FrodoKEMMode::FrodoKEM976_SHAKE,
            Botan::FrodoKEMMode::FrodoKEM1344_SHAKE,
            Botan::FrodoKEMMode::eFrodoKEM640_SHAKE,
            Botan::FrodoKEMMode::eFrodoKEM976_SHAKE,
            Botan::FrodoKEMMode::eFrodoKEM1344_SHAKE,
            Botan::FrodoKEMMode::FrodoKEM640_AES,
            Botan::FrodoKEMMode::FrodoKEM976_AES,
            Botan::FrodoKEMMode::FrodoKEM1344_AES,
            Botan::FrodoKEMMode::eFrodoKEM640_AES,
            Botan::FrodoKEMMode::eFrodoKEM976_AES,
            Botan::FrodoKEMMode::eFrodoKEM1344_AES,
         };

         for(auto modet : frodo_modes) {
            if(!modet.is_available()) {
               continue;
            }

            Botan::FrodoKEMMode mode(modet);

            auto keygen_timer = make_timer(mode.to_string(), provider, "keygen");

            auto key = keygen_timer->run([&] { return Botan::FrodoKEM_PrivateKey(rng(), mode); });

            record_result(keygen_timer);

            bench_pk_kem(key, mode.to_string(), provider, "KDF2(SHA-256)", msec);
         }
      }
#endif

#if defined(BOTAN_HAS_XMSS_RFC8391)
      void bench_xmss(const std::string& provider, std::chrono::milliseconds msec) {
         /*
         We only test H10 signatures here since already they are quite slow (a
         few seconds per signature). On a fast machine, H16 signatures take 1-2
         minutes to generate and H20 signatures take 5-10 minutes to generate
         */
         std::vector<std::string> xmss_params{
            "XMSS-SHA2_10_256",
            "XMSS-SHAKE_10_256",
            "XMSS-SHA2_10_512",
            "XMSS-SHAKE_10_512",
         };

         for(std::string params : xmss_params) {
            auto keygen_timer = make_timer(params, provider, "keygen");

            std::unique_ptr<Botan::Private_Key> key(
               keygen_timer->run([&] { return Botan::create_private_key("XMSS", rng(), params); }));

            record_result(keygen_timer);
            if(bench_pk_sig(*key, params, provider, "", msec) == 1) {
               break;
            }
         }
      }
#endif

#if defined(BOTAN_HAS_HSS_LMS)
      void bench_hss_lms(const std::string& provider, std::chrono::milliseconds msec) {
         // At first we compare instances with multiple hash functions. LMS trees with
         // height 10 are suitable, since they can be used for enough signatures and are
         // fast enough for speed testing.
         // Afterward, setups with multiple HSS layers are tested
         std::vector<std::string> hss_lms_instances{"SHA-256,HW(10,1)",
                                                    "SHAKE-256(256),HW(10,1)",
                                                    "SHAKE-256(192),HW(10,1)",
                                                    "Truncated(SHA-256,192),HW(10,1)",
                                                    "SHA-256,HW(10,1),HW(10,1)",
                                                    "SHA-256,HW(10,1),HW(10,1),HW(10,1)"};

         for(const auto& params : hss_lms_instances) {
            auto keygen_timer = make_timer(params, provider, "keygen");

            std::unique_ptr<Botan::Private_Key> key(
               keygen_timer->run([&] { return Botan::create_private_key("HSS-LMS", rng(), params); }));

            record_result(keygen_timer);
            if(bench_pk_sig(*key, params, provider, "", msec) == 1) {
               break;
            }
         }
      }
#endif

#if defined(BOTAN_HAS_ZFEC)
      void bench_zfec(std::chrono::milliseconds msec) {
         const size_t k = 4;
         const size_t n = 16;

         Botan::ZFEC zfec(k, n);

         const size_t share_size = 256 * 1024;

         std::vector<uint8_t> input(share_size * k);
         rng().randomize(input.data(), input.size());

         std::vector<uint8_t> output(share_size * n);

         auto enc_fn = [&](size_t share, const uint8_t buf[], size_t len) {
            std::memcpy(&output[share * share_size], buf, len);
         };

         auto enc_timer =
            make_timer("zfec " + std::to_string(k) + "/" + std::to_string(n), input.size(), "encode", "", input.size());

         enc_timer->run_until_elapsed(msec, [&]() { zfec.encode(input.data(), input.size(), enc_fn); });

         record_result(enc_timer);

         auto dec_timer =
            make_timer("zfec " + std::to_string(k) + "/" + std::to_string(n), input.size(), "decode", "", input.size());

         std::map<size_t, const uint8_t*> shares;
         for(size_t i = 0; i != n; ++i) {
            shares[i] = &output[share_size * i];
         }

         // remove data shares to make decoding maximally expensive:
         while(shares.size() != k) {
            shares.erase(shares.begin());
         }

         std::vector<uint8_t> recovered(share_size * k);

         auto dec_fn = [&](size_t share, const uint8_t buf[], size_t len) {
            std::memcpy(&recovered[share * share_size], buf, len);
         };

         dec_timer->run_until_elapsed(msec, [&]() { zfec.decode_shares(shares, share_size, dec_fn); });

         record_result(dec_timer);

         if(recovered != input) {
            error_output() << "ZFEC recovery failed\n";
         }
      }

#endif

#if defined(BOTAN_HAS_POLY_DBL)
      void bench_poly_dbl(std::chrono::milliseconds msec) {
         for(size_t sz : {8, 16, 24, 32, 64, 128}) {
            auto be_timer = make_timer("poly_dbl_be_" + std::to_string(sz));
            auto le_timer = make_timer("poly_dbl_le_" + std::to_string(sz));

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

      void bench_bcrypt() {
         const std::string password = "not a very good password";

         for(uint8_t work_factor = 4; work_factor <= 14; ++work_factor) {
            auto timer = make_timer("bcrypt wf=" + std::to_string(work_factor));

            timer->run([&] { Botan::generate_bcrypt(password, rng(), work_factor); });

            record_result(timer);
         }
      }
#endif

#if defined(BOTAN_HAS_PASSHASH9)

      void bench_passhash9() {
         const std::string password = "not a very good password";

         for(uint8_t alg = 0; alg <= 4; ++alg) {
            if(Botan::is_passhash9_alg_supported(alg) == false) {
               continue;
            }

            for(auto work_factor : {10, 15}) {
               auto timer = make_timer("passhash9 alg=" + std::to_string(alg) + " wf=" + std::to_string(work_factor));

               timer->run([&] { Botan::generate_passhash9(password, rng(), static_cast<uint8_t>(work_factor), alg); });

               record_result(timer);
            }
         }
      }
#endif

#if defined(BOTAN_HAS_SCRYPT)

      void bench_scrypt(const std::string& /*provider*/, std::chrono::milliseconds msec) {
         auto pwdhash_fam = Botan::PasswordHashFamily::create_or_throw("Scrypt");

         for(size_t N : {8192, 16384, 32768, 65536}) {
            for(size_t r : {1, 8, 16}) {
               for(size_t p : {1}) {
                  auto pwdhash = pwdhash_fam->from_params(N, r, p);

                  auto scrypt_timer =
                     make_timer("scrypt-" + std::to_string(N) + "-" + std::to_string(r) + "-" + std::to_string(p) +
                                " (" + std::to_string(pwdhash->total_memory_usage() / (1024 * 1024)) + " MiB)");

                  uint8_t out[64];
                  uint8_t salt[8];
                  rng().randomize(salt, sizeof(salt));

                  while(scrypt_timer->under(msec)) {
                     scrypt_timer->run([&] {
                        pwdhash->derive_key(out, sizeof(out), "password", 8, salt, sizeof(salt));

                        Botan::copy_mem(salt, out, 8);
                     });
                  }

                  record_result(scrypt_timer);

                  if(scrypt_timer->events() == 1) {
                     break;
                  }
               }
            }
         }
      }

#endif

#if defined(BOTAN_HAS_ARGON2)

      void bench_argon2(const std::string& /*provider*/, std::chrono::milliseconds msec) {
         auto pwhash_fam = Botan::PasswordHashFamily::create_or_throw("Argon2id");

         for(size_t M : {8 * 1024, 64 * 1024, 256 * 1024}) {
            for(size_t t : {1, 4}) {
               for(size_t p : {1, 4}) {
                  auto pwhash = pwhash_fam->from_params(M, t, p);
                  auto timer = make_timer(pwhash->to_string());

                  uint8_t out[64];
                  uint8_t salt[16];
                  rng().randomize(salt, sizeof(salt));

                  while(timer->under(msec)) {
                     timer->run([&] { pwhash->derive_key(out, sizeof(out), "password", 8, salt, sizeof(salt)); });
                  }

                  record_result(timer);
               }
            }
         }
      }

#endif
};

BOTAN_REGISTER_COMMAND("speed", Speed);

}  // namespace Botan_CLI
