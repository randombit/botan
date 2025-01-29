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
#include <iomanip>
#include <map>
#include <set>
#include <sstream>

// Always available:
#include <botan/version.h>
#include <botan/internal/cpuid.h>
#include <botan/internal/fmt.h>
#include <botan/internal/stl_util.h>

#if defined(BOTAN_HAS_OS_UTILS)
   #include <botan/internal/os_utils.h>
#endif

#if defined(BOTAN_HAS_ECC_GROUP)
   #include <botan/ec_group.h>
#endif

namespace Botan_CLI {

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

std::string format_timer(const Timer& t, size_t time_unit) {
   constexpr size_t MiB = 1024 * 1024;

   std::ostringstream oss;

   oss << t.get_name() << " ";

   const uint64_t events = t.events();

   if(t.buf_size() == 0) {
      // Report operations/time unit

      if(events == 0) {
         oss << "no events ";
      } else {
         oss << static_cast<uint64_t>(t.events_per_second()) << ' ' << t.doing() << "/sec; ";

         if(time_unit == 1000) {
            oss << std::setprecision(2) << std::fixed << (t.milliseconds() / events) << " ms/op ";
         } else if(time_unit == 1000 * 1000) {
            oss << std::setprecision(2) << std::fixed << (t.microseconds() / events) << " us/op ";
         } else if(time_unit == 1000 * 1000 * 1000) {
            oss << std::setprecision(0) << std::fixed << (t.nanoseconds() / events) << " ns/op ";
         }

         if(t.cycles_consumed() != 0 && events > 0) {
            const double cycles_per_op = static_cast<double>(t.cycles_consumed()) / events;
            const int precision = (cycles_per_op < 10000) ? 2 : 0;
            oss << std::fixed << std::setprecision(precision) << cycles_per_op << " cycles/op ";
         }

         oss << "(" << events << " " << (events == 1 ? "op" : "ops") << " in " << t.milliseconds() << " ms)";
      }
   } else {
      // Bulk op - report bytes/time unit

      const double MiB_total = static_cast<double>(events) / MiB;
      const double MiB_per_sec = MiB_total / t.seconds();

      if(!t.doing().empty()) {
         oss << t.doing() << " ";
      }

      if(t.buf_size() > 0) {
         oss << "buffer size " << t.buf_size() << " bytes: ";
      }

      if(events == 0) {
         oss << "N/A ";
      } else {
         oss << std::fixed << std::setprecision(3) << MiB_per_sec << " MiB/sec ";
      }

      if(t.cycles_consumed() != 0 && events > 0) {
         const double cycles_per_byte = static_cast<double>(t.cycles_consumed()) / events;
         oss << std::fixed << std::setprecision(2) << cycles_per_byte << " cycles/byte ";
      }

      oss << "(" << MiB_total << " MiB in " << t.milliseconds() << " ms)";
   }

   return oss.str();
}

}  // namespace

class Speed final : public Command {
   public:
      Speed() :
            Command(
               "speed --msec=500 --format=default --time-unit=ms --ecc-groups= --buf-size=1024 --clear-cpuid= --cpu-clock-speed=0 --cpu-clock-ratio=1.0 *algos") {
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
            "ML-KEM",
            "ML-DSA",
            "SLH-DSA",
            "FrodoKEM",
            "HSS-LMS",
         };
         // clang-format on
      }

      std::string group() const override { return "misc"; }

      std::string description() const override { return "Measures the speed of algorithms"; }

      void go() override {
         std::chrono::milliseconds msec(get_arg_sz("msec"));
         std::vector<std::string> ecc_groups = Command::split_on(get_arg("ecc-groups"), ',');
         const std::string format = get_arg("format");
         const std::string clock_ratio = get_arg("cpu-clock-ratio");

         const size_t clock_speed = get_arg_sz("cpu-clock-speed");

         double clock_cycle_ratio = std::strtod(clock_ratio.c_str(), nullptr);

         m_time_unit = [](std::string_view tu) {
            if(tu == "ms") {
               return 1000;
            } else if(tu == "us") {
               return 1000 * 1000;
            } else if(tu == "ns") {
               return 1000 * 1000 * 1000;
            } else {
               throw CLI_Usage_Error("Unknown time unit (supported: ms, us, ns)");
            }
         }(get_arg("time-unit"));

         /*
         * This argument is intended to be the ratio between the cycle counter
         * and the actual machine cycles. It is extremely unlikely that there is
         * any machine where the cycle counter increments faster than the actual
         * clock.
         */
         if(clock_cycle_ratio < 0.0 || clock_cycle_ratio > 1.0) {
            throw CLI_Usage_Error("Unlikely CPU clock ratio of " + clock_ratio);
         }

         clock_cycle_ratio = 1.0 / clock_cycle_ratio;

#if defined(BOTAN_HAS_OS_UTILS)
         if(clock_speed != 0 && Botan::OS::get_cpu_cycle_counter() != 0) {
            error_output() << "The --cpu-clock-speed option is only intended to be used on "
                              "platforms without access to a cycle counter.\n"
                              "Expect incorrect results\n\n";
         }
#endif

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

         PerfConfig perf_config([&](const Timer& t) { this->record_result(t); },
                                clock_speed,
                                clock_cycle_ratio,
                                msec,
                                ecc_groups,
                                buf_sizes,
                                this->error_output(),
                                this->rng());

         for(const auto& algo : algos) {
            if(auto perf = PerfTest::get(algo)) {
               perf->go(perf_config);
            } else if(verbose() || !using_defaults) {
               error_output() << "Unknown algorithm '" << algo << "'\n";
            }
         }

         if(m_json) {
            output() << m_json->print();
         }
         if(m_summary) {
            output() << m_summary->print() << "\n";
         }

         if(verbose() && clock_speed == 0 && m_cycles_consumed > 0 && m_ns_taken > 0) {
            const double seconds = static_cast<double>(m_ns_taken) / 1000000000;
            const double Hz = static_cast<double>(m_cycles_consumed) / seconds;
            const double MHz = Hz / 1000000;
            output() << "\nEstimated clock speed " << MHz << " MHz\n";
         }
      }

   private:
      size_t m_time_unit = 0;
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
            output() << format_timer(t, m_time_unit) << std::endl;

            if(m_summary) {
               m_summary->add(t);
            }
         }
      }
};

BOTAN_REGISTER_COMMAND("speed", Speed);

}  // namespace Botan_CLI
