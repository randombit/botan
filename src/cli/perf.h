/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CLI_PERF_H_
#define BOTAN_CLI_PERF_H_

#include <botan/rng.h>
#include <botan/internal/fmt.h>
#include <chrono>
#include <functional>
#include <iosfwd>
#include <map>
#include <string>

#include "timer.h"

namespace Botan_CLI {

class PerfConfig final {
   public:
      PerfConfig(std::function<void(const Timer&)> record_result,
                 size_t clock_speed,
                 double clock_cycle_ratio,
                 std::chrono::milliseconds runtime,
                 const std::vector<std::string>& ecc_groups,
                 const std::vector<size_t>& buffer_sizes,
                 std::ostream& error_output,
                 Botan::RandomNumberGenerator& rng) :
            m_record_result(std::move(record_result)),
            m_clock_speed(clock_speed),
            m_clock_cycle_ratio(clock_cycle_ratio),
            m_runtime(runtime),
            m_ecc_groups(ecc_groups),
            m_buffer_sizes(buffer_sizes),
            m_error_output(error_output),
            m_rng(rng) {}

      const std::vector<size_t>& buffer_sizes() const { return m_buffer_sizes; }

      const std::vector<std::string>& ecc_groups() const { return m_ecc_groups; }

      std::chrono::milliseconds runtime() const { return m_runtime; }

      std::ostream& error_output() const { return m_error_output; }

      Botan::RandomNumberGenerator& rng() const { return m_rng; }

      void record_result(const Timer& timer) const { m_record_result(timer); }

      std::unique_ptr<Timer> make_timer(const std::string& alg,
                                        uint64_t event_mult = 1,
                                        const std::string& what = "",
                                        const std::string& provider = "",
                                        size_t buf_size = 0) const {
         return std::make_unique<Timer>(alg, provider, what, event_mult, buf_size, m_clock_cycle_ratio, m_clock_speed);
      }

   private:
      std::function<void(const Timer&)> m_record_result;
      size_t m_clock_speed = 0;
      double m_clock_cycle_ratio = 0.0;
      std::chrono::milliseconds m_runtime;
      std::vector<std::string> m_ecc_groups;
      std::vector<size_t> m_buffer_sizes;
      std::ostream& m_error_output;
      Botan::RandomNumberGenerator& m_rng;
};

class PerfTest {
   public:
      virtual ~PerfTest() = default;

      // Returns nullptr if unknown / not available
      static std::unique_ptr<PerfTest> get(const std::string& alg);

      virtual void go(const PerfConfig& config) = 0;

      virtual std::string format_name(const std::string& alg, const std::string& param) const;

      typedef std::function<std::unique_ptr<PerfTest>()> pt_maker_fn;

      class Registration final {
         public:
            Registration(const std::string& name, const std::function<std::unique_ptr<PerfTest>()>& maker_fn);
      };

   private:
      static std::unique_ptr<PerfTest> get_sym(const std::string& alg);

      static std::map<std::string, pt_maker_fn>& global_registry();
};

#define BOTAN_REGISTER_PERF_TEST(name, Perf_Class)                \
   const Botan_CLI::PerfTest::Registration reg_perf_##Perf_Class( \
      name, []() -> std::unique_ptr<Botan_CLI::PerfTest> { return std::make_unique<Perf_Class>(); })

}  // namespace Botan_CLI

#endif
