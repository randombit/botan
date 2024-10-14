/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CLI_PERF_H_
#define BOTAN_CLI_PERF_H_

#include <botan/rng.h>
#include <botan/internal/fmt.h>
#include <botan/internal/timer.h>
#include <chrono>
#include <functional>
#include <iosfwd>
#include <map>
#include <string>

namespace Botan_CLI {

class PerfConfig {
   public:
      virtual ~PerfConfig() = default;

      virtual std::chrono::milliseconds runtime() const = 0;

      virtual const std::vector<std::string>& ecc_groups() const = 0;

      virtual const std::vector<size_t>& buffer_sizes() const = 0;

      virtual std::ostream& error_output() const = 0;

      virtual Botan::RandomNumberGenerator& rng() const = 0;

      virtual void record_result(const Botan::Timer& timer) const = 0;

      virtual std::unique_ptr<Botan::Timer> make_timer(const std::string& alg,
                                                       uint64_t event_mult = 1,
                                                       const std::string& what = "",
                                                       const std::string& provider = "",
                                                       size_t buf_size = 0) const = 0;
};

class PerfTest {
   public:
      virtual ~PerfTest() = default;

      // Returns nullptr if unknown / not available
      static std::unique_ptr<PerfTest> get(const std::string& alg);

      virtual void go(const PerfConfig& config) = 0;

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
