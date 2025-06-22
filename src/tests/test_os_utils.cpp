/*
* Testing operating system specific wrapper code
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_OS_UTILS)
   #include <botan/internal/os_utils.h>
   #include <botan/internal/target_info.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_OS_UTILS)

namespace {

/*
uint32_t get_process_id();
uint64_t get_cpu_cycle_counter();
uint64_t get_system_timestamp_ns();
size_t get_memory_locking_limit();
void* allocate_locked_pages(size_t length);
void free_locked_pages(void* ptr, size_t length);
int run_cpu_instruction_probe(std::function<int ()> probe_fn);
*/

class OS_Utils_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         results.push_back(test_get_process_id());
         results.push_back(test_get_cpu_cycle_counter());
         results.push_back(test_get_high_resolution_clock());
         results.push_back(test_get_cpu_numbers());
         results.push_back(test_get_system_timestamp());
         results.push_back(test_memory_locking());
         results.push_back(test_cpu_instruction_probe());

         return results;
      }

   private:
      static Test::Result test_get_process_id() {
         Test::Result result("OS::get_process_id");

         uint32_t pid1 = Botan::OS::get_process_id();
         uint32_t pid2 = Botan::OS::get_process_id();

         result.test_eq("PID same across calls", static_cast<size_t>(pid1), static_cast<size_t>(pid2));

   #if defined(BOTAN_TARGET_OS_IS_LLVM) || defined(BOTAN_TARGET_OS_IS_NONE)
         result.test_eq("PID is expected to be zero on this platform", pid1, size_t(0));
   #else
         result.test_ne("PID is non-zero on systems with processes", pid1, 0);
   #endif

         return result;
      }

      static Test::Result test_get_cpu_cycle_counter() {
         const size_t max_trials = 1024;
         const size_t max_repeats = 32;

         Test::Result result("OS::get_cpu_cycle_counter");

         const uint64_t proc_ts1 = Botan::OS::get_cpu_cycle_counter();

         if(proc_ts1 == 0) {
            const uint64_t proc_ts2 = Botan::OS::get_cpu_cycle_counter();
            result.test_is_eq("Disabled processor timestamp stays at zero", proc_ts1, proc_ts2);
            return result;
         }

         size_t counts = 0;
         while(counts < max_trials && (Botan::OS::get_cpu_cycle_counter() == proc_ts1)) {
            ++counts;
         }

         result.test_lt("CPU cycle counter eventually changes value", counts, max_repeats);

         return result;
      }

      static Test::Result test_get_high_resolution_clock() {
         Test::Result result("OS::get_high_resolution_clock");

         // Basic functionality test
         const uint64_t first_hrc = Botan::OS::get_high_resolution_clock();
         result.confirm("High resolution timestamp value is never zero", first_hrc != 0);

         // Non-decreasing check monotonic
         std::array<uint64_t, 100 /* sample count */> timestamps{};
         for(std::size_t i = 0; i < timestamps.size(); ++i) {
            timestamps[i] = Botan::OS::get_high_resolution_clock();

            if(i < timestamps.size() - 1) {  // No sleep last time
               std::this_thread::sleep_for(std::chrono::microseconds(100));
            }
         }

         const bool is_monotonic = std::is_sorted(timestamps.begin(), timestamps.end());
         result.confirm("Clock values are monotonic", is_monotonic);
         result.confirm("Clock values show progression", timestamps.front() != timestamps.back());
         return result;
      }

      static Test::Result test_get_cpu_numbers() {
         Test::Result result("OS::get_cpu_available");

         const size_t ta = Botan::OS::get_cpu_available();

         result.test_gte("get_cpu_available is at least 1", ta, 1);

         return result;
      }

      static Test::Result test_get_system_timestamp() {
         Test::Result result("OS::get_system_timestamp_ns");

         // Basic functionality test
         const uint64_t first_timestamp = Botan::OS::get_system_timestamp_ns();
         result.confirm("Timestamp is non-zero", first_timestamp != 0);

         // Sanity check
         const auto epoch_2020 = std::chrono::sys_days{std::chrono::year{2020} / 1 / 1};
         const auto epoch_2020_ns = duration_cast<std::chrono::nanoseconds>(epoch_2020.time_since_epoch()).count();
         result.test_gte("Timestamp after Jan 1, 2020", first_timestamp, static_cast<uint64_t>(epoch_2020_ns));

         // Non-decreasing check
         std::array<uint64_t, 100 /* sample_count */> timestamps{};
         for(std::size_t i = 0; i < timestamps.size(); ++i) {
            timestamps[i] = Botan::OS::get_system_timestamp_ns();
            if(i < timestamps.size() - 1) {  // No sleep last time
               std::this_thread::sleep_for(std::chrono::microseconds(100));
            }
         }

         bool is_non_decreasing = std::is_sorted(timestamps.begin(), timestamps.end());
         result.confirm("Clock values are monotonic", is_non_decreasing);
         result.confirm("Clock values show progression", timestamps.front() != timestamps.back());
         return result;
      }

      static Test::Result test_memory_locking() {
         Test::Result result("OS memory locked pages");

         // TODO any tests...

         return result;
      }

      static Test::Result test_cpu_instruction_probe() {
         Test::Result result("OS::run_cpu_instruction_probe");

         // OS::run_cpu_instruction_probe only implemented for Unix signals or Windows SEH

         std::function<int()> ok_fn = []() noexcept -> int { return 5; };
         const int run_rc = Botan::OS::run_cpu_instruction_probe(ok_fn);

         if(run_rc == -3) {
            result.test_note("run_cpu_instruction_probe not implemented on this platform");
            return {result};
         }

         result.confirm("Correct result returned by working probe fn", run_rc == 5);

         std::function<int()> crash_probe;

   #if defined(BOTAN_USE_GCC_INLINE_ASM)

      #if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)
         crash_probe = []() noexcept -> int {
            asm volatile("ud2");
            return 3;
         };

      #elif defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY)
         //ARM: asm volatile (".word 0xf7f0a000\n");
         // illegal instruction in both ARM and Thumb modes
         crash_probe = []() noexcept -> int {
            asm volatile(".word 0xe7f0def0\n");
            return 3;
         };

      #else
               /*
         PPC: "The instruction with primary opcode 0, when the instruction does not consist
         entirely of binary zeros"
         Others ?
         */
      #endif

   #endif

         if(crash_probe) {
            const int crash_rc = Botan::OS::run_cpu_instruction_probe(crash_probe);
            result.confirm("Result for function executing undefined opcode", crash_rc < 0);
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("utils", "os_utils", OS_Utils_Tests);

}  // namespace

#endif

}  // namespace Botan_Tests
