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
   #include <botan/internal/time_utils.h>
   #include <chrono>
#endif

#if defined(BOTAN_TARGET_OS_HAS_THREADS)
   #include <thread>
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
         results.push_back(test_get_thread_cpu_time());
         results.push_back(test_measure_cost());
         results.push_back(test_memory_locking());
         results.push_back(test_cpu_instruction_probe());

         return results;
      }

   private:
      static Test::Result test_get_process_id() {
         Test::Result result("OS::get_process_id");

         const uint32_t pid1 = Botan::OS::get_process_id();
         const uint32_t pid2 = Botan::OS::get_process_id();

         result.test_u32_eq("PID same across calls", pid1, pid2);

   #if defined(BOTAN_TARGET_OS_IS_LLVM) || defined(BOTAN_TARGET_OS_IS_NONE)
         result.test_u32_eq("PID is expected to be zero on this platform", pid1, 0);
   #else
         result.test_sz_ne("PID is non-zero on systems with processes", pid1, 0);
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
            result.test_u64_eq("Disabled processor timestamp stays at zero", proc_ts1, proc_ts2);
            return result;
         }

         size_t counts = 0;
         while(counts < max_trials && (Botan::OS::get_cpu_cycle_counter() == proc_ts1)) {
            ++counts;
         }

         result.test_sz_lt("CPU cycle counter eventually changes value", counts, max_repeats);

         return result;
      }

      static Test::Result test_get_high_resolution_clock() {
         // We can easily test progression; however, testing precision is trickier.
         // On very fast machines with very low clock resolution (like the web platform offers),
         // it may be necessary to make the call quite a few times to notice any change.
         constexpr auto max_trials = 32768;

         Test::Result result("OS::get_high_resolution_clock");

         // TODO better tests
         const auto hr_ts1 = Botan::OS::get_high_resolution_clock();
         result.test_is_true("high resolution timestamp value is never zero", hr_ts1 != 0);

         for(size_t trials = 0; trials < max_trials; ++trials) {
            if(hr_ts1 < Botan::OS::get_high_resolution_clock()) {
               result.test_success("high resolution clock made forward progress");
               return result;
            }
         }

         result.test_failure("high resolution clock didn't make forward progress, even after many trials");

         return result;
      }

      static Test::Result test_get_cpu_numbers() {
         Test::Result result("OS::get_cpu_available");

         const size_t ta = Botan::OS::get_cpu_available();

         result.test_sz_gte("get_cpu_available is at least 1", ta, 1);

         return result;
      }

      static Test::Result test_get_system_timestamp() {
         // TODO better tests
         Test::Result result("OS::get_system_timestamp_ns");

         const uint64_t sys_ts1 = Botan::OS::get_system_timestamp_ns();
         result.test_is_true("System timestamp value is never zero", sys_ts1 != 0);

         // do something that consumes a little time
         Botan::OS::get_process_id();

         const uint64_t sys_ts2 = Botan::OS::get_system_timestamp_ns();

         result.test_is_true("System time moves forward", sys_ts1 <= sys_ts2);

         return result;
      }

      // A little CPU work whose result is observed so it cannot be optimized away
      static uint64_t burn_cpu(uint64_t x, size_t rounds) {
         for(size_t i = 0; i != rounds; ++i) {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
         }
         return x;
      }

      static uint64_t steady_clock_ns() {
         const auto now = std::chrono::steady_clock::now().time_since_epoch();
         return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(now).count());
      }

      static Test::Result test_get_thread_cpu_time() {
         Test::Result result("OS::get_thread_cpu_time_ns");

         const auto cpu_ts1 = Botan::OS::get_thread_cpu_time_ns();

         if(!cpu_ts1.has_value()) {
            result.test_note("Thread CPU time not available on this platform");
            return result;
         }

         const uint64_t wall_start = steady_clock_ns();
         uint64_t state = 0x9E3779B97F4A7C15;
         while(steady_clock_ns() - wall_start < 2000000) {
            state = burn_cpu(state, 1000);
         }
         const uint64_t wall_elapsed = steady_clock_ns() - wall_start;
         result.test_is_true("Work loop produced a value", state != 0);

         const auto cpu_ts2 = Botan::OS::get_thread_cpu_time_ns();
         result.test_is_true("Thread CPU time remains available", cpu_ts2.has_value());

         if(cpu_ts2.has_value()) {
            result.test_is_true("Thread CPU time advances while busy", *cpu_ts2 > *cpu_ts1);
            result.test_is_true("Thread CPU time does not exceed wall time",
                                (*cpu_ts2 - *cpu_ts1) <= wall_elapsed + 1000000);
         }

   #if defined(BOTAN_TARGET_OS_HAS_THREADS)
         const auto cpu_ts3 = Botan::OS::get_thread_cpu_time_ns();
         std::this_thread::sleep_for(std::chrono::milliseconds(20));
         const auto cpu_ts4 = Botan::OS::get_thread_cpu_time_ns();

         if(cpu_ts3.has_value() && cpu_ts4.has_value()) {
            result.test_is_true("Thread CPU time barely advances while sleeping", (*cpu_ts4 - *cpu_ts3) < 5000000);
         }
   #endif

         return result;
      }

      static Test::Result test_measure_cost() {
         Test::Result result("measure_cost");

         size_t calls = 0;
         uint64_t state = 0x9E3779B97F4A7C15;
         auto fn = [&]() {
            calls += 1;
            state = burn_cpu(state, 20000);
         };

         const uint64_t cost = Botan::measure_cost(0, fn);
         result.test_sz_gte("Minimum number of samples taken even with no time budget", calls, 3);
         result.test_is_true("Cost estimate is nonzero", cost > 0);

         calls = 0;
         const uint64_t wall_start = steady_clock_ns();
         const uint64_t cost2 = Botan::measure_cost(5, fn);
         const uint64_t wall_elapsed = steady_clock_ns() - wall_start;

         result.test_is_true("Tuning loop ran for at least the requested time", wall_elapsed >= 5000000);
         result.test_is_true("Several samples taken", calls >= 3);
         result.test_is_true("Cost estimate is nonzero", cost2 > 0);
         result.test_is_true("Cost estimate is below wall time of the loop", cost2 < wall_elapsed);
         result.test_is_true("Work loop produced a value", state != 0);

         return result;
      }

      static Test::Result test_memory_locking() {
         Test::Result result("OS memory locked pages");

         // TODO any tests...

         return result;
      }

      static Test::Result test_cpu_instruction_probe() {
         Test::Result result("OS::run_cpu_instruction_probe");

         // OS::run_cpu_instruction_probe is only implemented on systems supporting Unix-style signals

         const std::function<int()> ok_fn = []() noexcept -> int { return 5; };
         const int run_rc = Botan::OS::run_cpu_instruction_probe(ok_fn);

         if(run_rc == -3) {
            result.test_note("run_cpu_instruction_probe not implemented on this platform");
            return {result};
         }

         result.test_is_true("Correct result returned by working probe fn", run_rc == 5);

         std::function<int()> crash_probe;

   #if defined(BOTAN_USE_GCC_INLINE_ASM)

      #if defined(BOTAN_TARGET_ARCH_IS_X86_FAMILY)
         crash_probe = []() noexcept -> int {
            asm volatile("ud2");  // NOLINT(*-no-assembler)
            return 3;
         };

      #elif defined(BOTAN_TARGET_ARCH_IS_ARM_FAMILY)
         //ARM: asm volatile (".word 0xf7f0a000\n");
         // illegal instruction in both ARM and Thumb modes
         crash_probe = []() noexcept -> int {
            asm volatile(".word 0xe7f0def0\n");  // NOLINT(*-no-assembler)
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
            result.test_is_true("Result for function executing undefined opcode", crash_rc < 0);
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("utils", "os_utils", OS_Utils_Tests);

}  // namespace

#endif

}  // namespace Botan_Tests
