/*
* Testing operating system specific wrapper code
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include <botan/internal/os_utils.h>
#include <thread>

// For __ud2 intrinsic
#if defined(BOTAN_TARGET_COMPILER_IS_MSVC)
   #include <intrin.h>
#endif

namespace Botan_Tests {

namespace {

/*
uint32_t get_process_id();
uint64_t get_processor_timestamp();
uint64_t get_system_timestamp_ns();
size_t get_memory_locking_limit();
void* allocate_locked_pages(size_t length);
void free_locked_pages(void* ptr, size_t length);
int run_cpu_instruction_probe(std::function<int ()> probe_fn);
*/

class OS_Utils_Tests : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;

         results.push_back(test_get_process_id());
         results.push_back(test_get_processor_timestamp());
         results.push_back(test_get_high_resolution_clock());
         results.push_back(test_get_system_timestamp());
         results.push_back(test_memory_locking());
         results.push_back(test_cpu_instruction_probe());

         return results;
         }

   private:

      Test::Result test_get_process_id()
         {
         Test::Result result("OS::get_process_id");

         uint32_t pid1 = Botan::OS::get_process_id();
         uint32_t pid2 = Botan::OS::get_process_id();

         result.test_eq("PID same across calls", static_cast<size_t>(pid1), static_cast<size_t>(pid2));

#if defined(BOTAN_TARGET_OS_TYPE_IS_UNIKERNEL)
         result.test_eq("PID is zero on unikernel systems", pid1, 0);
#else
         result.test_ne("PID is non-zero on systems with processes", pid1, 0);
#endif

         return result;
         }

      Test::Result test_get_processor_timestamp()
         {
         // TODO better tests
         Test::Result result("OS::get_processor_timestamp");

         const uint64_t proc_ts1 = Botan::OS::get_processor_timestamp();

         // do something that consumes a little time
         std::this_thread::sleep_for(std::chrono::milliseconds(50));

         uint64_t proc_ts2 = Botan::OS::get_processor_timestamp();

         if(proc_ts1 == 0)
            {
            result.test_is_eq("Disabled processor timestamp stays at zero", proc_ts1, proc_ts2);
            }
         else
            {
            result.confirm("Processor timestamp does not duplicate", proc_ts1 != proc_ts2);
            }

         return result;
         }

      Test::Result test_get_high_resolution_clock()
         {
         // TODO better tests

         Test::Result result("OS::get_high_resolution_clock");

         uint64_t hr_ts1 = Botan::OS::get_high_resolution_clock();
         result.test_ne("high resolution timestamp value is never zero", hr_ts1, 0);

         // do something that consumes a little time
         Botan::OS::get_process_id();

         uint64_t hr_ts2 = Botan::OS::get_high_resolution_clock();

         result.test_ne("high resolution timestamp does not duplicate", hr_ts1, hr_ts2);
         return result;
         }

      Test::Result test_get_system_timestamp()
         {
         // TODO better tests
         Test::Result result("OS::get_system_timestamp_ns");

         uint64_t sys_ts1 = Botan::OS::get_system_timestamp_ns();
         result.test_ne("System timestamp value is never zero", sys_ts1, 0);

         // do something that consumes a little time
         Botan::OS::get_process_id();

         uint64_t sys_ts2 = Botan::OS::get_system_timestamp_ns();

         result.confirm("System time moves forward", sys_ts1 <= sys_ts2);

         return result;
         }

      Test::Result test_memory_locking()
         {
         Test::Result result("OS memory locked pages");

         // TODO any tests...

         return result;
         }

      Test::Result test_cpu_instruction_probe()
         {
         Test::Result result("OS::run_cpu_instruction_probe");

         // OS::run_cpu_instruction_probe only implemented for Unix signals or Windows SEH

         std::function<int ()> ok_fn = []() -> int { return 5; };
         const int run_rc = Botan::OS::run_cpu_instruction_probe(ok_fn);

         if(run_rc == -3)
            {
            result.test_note("run_cpu_instruction_probe not implemented on this platform");
            return {result};
            }

         result.confirm("Correct result returned by working probe fn", run_rc == 5);

         std::function<int ()> crash_probe;

#if defined(BOTAN_TARGET_COMPILER_IS_MSVC)
         crash_probe = []() -> int { __ud2(); return 3; };

#elif defined(BOTAN_USE_GCC_INLINE_ASM)

#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)
         crash_probe = []() -> int { asm volatile("ud2"); return 3; };

#elif defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY)
         //ARM: asm volatile (".word 0xf7f0a000\n");
         // illegal instruction in both ARM and Thumb modes
         crash_probe = []() -> int { asm volatile(".word 0xe7f0def0\n"); return 3; };

#else
         /*
         PPC: "The instruction with primary opcode 0, when the instruction does not consist
         entirely of binary zeros"
         Others ?
         */
#endif

#endif

         if(crash_probe)
            {
            const int crash_rc = Botan::OS::run_cpu_instruction_probe(crash_probe);
            result.confirm("Result for function executing undefined opcode", crash_rc < 0);
            }

         return result;
         }
   };

BOTAN_REGISTER_TEST("os_utils", OS_Utils_Tests);

}

}
