/*
* OS and machine specific utility functions
* (C) 2015,2016,2017,2018 Jack Lloyd
* (C) 2016 Daniel Neus
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/os_utils.h>

#include <botan/exceptn.h>
#include <botan/mem_ops.h>
#include <botan/internal/target_info.h>

#if defined(BOTAN_HAS_CPUID)
   #include <botan/internal/cpuid.h>
#endif

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <iomanip>
#include <sstream>

#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   #include <errno.h>
   #include <pthread.h>
   #include <setjmp.h>
   #include <signal.h>
   #include <stdlib.h>
   #include <sys/mman.h>
   #include <sys/resource.h>
   #include <sys/types.h>
   #include <termios.h>
   #include <unistd.h>
   #undef B0
#endif

#if defined(BOTAN_TARGET_OS_IS_EMSCRIPTEN)
   #include <emscripten/emscripten.h>
#endif

#if defined(BOTAN_TARGET_OS_HAS_GETAUXVAL) || defined(BOTAN_TARGET_OS_HAS_ELF_AUX_INFO)
   #include <sys/auxv.h>
#endif

#if defined(BOTAN_TARGET_OS_HAS_WIN32)
   #define NOMINMAX 1
   #define _WINSOCKAPI_  // stop windows.h including winsock.h
   #include <windows.h>
   #if defined(BOTAN_BUILD_COMPILER_IS_MSVC)
      #include <libloaderapi.h>
      #include <stringapiset.h>
   #endif
#endif

#if defined(BOTAN_TARGET_OS_IS_IOS) || defined(BOTAN_TARGET_OS_IS_MACOS)
   #include <mach/vm_statistics.h>
   #include <sys/sysctl.h>
   #include <sys/types.h>
#endif

#if defined(BOTAN_TARGET_OS_HAS_PRCTL)
   #include <sys/prctl.h>
#endif

#if defined(BOTAN_TARGET_OS_IS_FREEBSD) || defined(BOTAN_TARGET_OS_IS_OPENBSD) || defined(BOTAN_TARGET_OS_IS_DRAGONFLY)
   #include <pthread_np.h>
#endif

#if defined(BOTAN_TARGET_OS_IS_HAIKU)
   #include <kernel/OS.h>
#endif

namespace Botan {

uint32_t OS::get_process_id() {
#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   return ::getpid();
#elif defined(BOTAN_TARGET_OS_HAS_WIN32)
   return ::GetCurrentProcessId();
#elif defined(BOTAN_TARGET_OS_IS_LLVM) || defined(BOTAN_TARGET_OS_IS_NONE)
   return 0;  // truly no meaningful value
#else
   #error "Missing get_process_id"
#endif
}

namespace {

#if defined(BOTAN_TARGET_OS_HAS_GETAUXVAL) || defined(BOTAN_TARGET_OS_HAS_ELF_AUX_INFO)
   #define BOTAN_TARGET_HAS_AUXVAL_INTERFACE
#endif

std::optional<unsigned long> auxval_hwcap() {
#if defined(AT_HWCAP)
   return AT_HWCAP;
#elif defined(BOTAN_TARGET_HAS_AUXVAL_INTERFACE)
   // If the value is not defined in a header we can see,
   // but auxval is supported, return the Linux/Android value
   return 16;
#else
   return {};
#endif
}

std::optional<unsigned long> auxval_hwcap2() {
#if defined(AT_HWCAP2)
   return AT_HWCAP2;
#elif defined(BOTAN_TARGET_HAS_AUXVAL_INTERFACE)
   // If the value is not defined in a header we can see,
   // but auxval is supported, return the Linux/Android value
   return 26;
#else
   return {};
#endif
}

std::optional<unsigned long> get_auxval(std::optional<unsigned long> id) {
   if(id) {
#if defined(BOTAN_TARGET_OS_HAS_GETAUXVAL)
      return ::getauxval(*id);
#elif defined(BOTAN_TARGET_OS_HAS_ELF_AUX_INFO)
      unsigned long auxinfo = 0;
      if(::elf_aux_info(static_cast<int>(*id), &auxinfo, sizeof(auxinfo)) == 0) {
         return auxinfo;
      }
#endif
   }

   return {};
}

}  // namespace

std::optional<std::pair<unsigned long, unsigned long>> OS::get_auxval_hwcap() {
   if(const auto hwcap = get_auxval(auxval_hwcap())) {
      // If hwcap worked/was valid, we don't require hwcap2 to also
      // succeed but instead will return zeros if it failed.
      auto hwcap2 = get_auxval(auxval_hwcap2()).value_or(0);
      return std::make_pair(*hwcap, hwcap2);
   } else {
      return {};
   }
}

namespace {

/**
* Test if we are currently running with elevated permissions
* eg setuid, setgid, or with POSIX caps set.
*/
bool running_in_privileged_state() {
#if defined(AT_SECURE)
   if(auto at_secure = get_auxval(AT_SECURE)) {
      return at_secure != 0;
   }
#endif

#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   return (::getuid() != ::geteuid()) || (::getgid() != ::getegid());
#else
   return false;
#endif
}

}  // namespace

uint64_t OS::get_cpu_cycle_counter() {
   uint64_t rtc = 0;

#if defined(BOTAN_TARGET_OS_HAS_WIN32)
   LARGE_INTEGER tv;
   ::QueryPerformanceCounter(&tv);
   rtc = tv.QuadPart;

#elif defined(BOTAN_USE_GCC_INLINE_ASM)

   #if defined(BOTAN_TARGET_ARCH_IS_X86_64)

   uint32_t rtc_low = 0;
   uint32_t rtc_high = 0;
   asm volatile("rdtsc" : "=d"(rtc_high), "=a"(rtc_low));
   rtc = (static_cast<uint64_t>(rtc_high) << 32) | rtc_low;

   #elif defined(BOTAN_TARGET_ARCH_IS_X86_FAMILY) && defined(BOTAN_HAS_CPUID)

   if(CPUID::has(CPUID::Feature::RDTSC)) {
      uint32_t rtc_low = 0;
      uint32_t rtc_high = 0;
      asm volatile("rdtsc" : "=d"(rtc_high), "=a"(rtc_low));
      rtc = (static_cast<uint64_t>(rtc_high) << 32) | rtc_low;
   }

   #elif defined(BOTAN_TARGET_ARCH_IS_PPC64)

   for(;;) {
      uint32_t rtc_low = 0;
      uint32_t rtc_high = 0;
      uint32_t rtc_high2 = 0;
      asm volatile("mftbu %0" : "=r"(rtc_high));
      asm volatile("mftb %0" : "=r"(rtc_low));
      asm volatile("mftbu %0" : "=r"(rtc_high2));

      if(rtc_high == rtc_high2) {
         rtc = (static_cast<uint64_t>(rtc_high) << 32) | rtc_low;
         break;
      }
   }

   #elif defined(BOTAN_TARGET_ARCH_IS_ALPHA)
   asm volatile("rpcc %0" : "=r"(rtc));

      // OpenBSD does not trap access to the %tick register
   #elif defined(BOTAN_TARGET_ARCH_IS_SPARC64) && !defined(BOTAN_TARGET_OS_IS_OPENBSD)
   asm volatile("rd %%tick, %0" : "=r"(rtc));

   #elif defined(BOTAN_TARGET_ARCH_IS_IA64)
   asm volatile("mov %0=ar.itc" : "=r"(rtc));

   #elif defined(BOTAN_TARGET_ARCH_IS_S390X)
   asm volatile("stck 0(%0)" : : "a"(&rtc) : "memory", "cc");

   #elif defined(BOTAN_TARGET_ARCH_IS_HPPA)
   asm volatile("mfctl 16,%0" : "=r"(rtc));  // 64-bit only?

   #else
      //#warning "OS::get_cpu_cycle_counter not implemented"
   #endif

#endif

   return rtc;
}

size_t OS::get_cpu_available() {
#if defined(BOTAN_TARGET_OS_HAS_POSIX1)

   #if defined(_SC_NPROCESSORS_ONLN)
   const long cpu_online = ::sysconf(_SC_NPROCESSORS_ONLN);
   if(cpu_online > 0) {
      return static_cast<size_t>(cpu_online);
   }
   #endif

   #if defined(_SC_NPROCESSORS_CONF)
   const long cpu_conf = ::sysconf(_SC_NPROCESSORS_CONF);
   if(cpu_conf > 0) {
      return static_cast<size_t>(cpu_conf);
   }
   #endif

#endif

#if defined(BOTAN_TARGET_OS_HAS_THREADS)
   // hardware_concurrency is allowed to return 0 if the value is not
   // well defined or not computable.
   const size_t hw_concur = std::thread::hardware_concurrency();

   if(hw_concur > 0) {
      return hw_concur;
   }
#endif

   return 1;
}

uint64_t OS::get_high_resolution_clock() {
   if(uint64_t cpu_clock = OS::get_cpu_cycle_counter()) {
      return cpu_clock;
   }

#if defined(BOTAN_TARGET_OS_IS_EMSCRIPTEN)
   return emscripten_get_now();
#endif

   /*
   If we got here either we either don't have an asm instruction
   above, or (for x86) RDTSC is not available at runtime. Try some
   clock_gettimes and return the first one that works, or otherwise
   fall back to std::chrono.
   */

#if defined(BOTAN_TARGET_OS_HAS_CLOCK_GETTIME)

   // The ordering here is somewhat arbitrary...
   const clockid_t clock_types[] = {
   #if defined(CLOCK_MONOTONIC_HR)
      CLOCK_MONOTONIC_HR,
   #endif
   #if defined(CLOCK_MONOTONIC_RAW)
      CLOCK_MONOTONIC_RAW,
   #endif
   #if defined(CLOCK_MONOTONIC)
      CLOCK_MONOTONIC,
   #endif
   #if defined(CLOCK_PROCESS_CPUTIME_ID)
      CLOCK_PROCESS_CPUTIME_ID,
   #endif
   #if defined(CLOCK_THREAD_CPUTIME_ID)
      CLOCK_THREAD_CPUTIME_ID,
   #endif
   };

   for(clockid_t clock : clock_types) {
      struct timespec ts {};

      if(::clock_gettime(clock, &ts) == 0) {
         return (static_cast<uint64_t>(ts.tv_sec) * 1000000000) + static_cast<uint64_t>(ts.tv_nsec);
      }
   }
#endif

#if defined(BOTAN_TARGET_OS_HAS_SYSTEM_CLOCK)
   // Plain C++11 fallback
   auto now = std::chrono::high_resolution_clock::now().time_since_epoch();
   return std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
#else
   return 0;
#endif
}

uint64_t OS::get_system_timestamp_ns() {
#if defined(BOTAN_TARGET_OS_HAS_CLOCK_GETTIME)
   struct timespec ts {};

   if(::clock_gettime(CLOCK_REALTIME, &ts) == 0) {
      return (static_cast<uint64_t>(ts.tv_sec) * 1000000000) + static_cast<uint64_t>(ts.tv_nsec);
   }
#endif

#if defined(BOTAN_TARGET_OS_HAS_SYSTEM_CLOCK)
   auto now = std::chrono::system_clock::now().time_since_epoch();
   return std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
#else
   throw Not_Implemented("OS::get_system_timestamp_ns this system does not support a clock");
#endif
}

std::string OS::format_time(time_t time, const std::string& format) {
   std::tm tm{};

#if defined(BOTAN_TARGET_OS_HAS_WIN32)
   if(::localtime_s(&tm, &time) != 0) {
      throw Encoding_Error("Could not convert time_t to localtime");
   }
#elif defined(BOTAN_TARGET_OS_HAS_POSIX1)
   if(::localtime_r(&time, &tm) == nullptr) {
      throw Encoding_Error("Could not convert time_t to localtime");
   }
#else
   if(auto tmp = std::localtime(&time)) {
      tm = *tmp;
   } else {
      throw Encoding_Error("Could not convert time_t to localtime");
   }
#endif

   std::ostringstream oss;
   oss << std::put_time(&tm, format.c_str());
   return oss.str();
}

size_t OS::system_page_size() {
   const size_t default_page_size = 4096;

#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   long p = ::sysconf(_SC_PAGESIZE);
   if(p > 1) {
      return static_cast<size_t>(p);
   } else {
      return default_page_size;
   }
#elif defined(BOTAN_TARGET_OS_HAS_VIRTUAL_LOCK)
   BOTAN_UNUSED(default_page_size);
   SYSTEM_INFO sys_info;
   ::GetSystemInfo(&sys_info);
   return sys_info.dwPageSize;
#else
   return default_page_size;
#endif
}

size_t OS::get_memory_locking_limit() {
   /*
   * Linux defaults to only 64 KiB of mlockable memory per process (too small)
   * but BSDs offer a small fraction of total RAM (more than we need). Bound the
   * total mlock size to 512 KiB which is enough to run the entire test suite
   * without spilling to non-mlock memory (and thus presumably also enough for
   * many useful programs), but small enough that we should not cause problems
   * even if many processes are mlocking on the same machine.
   */
   const size_t max_locked_kb = 512;

   /*
   * If RLIMIT_MEMLOCK is not defined, likely the OS does not support
   * unprivileged mlock calls.
   */
#if defined(RLIMIT_MEMLOCK) && defined(BOTAN_TARGET_OS_HAS_POSIX1) && defined(BOTAN_TARGET_OS_HAS_POSIX_MLOCK)
   const size_t mlock_requested =
      std::min<size_t>(read_env_variable_sz("BOTAN_MLOCK_POOL_SIZE", max_locked_kb), max_locked_kb);

   if(mlock_requested > 0) {
      struct ::rlimit limits {};

      ::getrlimit(RLIMIT_MEMLOCK, &limits);

      if(limits.rlim_cur < limits.rlim_max) {
         limits.rlim_cur = limits.rlim_max;
         ::setrlimit(RLIMIT_MEMLOCK, &limits);
         ::getrlimit(RLIMIT_MEMLOCK, &limits);
      }

      return std::min<size_t>(limits.rlim_cur, mlock_requested * 1024);
   }

#elif defined(BOTAN_TARGET_OS_HAS_VIRTUAL_LOCK)
   const size_t mlock_requested =
      std::min<size_t>(read_env_variable_sz("BOTAN_MLOCK_POOL_SIZE", max_locked_kb), max_locked_kb);

   SIZE_T working_min = 0, working_max = 0;
   if(!::GetProcessWorkingSetSize(::GetCurrentProcess(), &working_min, &working_max)) {
      return 0;
   }

   // According to Microsoft MSDN:
   // The maximum number of pages that a process can lock is equal to the number of pages in its minimum working set minus a small overhead
   // In the book "Windows Internals Part 2": the maximum lockable pages are minimum working set size - 8 pages
   // But the information in the book seems to be inaccurate/outdated
   // I've tested this on Windows 8.1 x64, Windows 10 x64 and Windows 7 x86
   // On all three OS the value is 11 instead of 8
   const size_t overhead = OS::system_page_size() * 11;
   if(working_min > overhead) {
      const size_t lockable_bytes = working_min - overhead;
      return std::min<size_t>(lockable_bytes, mlock_requested * 1024);
   }
#else
   // Not supported on this platform
   BOTAN_UNUSED(max_locked_kb);
#endif

   return 0;
}

bool OS::read_env_variable(std::string& value_out, std::string_view name_view) {
   value_out = "";

   if(running_in_privileged_state()) {
      return false;
   }

#if defined(BOTAN_TARGET_OS_HAS_WIN32) && defined(BOTAN_BUILD_COMPILER_IS_MSVC)
   const std::string name(name_view);
   char val[128] = {0};
   size_t req_size = 0;
   if(getenv_s(&req_size, val, sizeof(val), name.c_str()) == 0) {
      // Microsoft's implementation always writes a terminating \0,
      // and includes it in the reported length of the environment variable
      // if a value exists.
      if(req_size > 0 && val[req_size - 1] == '\0') {
         value_out = std::string(val);
      } else {
         value_out = std::string(val, req_size);
      }
      return true;
   }
#else
   const std::string name(name_view);
   if(const char* val = std::getenv(name.c_str())) {
      value_out = val;
      return true;
   }
#endif

   return false;
}

size_t OS::read_env_variable_sz(std::string_view name, size_t def) {
   std::string value;
   if(read_env_variable(value, name) && !value.empty()) {
      try {
         const size_t val = std::stoul(value, nullptr);
         return val;
      } catch(std::exception&) { /* ignore it */
      }
   }

   return def;
}

#if defined(BOTAN_TARGET_OS_HAS_POSIX1) && defined(BOTAN_TARGET_OS_HAS_POSIX_MLOCK)

namespace {

int get_locked_fd() {
   #if defined(BOTAN_TARGET_OS_IS_IOS) || defined(BOTAN_TARGET_OS_IS_MACOS)
   // On Darwin, tagging anonymous pages allows vmmap to track these.
   // Allowed from 240 to 255 for userland applications
   static constexpr int default_locked_fd = 255;
   int locked_fd = default_locked_fd;

   if(size_t locked_fdl = OS::read_env_variable_sz("BOTAN_LOCKED_FD", default_locked_fd)) {
      if(locked_fdl < 240 || locked_fdl > 255) {
         locked_fdl = default_locked_fd;
      }
      locked_fd = static_cast<int>(locked_fdl);
   }
   return VM_MAKE_TAG(locked_fd);
   #else
   return -1;
   #endif
}

}  // namespace

#endif

std::vector<void*> OS::allocate_locked_pages(size_t count) {
   std::vector<void*> result;

#if(defined(BOTAN_TARGET_OS_HAS_POSIX1) && defined(BOTAN_TARGET_OS_HAS_POSIX_MLOCK)) || \
   defined(BOTAN_TARGET_OS_HAS_VIRTUAL_LOCK)

   result.reserve(count);

   const size_t page_size = OS::system_page_size();

   #if defined(BOTAN_TARGET_OS_HAS_POSIX1) && defined(BOTAN_TARGET_OS_HAS_POSIX_MLOCK)
   static const int locked_fd = get_locked_fd();
   #endif

   for(size_t i = 0; i != count; ++i) {
      void* ptr = nullptr;

   #if defined(BOTAN_TARGET_OS_HAS_POSIX1) && defined(BOTAN_TARGET_OS_HAS_POSIX_MLOCK)

      int mmap_flags = MAP_PRIVATE;

      #if defined(MAP_ANONYMOUS)
      mmap_flags |= MAP_ANONYMOUS;
      #elif defined(MAP_ANON)
      mmap_flags |= MAP_ANON;
      #endif

      #if defined(MAP_CONCEAL)
      mmap_flags |= MAP_CONCEAL;
      #elif defined(MAP_NOCORE)
      mmap_flags |= MAP_NOCORE;
      #endif

      int mmap_prot = PROT_READ | PROT_WRITE;

      #if defined(PROT_MAX)
      mmap_prot |= PROT_MAX(mmap_prot);
      #endif

      ptr = ::mmap(nullptr,
                   3 * page_size,
                   mmap_prot,
                   mmap_flags,
                   /*fd=*/locked_fd,
                   /*offset=*/0);

      if(ptr == MAP_FAILED) {
         continue;
      }

      // lock the data page
      if(::mlock(static_cast<uint8_t*>(ptr) + page_size, page_size) != 0) {
         ::munmap(ptr, 3 * page_size);
         continue;
      }

      #if defined(MADV_DONTDUMP)
      // we ignore errors here, as DONTDUMP is just a bonus
      ::madvise(static_cast<uint8_t*>(ptr) + page_size, page_size, MADV_DONTDUMP);
      #endif

   #elif defined(BOTAN_TARGET_OS_HAS_VIRTUAL_LOCK)
      ptr = ::VirtualAlloc(nullptr, 3 * page_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

      if(ptr == nullptr)
         continue;

      if(::VirtualLock(static_cast<uint8_t*>(ptr) + page_size, page_size) == 0) {
         ::VirtualFree(ptr, 0, MEM_RELEASE);
         continue;
      }
   #endif

      std::memset(ptr, 0, 3 * page_size);  // zero data page and both guard pages

      // Attempts to name the data page
      page_named(ptr, 3 * page_size);
      // Make guard page preceeding the data page
      page_prohibit_access(static_cast<uint8_t*>(ptr));
      // Make guard page following the data page
      page_prohibit_access(static_cast<uint8_t*>(ptr) + 2 * page_size);

      result.push_back(static_cast<uint8_t*>(ptr) + page_size);
   }
#else
   BOTAN_UNUSED(count);
#endif

   return result;
}

void OS::page_allow_access(void* page) {
#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   const size_t page_size = OS::system_page_size();
   ::mprotect(page, page_size, PROT_READ | PROT_WRITE);
#elif defined(BOTAN_TARGET_OS_HAS_VIRTUAL_LOCK)
   const size_t page_size = OS::system_page_size();
   DWORD old_perms = 0;
   ::VirtualProtect(page, page_size, PAGE_READWRITE, &old_perms);
   BOTAN_UNUSED(old_perms);
#else
   BOTAN_UNUSED(page);
#endif
}

void OS::page_prohibit_access(void* page) {
#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   const size_t page_size = OS::system_page_size();
   ::mprotect(page, page_size, PROT_NONE);
#elif defined(BOTAN_TARGET_OS_HAS_VIRTUAL_LOCK)
   const size_t page_size = OS::system_page_size();
   DWORD old_perms = 0;
   ::VirtualProtect(page, page_size, PAGE_NOACCESS, &old_perms);
   BOTAN_UNUSED(old_perms);
#else
   BOTAN_UNUSED(page);
#endif
}

void OS::free_locked_pages(const std::vector<void*>& pages) {
   const size_t page_size = OS::system_page_size();

   for(void* ptr : pages) {
      secure_scrub_memory(ptr, page_size);

      // ptr points to the data page, guard pages are before and after
      page_allow_access(static_cast<uint8_t*>(ptr) - page_size);
      page_allow_access(static_cast<uint8_t*>(ptr) + page_size);

#if defined(BOTAN_TARGET_OS_HAS_POSIX1) && defined(BOTAN_TARGET_OS_HAS_POSIX_MLOCK)
      ::munlock(ptr, page_size);
      ::munmap(static_cast<uint8_t*>(ptr) - page_size, 3 * page_size);
#elif defined(BOTAN_TARGET_OS_HAS_VIRTUAL_LOCK)
      ::VirtualUnlock(ptr, page_size);
      ::VirtualFree(static_cast<uint8_t*>(ptr) - page_size, 0, MEM_RELEASE);
#endif
   }
}

void OS::page_named(void* page, size_t size) {
#if defined(BOTAN_TARGET_OS_HAS_PRCTL) && defined(PR_SET_VMA) && defined(PR_SET_VMA_ANON_NAME)
   static constexpr char name[] = "Botan mlock pool";
   // NOLINTNEXTLINE(*-vararg)
   int r = prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, reinterpret_cast<uintptr_t>(page), size, name);
   BOTAN_UNUSED(r);
#else
   BOTAN_UNUSED(page, size);
#endif
}

#if defined(BOTAN_TARGET_OS_HAS_THREADS)
void OS::set_thread_name(std::thread& thread, const std::string& name) {
   #if defined(BOTAN_TARGET_OS_IS_LINUX) || defined(BOTAN_TARGET_OS_IS_FREEBSD) || defined(BOTAN_TARGET_OS_IS_DRAGONFLY)
   static_cast<void>(pthread_setname_np(thread.native_handle(), name.c_str()));
   #elif defined(BOTAN_TARGET_OS_IS_OPENBSD)
   static_cast<void>(pthread_set_name_np(thread.native_handle(), name.c_str()));
   #elif defined(BOTAN_TARGET_OS_IS_NETBSD)
   static_cast<void>(pthread_setname_np(thread.native_handle(), "%s", const_cast<char*>(name.c_str())));
   #elif defined(BOTAN_TARGET_OS_HAS_WIN32) && defined(_LIBCPP_HAS_THREAD_API_PTHREAD)
   static_cast<void>(pthread_setname_np(thread.native_handle(), name.c_str()));
   #elif defined(BOTAN_TARGET_OS_HAS_WIN32) && defined(BOTAN_BUILD_COMPILER_IS_MSVC)
   typedef HRESULT(WINAPI * std_proc)(HANDLE, PCWSTR);
   HMODULE kern = GetModuleHandleA("KernelBase.dll");
   std_proc set_thread_name = reinterpret_cast<std_proc>(GetProcAddress(kern, "SetThreadDescription"));
   if(set_thread_name) {
      std::wstring w;
      auto sz = MultiByteToWideChar(CP_UTF8, 0, name.data(), -1, nullptr, 0);
      if(sz > 0) {
         w.resize(sz);
         if(MultiByteToWideChar(CP_UTF8, 0, name.data(), -1, &w[0], sz) > 0) {
            (void)set_thread_name(thread.native_handle(), w.c_str());
         }
      }
   }
   #elif defined(BOTAN_TARGET_OS_IF_HAIKU)
   auto thread_id = get_pthread_thread_id(thread.native_handle());
   static_cast<void>(rename_thread(thread_id, name.c_str()));
   #else
   // TODO other possible oses ?
   // macOs does not seem to allow to name threads other than the current one.
   BOTAN_UNUSED(thread, name);
   #endif
}
#endif

#if defined(BOTAN_TARGET_OS_HAS_POSIX1) && !defined(BOTAN_TARGET_OS_IS_EMSCRIPTEN)

namespace {

// NOLINTNEXTLINE(*-avoid-non-const-global-variables)
::sigjmp_buf g_sigill_jmp_buf;

void botan_sigill_handler(int /*unused*/) {
   siglongjmp(g_sigill_jmp_buf, /*non-zero return value*/ 1);
}

}  // namespace

#endif

int OS::run_cpu_instruction_probe(const std::function<int()>& probe_fn) {
   volatile int probe_result = -3;

#if defined(BOTAN_TARGET_OS_HAS_POSIX1) && !defined(BOTAN_TARGET_OS_IS_EMSCRIPTEN)
   struct sigaction old_sigaction {};

   struct sigaction sigaction {};

   sigaction.sa_handler = botan_sigill_handler;
   sigemptyset(&sigaction.sa_mask);
   sigaction.sa_flags = 0;

   int rc = ::sigaction(SIGILL, &sigaction, &old_sigaction);

   if(rc != 0) {
      throw System_Error("run_cpu_instruction_probe sigaction failed", errno);
   }

   rc = sigsetjmp(g_sigill_jmp_buf, /*save sigs*/ 1);

   if(rc == 0) {
      // first call to sigsetjmp
      probe_result = probe_fn();
   } else if(rc == 1) {
      // non-local return from siglongjmp in signal handler: return error
      probe_result = -1;
   }

   // Restore old SIGILL handler, if any
   rc = ::sigaction(SIGILL, &old_sigaction, nullptr);
   if(rc != 0) {
      throw System_Error("run_cpu_instruction_probe sigaction restore failed", errno);
   }

#else
   BOTAN_UNUSED(probe_fn);
#endif

   return probe_result;
}

std::unique_ptr<OS::Echo_Suppression> OS::suppress_echo_on_terminal() {
#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   class POSIX_Echo_Suppression : public Echo_Suppression {
      public:
         POSIX_Echo_Suppression() : m_stdin_fd(fileno(stdin)), m_old_termios{} {
            if(::tcgetattr(m_stdin_fd, &m_old_termios) != 0) {
               throw System_Error("Getting terminal status failed", errno);
            }

            struct termios noecho_flags = m_old_termios;
            noecho_flags.c_lflag &= ~ECHO;
            noecho_flags.c_lflag |= ECHONL;

            if(::tcsetattr(m_stdin_fd, TCSANOW, &noecho_flags) != 0) {
               throw System_Error("Clearing terminal echo bit failed", errno);
            }
         }

         void reenable_echo() override {
            if(m_stdin_fd > 0) {
               if(::tcsetattr(m_stdin_fd, TCSANOW, &m_old_termios) != 0) {
                  throw System_Error("Restoring terminal echo bit failed", errno);
               }
               m_stdin_fd = -1;
            }
         }

         ~POSIX_Echo_Suppression() override {
            try {
               reenable_echo();
            } catch(...) {}
         }

         POSIX_Echo_Suppression(const POSIX_Echo_Suppression& other) = delete;
         POSIX_Echo_Suppression(POSIX_Echo_Suppression&& other) = delete;
         POSIX_Echo_Suppression& operator=(const POSIX_Echo_Suppression& other) = delete;
         POSIX_Echo_Suppression& operator=(POSIX_Echo_Suppression&& other) = delete;

      private:
         int m_stdin_fd;
         struct termios m_old_termios;
   };

   return std::make_unique<POSIX_Echo_Suppression>();

#elif defined(BOTAN_TARGET_OS_HAS_WIN32)

   class Win32_Echo_Suppression : public Echo_Suppression {
      public:
         Win32_Echo_Suppression() {
            m_input_handle = ::GetStdHandle(STD_INPUT_HANDLE);
            if(::GetConsoleMode(m_input_handle, &m_console_state) == 0)
               throw System_Error("Getting console mode failed", ::GetLastError());

            DWORD new_mode = ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT;
            if(::SetConsoleMode(m_input_handle, new_mode) == 0)
               throw System_Error("Setting console mode failed", ::GetLastError());
         }

         void reenable_echo() override {
            if(m_input_handle != INVALID_HANDLE_VALUE) {
               if(::SetConsoleMode(m_input_handle, m_console_state) == 0)
                  throw System_Error("Setting console mode failed", ::GetLastError());
               m_input_handle = INVALID_HANDLE_VALUE;
            }
         }

         ~Win32_Echo_Suppression() override {
            try {
               reenable_echo();
            } catch(...) {}
         }

         Win32_Echo_Suppression(const Win32_Echo_Suppression& other) = delete;
         Win32_Echo_Suppression(Win32_Echo_Suppression&& other) = delete;
         Win32_Echo_Suppression& operator=(const Win32_Echo_Suppression& other) = delete;
         Win32_Echo_Suppression& operator=(Win32_Echo_Suppression&& other) = delete;

      private:
         HANDLE m_input_handle;
         DWORD m_console_state;
   };

   return std::make_unique<Win32_Echo_Suppression>();

#else

   // Not supported on this platform, return null
   return nullptr;
#endif
}

}  // namespace Botan
