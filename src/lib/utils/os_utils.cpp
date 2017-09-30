/*
* OS and machine specific utility functions
* (C) 2015,2016,2017 Jack Lloyd
* (C) 2016 Daniel Neus
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/os_utils.h>
#include <botan/cpuid.h>
#include <botan/exceptn.h>
#include <botan/mem_ops.h>
#include <chrono>

#if defined(BOTAN_HAS_BOOST_ASIO)
  /*
  * We don't need serial port support anyway, and asking for it
  * causes macro conflicts with Darwin's termios.h when this
  * file is included in the amalgamation. GH #350
  */
  #define BOOST_ASIO_DISABLE_SERIAL_PORT
  #include <boost/asio.hpp>
#endif

#if defined(BOTAN_TARGET_OS_HAS_EXPLICIT_BZERO)
  #include <string.h>
#endif

#if defined(BOTAN_TARGET_OS_TYPE_IS_UNIX)
  #include <sys/types.h>
  #include <sys/resource.h>
  #include <sys/mman.h>
  #include <signal.h>
  #include <setjmp.h>
  #include <unistd.h>
  #include <errno.h>

#if !defined(BOTAN_HAS_BOOST_ASIO)
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <netdb.h>
#endif

#elif defined(BOTAN_TARGET_OS_TYPE_IS_WINDOWS)
  #define NOMINMAX 1
#if !defined(BOTAN_HAS_BOOST_ASIO)
  #include <winsock2.h>
  #include <ws2tcpip.h>
#endif
  #include <windows.h>
#endif

namespace Botan {

namespace {

#if defined(BOTAN_HAS_BOOST_ASIO)

class Asio_Socket final : public OS::Socket
   {
   public:
      Asio_Socket(const std::string& hostname, const std::string& service) :
         m_tcp(m_io)
         {
         boost::asio::ip::tcp::resolver resolver(m_io);
         boost::asio::ip::tcp::resolver::query query(hostname, service);
         boost::asio::connect(m_tcp, resolver.resolve(query));
         }

      void write(const uint8_t buf[], size_t len) override
         {
         boost::asio::write(m_tcp, boost::asio::buffer(buf, len));
         }

      size_t read(uint8_t buf[], size_t len) override
         {
         boost::system::error_code error;
         size_t got = m_tcp.read_some(boost::asio::buffer(buf, len), error);

         if(error)
            {
            if(error == boost::asio::error::eof)
               return 0;
            throw boost::system::system_error(error); // Some other error.
            }

         return got;
         }

   private:
      boost::asio::io_service m_io;
      boost::asio::ip::tcp::socket m_tcp;
   };

#elif defined(BOTAN_TARGET_OS_TYPE_IS_WINDOWS)

class Winsock_Socket final : public OS::Socket
   {
   public:
      Winsock_Socket(const std::string& hostname, const std::string& service)
         {
         WSAData wsa_data;
         WORD wsa_version = MAKEWORD(2, 2);

         if (::WSAStartup(wsa_version, &wsa_data) != 0)
            {
            throw Exception("WSAStartup() failed: " + std::to_string(WSAGetLastError()));
            }

         if (LOBYTE(wsa_data.wVersion) != 2 || HIBYTE(wsa_data.wVersion) != 2)
            {
            ::WSACleanup();
            throw Exception("Could not find a usable version of Winsock.dll");
            }

         addrinfo hints;
         ::memset(&hints, 0, sizeof(addrinfo));
         hints.ai_family = AF_UNSPEC;
         hints.ai_socktype = SOCK_STREAM;
         addrinfo* res;

         if(::getaddrinfo(hostname.c_str(), service.c_str(), &hints, &res) != 0)
            {
            throw Exception("Name resolution failed for " + hostname);
            }

         for(addrinfo* rp = res; (m_socket == INVALID_SOCKET) && (rp != nullptr); rp = rp->ai_next)
            {
            m_socket = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

            // unsupported socket type?
            if(m_socket == INVALID_SOCKET)
               continue;

            if(::connect(m_socket, rp->ai_addr, rp->ai_addrlen) != 0)
               {
               ::closesocket(m_socket);
               m_socket = INVALID_SOCKET;
               continue;
               }
            }

         ::freeaddrinfo(res);

         if(m_socket == INVALID_SOCKET)
            {
            throw Exception("Connecting to " + hostname +
                            " for service " + service + " failed");
            }
         }

      ~Winsock_Socket()
         {
         ::closesocket(m_socket);
         m_socket = INVALID_SOCKET;
         ::WSACleanup();
         }

      void write(const uint8_t buf[], size_t len) override
         {
         size_t sent_so_far = 0;
         while(sent_so_far != len)
            {
            const size_t left = len - sent_so_far;
            int sent = ::send(m_socket,
                              reinterpret_cast<const char*>(buf + sent_so_far),
                              static_cast<int>(left),
                              0);

            if(sent == SOCKET_ERROR)
               throw Exception("Socket write failed with error " +
                               std::to_string(::WSAGetLastError()));
            else
               sent_so_far += static_cast<size_t>(sent);
            }
         }

      size_t read(uint8_t buf[], size_t len) override
         {
         int got = ::recv(m_socket,
                          reinterpret_cast<char*>(buf),
                          static_cast<int>(len), 0);

         if(got == SOCKET_ERROR)
            throw Exception("Socket read failed with error " +
                            std::to_string(::WSAGetLastError()));
         return static_cast<size_t>(got);
         }

   private:
      SOCKET m_socket = INVALID_SOCKET;
   };

#elif defined(BOTAN_TARGET_OS_TYPE_IS_UNIX)
class BSD_Socket final : public OS::Socket
   {
   public:
      BSD_Socket(const std::string& hostname, const std::string& service)
         {
         addrinfo hints;
         ::memset(&hints, 0, sizeof(addrinfo));
         hints.ai_family = AF_UNSPEC;
         hints.ai_socktype = SOCK_STREAM;
         addrinfo* res;

         if(::getaddrinfo(hostname.c_str(), service.c_str(), &hints, &res) != 0)
            {
            throw Exception("Name resolution failed for " + hostname);
            }

         m_fd = -1;

         for(addrinfo* rp = res; (m_fd < 0) && (rp != nullptr); rp = rp->ai_next)
            {
            m_fd = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

            if(m_fd < 0)
               {
               // unsupported socket type?
               continue;
               }

            if(::connect(m_fd, rp->ai_addr, rp->ai_addrlen) != 0)
               {
               ::close(m_fd);
               m_fd = -1;
               continue;
               }
            }

         ::freeaddrinfo(res);

         if(m_fd < 0)
            {
            throw Exception("Connecting to " + hostname +
                            " for service " + service + " failed");
            }
         }

      ~BSD_Socket()
         {
         ::close(m_fd);
         m_fd = -1;
         }

      void write(const uint8_t buf[], size_t len) override
         {
         size_t sent_so_far = 0;
         while(sent_so_far != len)
            {
            const size_t left = len - sent_so_far;
            ssize_t sent = ::write(m_fd, &buf[sent_so_far], left);
            if(sent < 0)
               throw Exception("Socket write failed with error '" +
                               std::string(::strerror(errno)) + "'");
            else
               sent_so_far += static_cast<size_t>(sent);
            }
         }

      size_t read(uint8_t buf[], size_t len) override
         {
         ssize_t got = ::read(m_fd, buf, len);

         if(got < 0)
            throw Exception("Socket read failed with error '" +
                            std::string(::strerror(errno)) + "'");
         return static_cast<size_t>(got);
         }

   private:
      int m_fd;
   };

#endif

}

std::unique_ptr<OS::Socket>
OS::open_socket(const std::string& hostname,
                const std::string& service)
   {
#if defined(BOTAN_HAS_BOOST_ASIO)
   return std::unique_ptr<OS::Socket>(new Asio_Socket(hostname, service));

#elif defined(BOTAN_TARGET_OS_TYPE_IS_WINDOWS)
   return std::unique_ptr<OS::Socket>(new Winsock_Socket(hostname, service));

#elif defined(BOTAN_TARGET_OS_TYPE_IS_UNIX)
   return std::unique_ptr<OS::Socket>(new BSD_Socket(hostname, service));

#else
   // No sockets for you
   return std::unique_ptr<Socket>();
#endif
   }

// Not defined in OS namespace for historical reasons
void secure_scrub_memory(void* ptr, size_t n)
   {
#if defined(BOTAN_TARGET_OS_HAS_RTLSECUREZEROMEMORY)
   ::RtlSecureZeroMemory(ptr, n);

#elif defined(BOTAN_TARGET_OS_HAS_EXPLICIT_BZERO)
   ::explicit_bzero(ptr, n);

#elif defined(BOTAN_USE_VOLATILE_MEMSET_FOR_ZERO) && (BOTAN_USE_VOLATILE_MEMSET_FOR_ZERO == 1)
   /*
   Call memset through a static volatile pointer, which the compiler
   should not elide. This construct should be safe in conforming
   compilers, but who knows. I did confirm that on x86-64 GCC 6.1 and
   Clang 3.8 both create code that saves the memset address in the
   data segment and uncondtionally loads and jumps to that address.
   */
   static void* (*const volatile memset_ptr)(void*, int, size_t) = std::memset;
   (memset_ptr)(ptr, 0, n);
#else

   volatile uint8_t* p = reinterpret_cast<volatile uint8_t*>(ptr);

   for(size_t i = 0; i != n; ++i)
      p[i] = 0;
#endif
   }

uint32_t OS::get_process_id()
   {
#if defined(BOTAN_TARGET_OS_TYPE_IS_UNIX)
   return ::getpid();
#elif defined(BOTAN_TARGET_OS_IS_WINDOWS) || defined(BOTAN_TARGET_OS_IS_MINGW)
   return ::GetCurrentProcessId();
#elif defined(BOTAN_TARGET_OS_TYPE_IS_UNIKERNEL) || defined(BOTAN_TARGET_OS_IS_LLVM)
   return 0; // truly no meaningful value
#else
   #error "Missing get_process_id"
#endif
   }

uint64_t OS::get_processor_timestamp()
   {
   uint64_t rtc = 0;

#if defined(BOTAN_TARGET_OS_HAS_QUERY_PERF_COUNTER)
   LARGE_INTEGER tv;
   ::QueryPerformanceCounter(&tv);
   rtc = tv.QuadPart;

#elif defined(BOTAN_USE_GCC_INLINE_ASM)

#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)

   if(CPUID::has_rdtsc())
      {
      uint32_t rtc_low = 0, rtc_high = 0;
      asm volatile("rdtsc" : "=d" (rtc_high), "=a" (rtc_low));
      rtc = (static_cast<uint64_t>(rtc_high) << 32) | rtc_low;
      }

#elif defined(BOTAN_TARGET_ARCH_IS_PPC64)
   uint32_t rtc_low = 0, rtc_high = 0;
   asm volatile("mftbu %0; mftb %1" : "=r" (rtc_high), "=r" (rtc_low));

   /*
   qemu-ppc seems to not support mftb instr, it always returns zero.
   If both time bases are 0, assume broken and return another clock.
   */
   if(rtc_high > 0 || rtc_low > 0)
      {
      rtc = (static_cast<uint64_t>(rtc_high) << 32) | rtc_low;
      }

#elif defined(BOTAN_TARGET_ARCH_IS_ALPHA)
   asm volatile("rpcc %0" : "=r" (rtc));

   // OpenBSD does not trap access to the %tick register
#elif defined(BOTAN_TARGET_ARCH_IS_SPARC64) && !defined(BOTAN_TARGET_OS_IS_OPENBSD)
   asm volatile("rd %%tick, %0" : "=r" (rtc));

#elif defined(BOTAN_TARGET_ARCH_IS_IA64)
   asm volatile("mov %0=ar.itc" : "=r" (rtc));

#elif defined(BOTAN_TARGET_ARCH_IS_S390X)
   asm volatile("stck 0(%0)" : : "a" (&rtc) : "memory", "cc");

#elif defined(BOTAN_TARGET_ARCH_IS_HPPA)
   asm volatile("mfctl 16,%0" : "=r" (rtc)); // 64-bit only?

#else
   //#warning "OS::get_processor_timestamp not implemented"
#endif

#endif

   return rtc;
   }

uint64_t OS::get_high_resolution_clock()
   {
   if(uint64_t cpu_clock = OS::get_processor_timestamp())
      return cpu_clock;

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

   for(clockid_t clock : clock_types)
      {
      struct timespec ts;
      if(::clock_gettime(clock, &ts) == 0)
         {
         return (static_cast<uint64_t>(ts.tv_sec) * 1000000000) + static_cast<uint64_t>(ts.tv_nsec);
         }
      }
#endif

   // Plain C++11 fallback
   auto now = std::chrono::high_resolution_clock::now().time_since_epoch();
   return std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
   }

uint64_t OS::get_system_timestamp_ns()
   {
#if defined(BOTAN_TARGET_OS_HAS_CLOCK_GETTIME)
   struct timespec ts;
   if(::clock_gettime(CLOCK_REALTIME, &ts) == 0)
      {
      return (static_cast<uint64_t>(ts.tv_sec) * 1000000000) + static_cast<uint64_t>(ts.tv_nsec);
      }
#endif

   auto now = std::chrono::system_clock::now().time_since_epoch();
   return std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
   }

size_t OS::get_memory_locking_limit()
   {
#if defined(BOTAN_TARGET_OS_HAS_POSIX_MLOCK)
   /*
   * Linux defaults to only 64 KiB of mlockable memory per process
   * (too small) but BSDs offer a small fraction of total RAM (more
   * than we need). Bound the total mlock size to 512 KiB which is
   * enough to run the entire test suite without spilling to non-mlock
   * memory (and thus presumably also enough for many useful
   * programs), but small enough that we should not cause problems
   * even if many processes are mlocking on the same machine.
   */
   size_t mlock_requested = BOTAN_MLOCK_ALLOCATOR_MAX_LOCKED_KB;

   /*
   * Allow override via env variable
   */
   if(const char* env = ::getenv("BOTAN_MLOCK_POOL_SIZE"))
      {
      try
         {
         const size_t user_req = std::stoul(env, nullptr);
         mlock_requested = std::min(user_req, mlock_requested);
         }
      catch(std::exception&) { /* ignore it */ }
      }

#if defined(RLIMIT_MEMLOCK)
   if(mlock_requested > 0)
      {
      struct ::rlimit limits;

      ::getrlimit(RLIMIT_MEMLOCK, &limits);

      if(limits.rlim_cur < limits.rlim_max)
         {
         limits.rlim_cur = limits.rlim_max;
         ::setrlimit(RLIMIT_MEMLOCK, &limits);
         ::getrlimit(RLIMIT_MEMLOCK, &limits);
         }

      return std::min<size_t>(limits.rlim_cur, mlock_requested * 1024);
      }
#else
   /*
   * If RLIMIT_MEMLOCK is not defined, likely the OS does not support
   * unprivileged mlock calls.
   */
   return 0;
#endif

#elif defined(BOTAN_TARGET_OS_HAS_VIRTUAL_LOCK) && defined(BOTAN_BUILD_COMPILER_IS_MSVC)
   SIZE_T working_min = 0, working_max = 0;
   DWORD working_flags = 0;
   if(!::GetProcessWorkingSetSizeEx(::GetCurrentProcess(), &working_min, &working_max, &working_flags))
      {
      return 0;
      }

   SYSTEM_INFO sSysInfo;
   ::GetSystemInfo(&sSysInfo);

   // According to Microsoft MSDN:
   // The maximum number of pages that a process can lock is equal to the number of pages in its minimum working set minus a small overhead
   // In the book "Windows Internals Part 2": the maximum lockable pages are minimum working set size - 8 pages 
   // But the information in the book seems to be inaccurate/outdated
   // I've tested this on Windows 8.1 x64, Windows 10 x64 and Windows 7 x86
   // On all three OS the value is 11 instead of 8
   size_t overhead = sSysInfo.dwPageSize * 11ULL;
   if(working_min > overhead)
      {
      size_t lockable_bytes = working_min - overhead;
      if(lockable_bytes < (BOTAN_MLOCK_ALLOCATOR_MAX_LOCKED_KB * 1024ULL))
         {
         return lockable_bytes;
         }
      else
         {
         return BOTAN_MLOCK_ALLOCATOR_MAX_LOCKED_KB * 1024ULL;
         }
      }
#endif

   return 0;
   }

void* OS::allocate_locked_pages(size_t length)
   {
#if defined(BOTAN_TARGET_OS_HAS_POSIX_MLOCK)

#if !defined(MAP_NOCORE)
   #define MAP_NOCORE 0
#endif

#if !defined(MAP_ANONYMOUS)
   #define MAP_ANONYMOUS MAP_ANON
#endif

   void* ptr = ::mmap(nullptr,
                      length,
                      PROT_READ | PROT_WRITE,
                      MAP_ANONYMOUS | MAP_SHARED | MAP_NOCORE,
                      /*fd*/-1,
                      /*offset*/0);

   if(ptr == MAP_FAILED)
      {
      return nullptr;
      }

#if defined(MADV_DONTDUMP)
   ::madvise(ptr, length, MADV_DONTDUMP);
#endif

   if(::mlock(ptr, length) != 0)
      {
      ::munmap(ptr, length);
      return nullptr; // failed to lock
      }

   ::memset(ptr, 0, length);

   return ptr;
#elif defined BOTAN_TARGET_OS_HAS_VIRTUAL_LOCK
   LPVOID ptr = ::VirtualAlloc(nullptr, length, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
   if(!ptr)
      {
      return nullptr;
      }

   if(::VirtualLock(ptr, length) == 0)
      {
      ::VirtualFree(ptr, 0, MEM_RELEASE);
      return nullptr; // failed to lock
      }

   return ptr;
#else
   BOTAN_UNUSED(length);
   return nullptr; /* not implemented */
#endif
   }

void OS::free_locked_pages(void* ptr, size_t length)
   {
   if(ptr == nullptr || length == 0)
      return;

#if defined(BOTAN_TARGET_OS_HAS_POSIX_MLOCK)
   secure_scrub_memory(ptr, length);
   ::munlock(ptr, length);
   ::munmap(ptr, length);
#elif defined BOTAN_TARGET_OS_HAS_VIRTUAL_LOCK
   secure_scrub_memory(ptr, length);
   ::VirtualUnlock(ptr, length);
   ::VirtualFree(ptr, 0, MEM_RELEASE);
#else
   // Invalid argument because no way this pointer was allocated by us
   throw Invalid_Argument("Invalid ptr to free_locked_pages");
#endif
   }

#if defined(BOTAN_TARGET_OS_TYPE_IS_UNIX)
namespace {

static ::sigjmp_buf g_sigill_jmp_buf;

void botan_sigill_handler(int)
   {
   ::siglongjmp(g_sigill_jmp_buf, /*non-zero return value*/1);
   }

}
#endif

int OS::run_cpu_instruction_probe(std::function<int ()> probe_fn)
   {
   volatile int probe_result = -3;

#if defined(BOTAN_TARGET_OS_TYPE_IS_UNIX)
   struct sigaction old_sigaction;
   struct sigaction sigaction;

   sigaction.sa_handler = botan_sigill_handler;
   sigemptyset(&sigaction.sa_mask);
   sigaction.sa_flags = 0;

   int rc = ::sigaction(SIGILL, &sigaction, &old_sigaction);

   if(rc != 0)
      throw Exception("run_cpu_instruction_probe sigaction failed");

   rc = ::sigsetjmp(g_sigill_jmp_buf, /*save sigs*/1);

   if(rc == 0)
      {
      // first call to sigsetjmp
      probe_result = probe_fn();
      }
   else if(rc == 1)
      {
      // non-local return from siglongjmp in signal handler: return error
      probe_result = -1;
      }

   // Restore old SIGILL handler, if any
   rc = ::sigaction(SIGILL, &old_sigaction, nullptr);
   if(rc != 0)
      throw Exception("run_cpu_instruction_probe sigaction restore failed");

#elif defined(BOTAN_TARGET_OS_IS_WINDOWS) && defined(BOTAN_TARGET_COMPILER_IS_MSVC)

   // Windows SEH
   __try
      {
      probe_result = probe_fn();
      }
   __except(::GetExceptionCode() == EXCEPTION_ILLEGAL_INSTRUCTION ?
            EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
      {
      probe_result = -1;
      }

#endif

   return probe_result;
   }

}
