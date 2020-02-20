/*
* System RNG
* (C) 2014,2015,2017,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/system_rng.h>

#if defined(BOTAN_TARGET_OS_HAS_RTLGENRANDOM)
  #include <botan/dyn_load.h>
  #define NOMINMAX 1
  #define _WINSOCKAPI_ // stop windows.h including winsock.h
  #include <windows.h>

#elif defined(BOTAN_TARGET_OS_HAS_CRYPTO_NG)
  #include <bcrypt.h>

#elif defined(BOTAN_TARGET_OS_HAS_ARC4RANDOM)
  #include <stdlib.h>

#elif defined(BOTAN_TARGET_OS_HAS_GETRANDOM)
  #include <sys/random.h>
  #include <errno.h>

#elif defined(BOTAN_TARGET_OS_HAS_DEV_RANDOM)
  #include <sys/types.h>
  #include <sys/stat.h>
  #include <fcntl.h>
  #include <unistd.h>
  #include <errno.h>
#endif

namespace Botan {

namespace {

#if defined(BOTAN_TARGET_OS_HAS_RTLGENRANDOM)

class System_RNG_Impl final : public RandomNumberGenerator
   {
   public:
      System_RNG_Impl() : m_advapi("advapi32.dll")
         {
         // This throws if the function is not found
         m_rtlgenrandom = m_advapi.resolve<RtlGenRandom_fptr>("SystemFunction036");
         }

      void randomize(uint8_t buf[], size_t len) override
         {
         bool success = m_rtlgenrandom(buf, ULONG(len)) == TRUE;
         if(!success)
            throw System_Error("RtlGenRandom failed");
         }

      void add_entropy(const uint8_t[], size_t) override { /* ignored */ }
      bool is_seeded() const override { return true; }
      bool accepts_input() const override { return false; }
      void clear() override { /* not possible */ }
      std::string name() const override { return "RtlGenRandom"; }
   private:
      // Use type BYTE instead of BOOLEAN because of a naming conflict
      // https://msdn.microsoft.com/en-us/library/windows/desktop/aa387694(v=vs.85).aspx
      // https://msdn.microsoft.com/en-us/library/windows/desktop/aa383751(v=vs.85).aspx
      using RtlGenRandom_fptr = BYTE (NTAPI *)(PVOID, ULONG);

      Dynamically_Loaded_Library m_advapi;
      RtlGenRandom_fptr m_rtlgenrandom;
   };

#elif defined(BOTAN_TARGET_OS_HAS_CRYPTO_NG)

class System_RNG_Impl final : public RandomNumberGenerator
   {
   public:
      System_RNG_Impl()
         {
         NTSTATUS ret = ::BCryptOpenAlgorithmProvider(&m_prov,
                                                      BCRYPT_RNG_ALGORITHM,
                                                      MS_PRIMITIVE_PROVIDER, 0);
         if(ret != STATUS_SUCCESS)
            throw System_Error("System_RNG failed to acquire crypto provider", ret);
         }

      ~System_RNG_Impl()
         {
         ::BCryptCloseAlgorithmProvider(m_prov, 0);
         }

      void randomize(uint8_t buf[], size_t len) override
         {
         NTSTATUS ret = ::BCryptGenRandom(m_prov, static_cast<PUCHAR>(buf), static_cast<ULONG>(len), 0);
         if(ret != STATUS_SUCCESS)
            throw System_Error("System_RNG call to BCryptGenRandom failed", ret);
         }

      void add_entropy(const uint8_t in[], size_t length) override
         {
         /*
         There is a flag BCRYPT_RNG_USE_ENTROPY_IN_BUFFER to provide
         entropy inputs, but it is ignored in Windows 8 and later.
         */
         }

      bool is_seeded() const override { return true; }
      bool accepts_input() const override { return false; }
      void clear() override { /* not possible */ }
      std::string name() const override { return "crypto_ng"; }
   private:
      BCRYPT_ALG_HANDLE m_prov;
   };

#elif defined(BOTAN_TARGET_OS_HAS_ARC4RANDOM)

class System_RNG_Impl final : public RandomNumberGenerator
   {
   public:
      // No constructor or destructor needed as no userland state maintained

      void randomize(uint8_t buf[], size_t len) override
         {
         // macOS 10.15 arc4random crashes if called with buf == nullptr && len == 0
         if(len > 0)
            {
            ::arc4random_buf(buf, len);
            }
         }

      bool accepts_input() const override { return false; }
      void add_entropy(const uint8_t[], size_t) override { /* ignored */ }
      bool is_seeded() const override { return true; }
      void clear() override { /* not possible */ }
      std::string name() const override { return "arc4random"; }
   };

#elif defined(BOTAN_TARGET_OS_HAS_GETRANDOM)

class System_RNG_Impl final : public RandomNumberGenerator
   {
   public:
      // No constructor or destructor needed as no userland state maintained

      void randomize(uint8_t buf[], size_t len) override
         {
         const unsigned int flags = 0;

         while(len > 0)
            {
            const ssize_t got = ::getrandom(buf, len, flags);

            if(got < 0)
               {
               if(errno == EINTR)
                  continue;
               throw System_Error("System_RNG getrandom failed", errno);
               }

            buf += got;
            len -= got;
            }
         }

      bool accepts_input() const override { return false; }
      void add_entropy(const uint8_t[], size_t) override { /* ignored */ }
      bool is_seeded() const override { return true; }
      void clear() override { /* not possible */ }
      std::string name() const override { return "getrandom"; }
   };


#elif defined(BOTAN_TARGET_OS_HAS_DEV_RANDOM)

// Read a random device

class System_RNG_Impl final : public RandomNumberGenerator
   {
   public:
      System_RNG_Impl()
         {
#ifndef O_NOCTTY
#define O_NOCTTY 0
#endif

         m_fd = ::open(BOTAN_SYSTEM_RNG_DEVICE, O_RDWR | O_NOCTTY);

         if(m_fd >= 0)
            {
            m_writable = true;
            }
         else
            {
            /*
            Cannot open in read-write mode. Fall back to read-only,
            calls to add_entropy will fail, but randomize will work
            */
            m_fd = ::open(BOTAN_SYSTEM_RNG_DEVICE, O_RDONLY | O_NOCTTY);
            m_writable = false;
            }

         if(m_fd < 0)
            throw System_Error("System_RNG failed to open RNG device", errno);
         }

      ~System_RNG_Impl()
         {
         ::close(m_fd);
         m_fd = -1;
         }

      void randomize(uint8_t buf[], size_t len) override;
      void add_entropy(const uint8_t in[], size_t length) override;
      bool is_seeded() const override { return true; }
      bool accepts_input() const override { return m_writable; }
      void clear() override { /* not possible */ }
      std::string name() const override { return BOTAN_SYSTEM_RNG_DEVICE; }
   private:
      int m_fd;
      bool m_writable;
   };

void System_RNG_Impl::randomize(uint8_t buf[], size_t len)
   {
   while(len)
      {
      ssize_t got = ::read(m_fd, buf, len);

      if(got < 0)
         {
         if(errno == EINTR)
            continue;
         throw System_Error("System_RNG read failed", errno);
         }
      if(got == 0)
         throw System_Error("System_RNG EOF on device"); // ?!?

      buf += got;
      len -= got;
      }
   }

void System_RNG_Impl::add_entropy(const uint8_t input[], size_t len)
   {
   if(!m_writable)
      return;

   while(len)
      {
      ssize_t got = ::write(m_fd, input, len);

      if(got < 0)
         {
         if(errno == EINTR)
            continue;

         /*
         * This is seen on OS X CI, despite the fact that the man page
         * for macOS urandom explicitly states that writing to it is
         * supported, and write(2) does not document EPERM at all.
         * But in any case EPERM seems indicative of a policy decision
         * by the OS or sysadmin that additional entropy is not wanted
         * in the system pool, so we accept that and return here,
         * since there is no corrective action possible.
         *
         * In Linux EBADF or EPERM is returned if m_fd is not opened for
         * writing.
         */
         if(errno == EPERM || errno == EBADF)
            return;

         // maybe just ignore any failure here and return?
         throw System_Error("System_RNG write failed", errno);
         }

      input += got;
      len -= got;
      }
   }

#endif

}

RandomNumberGenerator& system_rng()
   {
   static System_RNG_Impl g_system_rng;
   return g_system_rng;
   }

}
