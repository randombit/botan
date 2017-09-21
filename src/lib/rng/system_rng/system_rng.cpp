/*
* System RNG
* (C) 2014,2015,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/system_rng.h>

#if defined(BOTAN_TARGET_OS_HAS_CRYPTGENRANDOM)
   #define NOMINMAX 1
   #define _WINSOCKAPI_ // stop windows.h including winsock.h
   #include <windows.h>
   #include <wincrypt.h>

#elif defined(BOTAN_TARGET_OS_HAS_CRYPTO_NG)
   #include <bcrypt.h>

#elif defined(BOTAN_TARGET_OS_HAS_ARC4RANDOM)
   #include <stdlib.h>

#else
   #include <sys/types.h>
   #include <sys/stat.h>
   #include <fcntl.h>
   #include <unistd.h>
   #include <errno.h>
#endif

namespace Botan {

namespace {

#if defined(BOTAN_TARGET_OS_HAS_CRYPTGENRANDOM)

class System_RNG_Impl final : public RandomNumberGenerator
   {
   public:
      System_RNG_Impl()
         {
         if(!CryptAcquireContext(&m_prov, nullptr, nullptr,
                                 BOTAN_SYSTEM_RNG_CRYPTOAPI_PROV_TYPE, CRYPT_VERIFYCONTEXT))
            throw Exception("System_RNG failed to acquire crypto provider");
         }

      ~System_RNG_Impl()
         {
         ::CryptReleaseContext(m_prov, 0);
         }

      void randomize(uint8_t buf[], size_t len) override
         {
         ::CryptGenRandom(m_prov, static_cast<DWORD>(len), buf);
         }

      void add_entropy(const uint8_t in[], size_t length) override
         {
         /*
         There is no explicit ConsumeRandom, but all values provided in
         the call are incorporated into the state.
         */
         std::vector<uint8_t> buf(in, in + length);
         ::CryptGenRandom(m_prov, static_cast<DWORD>(buf.size()), buf.data());
         }

      bool is_seeded() const override { return true; }
      void clear() override {}
      std::string name() const override { return "cryptoapi"; }
   private:
      HCRYPTPROV m_prov;
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
            throw Exception("System_RNG failed to acquire crypto provider");
         }

      ~System_RNG_Impl()
         {
         ::BCryptCloseAlgorithmProvider(m_prov, 0);
         }

      void randomize(uint8_t buf[], size_t len) override
         {
         ::BCryptGenRandom(m_prov, static_cast<PUCHAR>(buf), static_cast<ULONG>(len), 0);
         }

      void add_entropy(const uint8_t in[], size_t length) override
         {
         /*
         There is a flag BCRYPT_RNG_USE_ENTROPY_IN_BUFFER to provide
         entropy inputs, but it is ignored in Windows 8 and later.
         */
         }

      bool is_seeded() const override { return true; }
      void clear() override {}
      std::string name() const override { return "crypto_ng"; }
   private:
      BCRYPT_ALG_HANDLE m_handle;
   };

#elif defined(BOTAN_TARGET_OS_HAS_ARC4RANDOM)

class System_RNG_Impl final : public RandomNumberGenerator
   {
   public:
      // No constructor or destructor needed as no userland state maintained

      void randomize(uint8_t buf[], size_t len) override
         {
         ::arc4random_buf(buf, len);
         }

      void add_entropy(const uint8_t[], size_t) override { /* ignored */ }
      bool is_seeded() const override { return true; }
      void clear() override {}
      std::string name() const override { return "arc4random"; }
   };

#else

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

         /*
         Cannot open in read-write mode. Fall back to read-only,
         calls to add_entropy will fail, but randomize will work
         */
         if(m_fd < 0)
            m_fd = ::open(BOTAN_SYSTEM_RNG_DEVICE, O_RDONLY | O_NOCTTY);

         if(m_fd < 0)
            throw Exception("System_RNG failed to open RNG device");
         }

      ~System_RNG_Impl()
         {
         ::close(m_fd);
         m_fd = -1;
         }

      void randomize(uint8_t buf[], size_t len) override;
      void add_entropy(const uint8_t in[], size_t length) override;
      bool is_seeded() const override { return true; }
      void clear() override {}
      std::string name() const override { return BOTAN_SYSTEM_RNG_DEVICE; }
   private:
      int m_fd;
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
         throw Exception("System_RNG read failed error " + std::to_string(errno));
         }
      if(got == 0)
         throw Exception("System_RNG EOF on device"); // ?!?

      buf += got;
      len -= got;
      }
   }

void System_RNG_Impl::add_entropy(const uint8_t input[], size_t len)
   {
   while(len)
      {
      ssize_t got = ::write(m_fd, input, len);

      if(got < 0)
         {
         if(errno == EINTR)
            continue;

         /*
         * This is seen on OS X CI, despite the fact that the man page
         * for Darwin urandom explicitly states that writing to it is
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
         throw Exception("System_RNG write failed error " + std::to_string(errno));
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
