/*
* System RNG
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/system_rng.h>

#if defined(BOTAN_TARGET_OS_HAS_CRYPTGENRANDOM)

#include <windows.h>
#define NOMINMAX 1
#include <wincrypt.h>

#else

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#endif

namespace Botan {

namespace {

class System_RNG_Impl final : public RandomNumberGenerator
   {
   public:
      System_RNG_Impl();
      ~System_RNG_Impl();

      bool is_seeded() const override { return true; }

      void clear() override {}

      void randomize(uint8_t out[], size_t len) override;

      void add_entropy(const uint8_t in[], size_t length) override;

      std::string name() const override;

   private:
#if defined(BOTAN_TARGET_OS_HAS_CRYPTGENRANDOM)
      HCRYPTPROV m_prov;
#else
      int m_fd;
#endif
   };

std::string System_RNG_Impl::name() const
   {
#if defined(BOTAN_TARGET_OS_HAS_CRYPTGENRANDOM)
   return "cryptoapi";
#else
   return BOTAN_SYSTEM_RNG_DEVICE;
#endif
   }

System_RNG_Impl::System_RNG_Impl()
   {
#if defined(BOTAN_TARGET_OS_HAS_CRYPTGENRANDOM)

   if(!CryptAcquireContext(&m_prov, 0, 0, BOTAN_SYSTEM_RNG_CRYPTOAPI_PROV_TYPE, CRYPT_VERIFYCONTEXT))
      throw Exception("System_RNG failed to acquire crypto provider");

#else

#ifndef O_NOCTTY
  #define O_NOCTTY 0
#endif

   m_fd = ::open(BOTAN_SYSTEM_RNG_DEVICE, O_RDWR | O_NOCTTY);
   
   // Cannot open in read-write mode. Fall back to read-only
   // Calls to add_entropy will fail, but randomize will work
   if(m_fd < 0)
      m_fd = ::open(BOTAN_SYSTEM_RNG_DEVICE, O_RDONLY | O_NOCTTY);

   if(m_fd < 0)
      throw Exception("System_RNG failed to open RNG device");
#endif
   }

System_RNG_Impl::~System_RNG_Impl()
   {
#if defined(BOTAN_TARGET_OS_HAS_CRYPTGENRANDOM)
   ::CryptReleaseContext(m_prov, 0);
#else
   ::close(m_fd);
   m_fd = -1;
#endif
   }

void System_RNG_Impl::add_entropy(const uint8_t input[], size_t len)
   {
#if defined(BOTAN_TARGET_OS_HAS_CRYPTGENRANDOM)
   /*
   There is no explicit ConsumeRandom, but all values provided in
   the call are incorporated into the state.

   TODO: figure out a way to avoid this copy. Byte at a time updating
   seems worse than the allocation.

   for(size_t i = 0; i != len; ++i)
      {
      uint8_t b = input[i];
      ::CryptGenRandom(m_prov, 1, &b);
      }
   */

   if(len > 0)
      {
      secure_vector<uint8_t> buf(input, input + len);
      ::CryptGenRandom(m_prov, static_cast<DWORD>(buf.size()), buf.data());
      }
#else
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
#endif
   }

void System_RNG_Impl::randomize(uint8_t buf[], size_t len)
   {
#if defined(BOTAN_TARGET_OS_HAS_CRYPTGENRANDOM)
   ::CryptGenRandom(m_prov, static_cast<DWORD>(len), buf);
#else
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
#endif
   }

}

RandomNumberGenerator& system_rng()
   {
   static System_RNG_Impl g_system_rng;
   return g_system_rng;
   }

}
