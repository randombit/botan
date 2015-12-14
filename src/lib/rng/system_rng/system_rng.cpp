/*
* System RNG
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/system_rng.h>

#if defined(BOTAN_TARGET_OS_HAS_CRYPTGENRANDOM)

#include <windows.h>
#include <wincrypt.h>
#undef min
#undef max

#else

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#endif

namespace Botan {

namespace {

class System_RNG_Impl : public RandomNumberGenerator
   {
   public:
      System_RNG_Impl();
      ~System_RNG_Impl();

      void randomize(byte buf[], size_t len) override;

      bool is_seeded() const override { return true; }
      void clear() override {}
      std::string name() const override { return "system"; }

      size_t reseed_with_sources(Entropy_Sources&,
                                 size_t /*poll_bits*/,
                                 std::chrono::milliseconds /*timeout*/) override
         {
         // We ignore it and assert the PRNG is seeded.
         // TODO: could poll and write it to /dev/urandom to help seed it
         return 0;
         }

      void add_entropy(const byte[], size_t) override
         {
         }
   private:

#if defined(BOTAN_TARGET_OS_HAS_CRYPTGENRANDOM)
      HCRYPTPROV m_prov;
#else
      int m_fd;
#endif
   };

System_RNG_Impl::System_RNG_Impl()
   {
#if defined(BOTAN_TARGET_OS_HAS_CRYPTGENRANDOM)

   if(!CryptAcquireContext(&m_prov, 0, 0, BOTAN_SYSTEM_RNG_CRYPTOAPI_PROV_TYPE, CRYPT_VERIFYCONTEXT))
      throw Exception("System_RNG failed to acquire crypto provider");

#else

#ifndef O_NOCTTY
  #define O_NOCTTY 0
#endif

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

void System_RNG_Impl::randomize(byte buf[], size_t len)
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
