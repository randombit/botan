/*
* System RNG
* (C) 2014 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/system_rng.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

namespace Botan {

namespace {

class System_RNG : public RandomNumberGenerator
   {
   public:
      System_RNG();
      ~System_RNG();

      void randomize(byte buf[], size_t len);

      bool is_seeded() const { return true; }
      void clear() {}
      std::string name() const { return "system"; }

      void reseed(size_t) {}
      void add_entropy(const byte[], size_t) {}
   private:
      int m_fd;
   };

System_RNG::System_RNG()
   {
   m_fd = ::open("/dev/urandom", O_RDONLY);
   if(m_fd < 0)
      throw std::runtime_error("System_RNG failed to open /dev/urandom");
   }

System_RNG::~System_RNG()
   {
   ::close(m_fd);
   }

void System_RNG::randomize(byte buf[], size_t len)
   {
   while(len)
      {
      ssize_t got = ::read(m_fd, buf, len);

      if(got < 0)
         {
         if(errno == EINTR)
            continue;
         throw std::runtime_error("System_RNG read failed error " + std::to_string(errno));
         }
      if(got == 0)
         throw std::runtime_error("System_RNG EOF on device"); // ?!?

      buf += got;
      len -= got;
      }
   }

}

RandomNumberGenerator& system_rng()
   {
   static System_RNG g_system_rng;
   return g_system_rng;
   }

}
