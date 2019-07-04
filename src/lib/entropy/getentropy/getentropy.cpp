/*
* System Call getentropy(2)
* (C) 2017 Alexander Bluhm (genua GmbH)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/getentropy.h>

#if defined(BOTAN_TARGET_OS_IS_OPENBSD) || defined(BOTAN_TARGET_OS_IS_FREEBSD)
   #include <unistd.h>
#else
   #include <sys/random.h>
#endif

namespace Botan {

/**
* Gather 256 bytes entropy from getentropy(2).  Note that maximum
* buffer size is limited to 256 bytes.  On OpenBSD this does neither
* block nor fail.
*/
size_t Getentropy::poll(RandomNumberGenerator& rng)
   {
   secure_vector<uint8_t> buf(256);

   if(::getentropy(buf.data(), buf.size()) == 0)
      {
      rng.add_entropy(buf.data(), buf.size());
      return buf.size() * 8;
      }

   return 0;
   }
}
