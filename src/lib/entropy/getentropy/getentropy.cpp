/*
* System Call getentropy(2)
* (C) 2017 Alexander Bluhm (genua GmbH)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/getentropy.h>

#include <unistd.h>
 
#if defined(__APPLE__)
#if defined(__MAC_OS_X_VERSION_MIN_REQUIRED)
#if __MAC_OS_X_VERSION_MIN_REQUIRED >= 101200
/*
 * To enable genentropy() method on MacOS, you also need
 * to add "--with-os-features=getentropy
 */
#include <sys/random.h>
#endif
#endif /* __MAC_OS_X_VERSION_MIN_REQUIRED */
#endif /* __APPLE__ */

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
