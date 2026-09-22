/*
* System Call getentropy(2)
* (C) 2017 Alexander Bluhm (genua GmbH)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/getentropy.h>

#include <botan/rng.h>
#include <unistd.h>

// macOS and Android include it in sys/random.h instead
#if __has_include(<sys/random.h>)
   #include <sys/random.h>
#endif

namespace Botan {

/**
* Gather 256 bytes entropy from getentropy(2).  Note that maximum
* buffer size is limited to 256 bytes.  On OpenBSD this does neither
* block nor fail.
*/
void Getentropy::gather(Entropy_Accumulator& acc) {
   secure_vector<uint8_t> buf(256);

   if(::getentropy(buf.data(), buf.size()) == 0) {
      acc.add(buf, buf.size() * 8);
   }
}

}  // namespace Botan
