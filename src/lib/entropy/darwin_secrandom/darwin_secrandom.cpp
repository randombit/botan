/*
* Darwin SecRandomCopyBytes EntropySource
* (C) 2015 Daniel Seither (Kullo GmbH)
* (C) 2016 Simon Warta (Kullo GmbH)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/exceptn.h>
#include <botan/internal/darwin_secrandom.h>
#include <Security/Security.h>

namespace Botan {

/**
* Gather entropy from SecRandomCopyBytes
*/
void Darwin_SecRandom::poll(Entropy_Accumulator& accum)
   {
   secure_vector<byte>& buf = accum.get_io_buf(BOTAN_SYSTEM_RNG_POLL_REQUEST);

   // kSecRandomDefault refers to a "cryptographically secure random number generator"
   // See http://www.opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55050.9/lib/SecRandom.h
   if(0 == ::SecRandomCopyBytes(::kSecRandomDefault, buf.size(), buf.data()))
      {
      accum.add(buf.data(), buf.size(), BOTAN_ENTROPY_ESTIMATE_STRONG_RNG);
      }
   else
      {
      throw Exception("SecRandomCopyBytes failed with errno = " + std::to_string(errno));
      }
   }

}
