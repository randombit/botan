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
#include <Security/SecRandom.h>

namespace Botan {

/**
* Gather entropy from SecRandomCopyBytes
*/
size_t Darwin_SecRandom::poll(RandomNumberGenerator& rng)
   {
   secure_vector<uint8_t> buf(BOTAN_SYSTEM_RNG_POLL_REQUEST);

   // kSecRandomDefault refers to a "cryptographically secure random number generator"
   // See http://www.opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55050.9/lib/SecRandom.h
   if(0 == ::SecRandomCopyBytes(::kSecRandomDefault, buf.size(), buf.data()))
      {
      rng.add_entropy(buf.data(), buf.size());
      return buf.size() * 8;
      }
   else
      {
      throw Exception("SecRandomCopyBytes failed with errno = " + std::to_string(errno));
      }
   }

}
