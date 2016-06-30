/*
* Darwin SecRandomCopyBytes EntropySource
* (C) 2015 Daniel Seither (Kullo GmbH)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/darwin_secrandom.h>
#include <Security/Security.h>
#include <Security/SecRandom.h>

namespace Botan {

/**
* Gather entropy from SecRandomCopyBytes
*/
void Darwin_SecRandom::poll(Entropy_Accumulator& accum)
   {
   m_io_buf.resize(BOTAN_SYSTEM_RNG_POLL_REQUEST);

   if(0 == SecRandomCopyBytes(kSecRandomDefault, m_io_buf.size(), m_io_buf.data()))
      {
      accum.add(m_io_buf.data(), m_io_buf.size(), BOTAN_ENTROPY_ESTIMATE_STRONG_RNG);
      }
   }

}
