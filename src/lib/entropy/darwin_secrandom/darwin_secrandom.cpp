/*
* Darwin SecRandomCopyBytes EntropySource
* (C) 2015 Daniel Seither (Kullo GmbH)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/darwin_secrandom.h>
#include <Security/Security.h>

namespace Botan {

/**
* Gather entropy from SecRandomCopyBytes
*/
void Darwin_SecRandom::poll(Entropy_Accumulator& accum)
   {
   const size_t ENTROPY_BITS_PER_BYTE = 8;
   const size_t BUF_SIZE = 256;

   m_buf.resize(BUF_SIZE);
   if (0 == SecRandomCopyBytes(kSecRandomDefault, m_buf.size(), m_buf.data()))
      {
      accum.add(m_buf.data(), m_buf.size(), ENTROPY_BITS_PER_BYTE);
      }
   }

}
