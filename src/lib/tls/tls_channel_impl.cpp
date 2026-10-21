/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_channel_impl.h>

#include <botan/tls_exceptn.h>
#include <botan/tls_policy.h>

namespace Botan::TLS {

void Channel_Impl::note_useless_record(const Policy& policy) {
   m_useless_records++;

   if(const auto limit = policy.max_useless_records()) {
      if(m_useless_records > *limit) {
         throw TLS_Exception(Alert::UnexpectedMessage, "Peer sent too many consecutive useless records");
      }
   }
}

}  // namespace Botan::TLS
