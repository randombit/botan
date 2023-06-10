/*
* Key Update message
* (C) 2022 Jack Lloyd
*     2022 René Meusel, Hannes Rantzsch - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages.h>

#include <botan/tls_exceptn.h>

namespace Botan::TLS {

Key_Update::Key_Update(const bool request_peer_update) : m_update_requested(request_peer_update) {}

Key_Update::Key_Update(const std::vector<uint8_t>& buf) {
   if(buf.size() != 1) {
      throw TLS_Exception(Alert::DecodeError, "malformed key_update");
   }

   // RFC 8446 4.6.3
   //    If an implementation receives any other value [than 0 or 1], it MUST
   //    terminate the connection with an "illegal_parameter" alert.
   const uint8_t update_requested = buf.at(0);
   if(update_requested > 1) {
      throw TLS_Exception(Alert::IllegalParameter, "unexpected key_update parameter");
   }

   m_update_requested = update_requested == 1;
}

std::vector<uint8_t> Key_Update::serialize() const {
   return std::vector<uint8_t>(1, (m_update_requested ? 1 : 0));
}

}  // namespace Botan::TLS
