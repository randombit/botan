/*
* Certificate Status
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages_12.h>

#include <botan/internal/tls_handshake_hash.h>
#include <botan/internal/tls_handshake_io.h>

namespace Botan::TLS {

Certificate_Status_12::Certificate_Status_12(Handshake_IO& io,
                                             Handshake_Hash& hash,
                                             std::vector<uint8_t> raw_response_bytes) :
      Certificate_Status(std::move(raw_response_bytes)) {
   hash.update(io.send(*this));
}

}  // namespace Botan::TLS
