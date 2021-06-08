/*
* TLS Finished Message - implementation for TLS 1.2
* (C) 2004-2011,2015 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MSG_FINISHED_IMPL_12_H_
#define BOTAN_MSG_FINISHED_IMPL_12_H_

#include <botan/tls_magic.h>
#include <botan/internal/msg_finished_impl.h>
#include <vector>

namespace Botan {

namespace TLS {

class Handshake_IO;
class Handshake_State;

/**
* Finished Message TLSv1.2 implementation
*/
class Finished_Impl_12 final : public Finished_Impl
   {
   public:
      explicit Finished_Impl_12(Handshake_IO& io,
                                Handshake_State& state,
                                Connection_Side side);

      explicit Finished_Impl_12(const std::vector<uint8_t>& buf);
   };
}

}

#endif
