/*
* Finished Message
* (C) 2004-2006,2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/msg_finished_impl_12.h>

namespace Botan {

namespace TLS {

/*
* Create a new Finished message
*/
Finished_Impl_12::Finished_Impl_12(Handshake_IO& io,
                                   Handshake_State& state,
                                   Connection_Side side) :
   Finished_Impl(io, state, side)
   {
   }

/*
* Create a new Finished message
*/
Finished_Impl_12::Finished_Impl_12(const std::vector<uint8_t>& buf) : Finished_Impl(buf)
   {}
}

}
