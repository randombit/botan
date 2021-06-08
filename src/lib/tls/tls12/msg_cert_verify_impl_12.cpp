/*
* Certificate Verify Message
* (C) 2004,2006,2011,2012 Jack Lloyd
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/msg_cert_verify_impl_12.h>
#include <botan/tls_messages.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_handshake_state.h>


namespace Botan {

namespace TLS {

/*
* Create a new Certificate Verify message
*/
Certificate_Verify_Impl_12::Certificate_Verify_Impl_12(Handshake_IO& io,
                                                       Handshake_State& state,
                                                       const Policy& policy,
                                                       RandomNumberGenerator& rng,
                                                       const Private_Key* priv_key) :
   Certificate_Verify_Impl(io, state, policy, rng, priv_key)
   {
   }

/*
* Deserialize a Certificate Verify message
*/
Certificate_Verify_Impl_12::Certificate_Verify_Impl_12(const std::vector<uint8_t>& buf) :
   Certificate_Verify_Impl(buf)
   {
   }

/*
* Serialize a Certificate Verify message
*/
std::vector<uint8_t> Certificate_Verify_Impl_12::serialize() const
   {
   return Certificate_Verify_Impl::serialize();
   }
}

}
