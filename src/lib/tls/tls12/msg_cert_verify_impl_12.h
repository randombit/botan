/*
* TLS Certificate Verify Message - implementation for TLS 1.2
* (C) 2004-2011,2015 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MSG_CERT_VERIFY_IMPL_12_H_
#define BOTAN_MSG_CERT_VERIFY_IMPL_12_H_

#include <botan/internal/msg_cert_verify_impl.h>
#include <vector>

namespace Botan {

class RandomNumberGenerator;
class Private_Key;

namespace TLS {

class Handshake_IO;
class Handshake_State;
class Policy;

/**
* Certificate Verify Message TLSv1.2 implementation
*/
class Certificate_Verify_Impl_12 final : public Certificate_Verify_Impl
   {
   public:
      explicit Certificate_Verify_Impl_12(Handshake_IO& io,
                                          Handshake_State& state,
                                          const Policy& policy,
                                          RandomNumberGenerator& rng,
                                          const Private_Key* key);

      explicit Certificate_Verify_Impl_12(const std::vector<uint8_t>& buf);

      std::vector<uint8_t> serialize() const override;
   };
}

}

#endif
