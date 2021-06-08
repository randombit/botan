/*
* TLS Client Hello Message - implementation for TLS 1.2
* (C) 2004-2011,2015 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MSG_CLIENT_HELLO_IMPL_12_H_
#define BOTAN_MSG_CLIENT_HELLO_IMPL_12_H_

#include <botan/tls_messages.h>
#include <botan/tls_extensions.h>
#include <botan/tls_handshake_msg.h>
#include <botan/internal/msg_client_hello_impl.h>
#include <vector>
#include <string>

namespace Botan {
namespace TLS {

class Session;
class Handshake_IO;
class Policy;
class Callbacks;

std::vector<uint8_t> make_hello_random(RandomNumberGenerator& rng,
                                       const Policy& policy);
/**
* Client Hello Message TLSv1.2 implementation
*/
class Client_Hello_Impl_12 final : public Client_Hello_Impl
   {
   public:
      explicit Client_Hello_Impl_12(Handshake_IO& io,
                                    Handshake_Hash& hash,
                                    const Policy& policy,
                                    Callbacks& cb,
                                    RandomNumberGenerator& rng,
                                    const std::vector<uint8_t>& reneg_info,
                                    const Client_Hello::Settings& client_settings,
                                    const std::vector<std::string>& next_protocols);

      explicit Client_Hello_Impl_12(Handshake_IO& io,
                                    Handshake_Hash& hash,
                                    const Policy& policy,
                                    Callbacks& cb,
                                    RandomNumberGenerator& rng,
                                    const std::vector<uint8_t>& reneg_info,
                                    const Session& resumed_session,
                                    const std::vector<std::string>& next_protocols);

      explicit Client_Hello_Impl_12(const std::vector<uint8_t>& buf);
   };

}

}

#endif
