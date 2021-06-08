/*
* TLS Server Hello Message - implementation for (D)TLS 1.2
* (C) 2004-2011,2015 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MSG_SERVER_HELLO_IMPL_12_H_
#define BOTAN_MSG_SERVER_HELLO_IMPL_12_H_

#include <botan/internal/msg_server_hello_impl.h>
#include <vector>
#include <string>

namespace Botan {

class RandomNumberGenerator;

namespace TLS {

class Client_Hello;
class Session;
class Handshake_IO;
class Handshake_Hash;
class Callbacks;
class Policy;

std::vector<uint8_t> make_hello_random(RandomNumberGenerator& rng,
                                       const Policy& policy);

/**
* Server Hello Message TLSv1.2 implementation
*/
class Server_Hello_Impl_12 final : public Server_Hello_Impl
   {
   public:
      explicit Server_Hello_Impl_12(Handshake_IO& io,
                                    Handshake_Hash& hash,
                                    const Policy& policy,
                                    Callbacks& cb,
                                    RandomNumberGenerator& rng,
                                    const std::vector<uint8_t>& secure_reneg_info,
                                    const Client_Hello& client_hello,
                                    const Server_Hello::Settings& settings,
                                    const std::string next_protocol);

      explicit Server_Hello_Impl_12(Handshake_IO& io,
                                    Handshake_Hash& hash,
                                    const Policy& policy,
                                    Callbacks& cb,
                                    RandomNumberGenerator& rng,
                                    const std::vector<uint8_t>& secure_reneg_info,
                                    const Client_Hello& client_hello,
                                    Session& resumed_session,
                                    bool offer_session_ticket,
                                    const std::string& next_protocol);

      explicit Server_Hello_Impl_12(const std::vector<uint8_t>& buf);
   };

}

}

#endif //BOTAN_TLS_SERVER_HELLO_IMPL_12_H_
