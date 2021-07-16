/*
* TLS ClientHello Impl 1.3
* (C) 2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MSG_CLIENT_HELLO_IMPL_13_H_
#define BOTAN_MSG_CLIENT_HELLO_IMPL_13_H_

#include <botan/internal/msg_client_hello_impl.h>

#include <vector>
#include <exception>


namespace Botan {

namespace TLS {

class Client_Hello_Impl_13: public Client_Hello_Impl
   {
   public:
      explicit Client_Hello_Impl_13(Handshake_IO& io,
                                    Handshake_Hash& hash,
                                    const Policy& policy,
                                    Callbacks& cb,
                                    RandomNumberGenerator& rng,
                                    const std::vector<uint8_t>& reneg_info,
                                    const Client_Hello::Settings& client_settings,
                                    const std::vector<std::string>& next_protocols);

      explicit Client_Hello_Impl_13(Handshake_IO& io,
                                    Handshake_Hash& hash,
                                    const Policy& policy,
                                    Callbacks& cb,
                                    RandomNumberGenerator& rng,
                                    const std::vector<uint8_t>& reneg_info,
                                    const Session& resumed_session,
                                    const std::vector<std::string>& next_protocols);

      explicit Client_Hello_Impl_13(const std::vector<uint8_t>& buf);
   };

}

}

#endif
