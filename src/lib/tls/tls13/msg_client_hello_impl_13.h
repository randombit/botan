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
      explicit Client_Hello_Impl_13()
         {
         // TODO throw std::runtime_error("Implemenation for TLSv1.3 not ready yet. You are welcome to implement it.");
         }

      explicit Client_Hello_Impl_13(const std::vector<uint8_t>& buf) : Client_Hello_Impl(buf)
         {
         // TODO throw std::runtime_error("Implemenation for TLSv1.3 not ready yet. You are welcome to implement it.");
         }
   };

}

}

#endif
