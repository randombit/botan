/*
* TLS Messages Factory
* (C) 2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_MESSAGE_FACTORY_H_
#define BOTAN_TLS_MESSAGE_FACTORY_H_

#include <botan/tls_messages.h>
#include <botan/tls_version.h>
#include <botan/internal/stl_util.h>

#include <exception>
#include <vector>
#include <memory>

namespace Botan {

namespace TLS {

class Client_Hello_Impl;
class Server_Hello_Impl;
class Finished_Impl;
class Certificate_Verify_Impl;
class Certificate_Req_Impl;
class Certificate_Impl;

class Server_Hello_Impl_12;
class Client_Hello_Impl_12;
class Certificate_Req_Impl_12;
class Certificate_Verify_Impl_12;
class Certificate_Impl_12;
class Finished_Impl_12;

class Client_Hello_Impl_13;

namespace {

template<typename Message_Base_Type>
struct implementation_trait{};

template<>
struct implementation_trait<Server_Hello_Impl>
   {
   using v12 = Server_Hello_Impl_12;
   using v13 = Server_Hello_Impl_12;  // TODO fixme
   };

template<>
struct implementation_trait<Client_Hello_Impl>
   {
   using v12 = Client_Hello_Impl_12;
   using v13 = Client_Hello_Impl_13;
   };

template<>
struct implementation_trait<Certificate_Req_Impl>
   {
   using v12 = Certificate_Req_Impl_12;
   using v13 = Certificate_Req_Impl_12;  // TODO fixme
   };

template<>
struct implementation_trait<Certificate_Verify_Impl>
   {
   using v12 = Certificate_Verify_Impl_12;
   using v13 = Certificate_Verify_Impl_12;  // TODO fixme
   };

template<>
struct implementation_trait<Certificate_Impl>
   {
   using v12 = Certificate_Impl_12;
   using v13 = Certificate_Impl_12;  // TODO fixme
   };

template<>
struct implementation_trait<Finished_Impl>
   {
   using v12 = Finished_Impl_12;
   using v13 = Finished_Impl_12;  // TODO fixme
   };

}

namespace Message_Factory {

template <typename MessageBaseT, typename... ParamTs>
std::unique_ptr<MessageBaseT> create(const Protocol_Version &protocol_version, ParamTs&&... parameters)
   {
   using impl_t = implementation_trait<MessageBaseT>;

   switch (protocol_version.version_code()) {
#if defined(BOTAN_HAS_TLS_13)
     case Protocol_Version::TLS_V13:
       return std::make_unique<typename impl_t::v13>(std::forward<ParamTs>(parameters)...);
#endif
     case Protocol_Version::TLS_V12:
     case Protocol_Version::DTLS_V12:
       return std::make_unique<typename impl_t::v12>(std::forward<ParamTs>(parameters)...);
     default:
       BOTAN_ASSERT(false, "unexpected protocol version");
     }
   }

template <typename MessageBaseT, typename... ParamTs>
std::unique_ptr<MessageBaseT> create(std::vector<Protocol_Version> supported_versions, ParamTs&&... parameters)
   {
#if defined(BOTAN_HAS_TLS_13)
   const auto protocol_version =
      value_exists(supported_versions, Protocol_Version(Protocol_Version::TLS_V13))
         ? Protocol_Version::TLS_V13
         : Protocol_Version::TLS_V12;
#else
   BOTAN_UNUSED(supported_versions);
   const auto protocol_version = Protocol_Version::TLS_V12;
#endif

   return create<MessageBaseT>(protocol_version, std::forward<ParamTs>(parameters)...);
   }
}
}
}

#endif
