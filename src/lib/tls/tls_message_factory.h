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
#include <botan/p11_x509.h>
#include <botan/internal/tls_mock_msg_impl_13.h>

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
class Client_Hello_Impl_13;
class Certificate_Req_Impl_12;
class Certificate_Verify_Impl_12;
class Certificate_Impl_12;
class Finished_Impl_12;

class TLS_Message_Factory
   {
   public:
      template<typename Message_Base_Type, Protocol_Version::Version_Code Version>
      struct Impl_Version_Trait{};

      template <typename Message_Base_Type, Protocol_Version::Version_Code Version, typename ... Args>
      static std::unique_ptr<Message_Base_Type> create(Args&& ... args)
         {
         return std::make_unique<typename Impl_Version_Trait<Message_Base_Type, Version>::Ver_Impl>(std::forward<Args>(args) ... );
         }
   };

template<>
struct TLS_Message_Factory::Impl_Version_Trait<Server_Hello_Impl, Protocol_Version::TLS_V12>
   {
   using Ver_Impl = Server_Hello_Impl_12;
   };

template<>
struct TLS_Message_Factory::Impl_Version_Trait<Server_Hello_Impl, Protocol_Version::TLS_V13>
   {
   using Ver_Impl = Server_Hello_Impl_12; // TODO using Ver_Impl = Server_Hello_Impl_13
   };

template<>
struct TLS_Message_Factory::Impl_Version_Trait<Client_Hello_Impl, Protocol_Version::TLS_V12>
   {
   using Ver_Impl = Client_Hello_Impl_12;
   };

template<>
struct TLS_Message_Factory::Impl_Version_Trait<Client_Hello_Impl, Protocol_Version::TLS_V13>
   {
   using Ver_Impl = Mock_Impl_13<Client_Hello_Impl>; // TODO using Ver_Impl = Client_Hello_Impl_13
   };

template<>
struct TLS_Message_Factory::Impl_Version_Trait<Certificate_Req_Impl, Protocol_Version::TLS_V12>
   {
   using Ver_Impl = Certificate_Req_Impl_12;
   };

template<>
struct TLS_Message_Factory::Impl_Version_Trait<Certificate_Req_Impl, Protocol_Version::TLS_V13>
   {
   using Ver_Impl = Mock_Certificate_Req_Impl_13; // TODO using Ver_Impl = Certificate_Req_Impl_13
   };

template<>
struct TLS_Message_Factory::Impl_Version_Trait<Certificate_Verify_Impl, Protocol_Version::TLS_V12>
   {
   using Ver_Impl = Certificate_Verify_Impl_12;
   };

template<>
struct TLS_Message_Factory::Impl_Version_Trait<Certificate_Verify_Impl, Protocol_Version::TLS_V13>
   {
   using Ver_Impl = Mock_Impl_13<Certificate_Verify_Impl>; // TODO  using Ver_Impl = Certificate_Verify_Impl_13
   };

template<>
struct TLS_Message_Factory::Impl_Version_Trait<Certificate_Impl, Protocol_Version::TLS_V12>
   {
   using Ver_Impl = Certificate_Impl_12;
   };

template<>
struct TLS_Message_Factory::Impl_Version_Trait<Certificate_Impl, Protocol_Version::TLS_V13>
   {
   using Ver_Impl = Mock_Certificate_Impl_13; // TODO using Ver_Impl = Certificate_Impl_13
   };

template<>
struct TLS_Message_Factory::Impl_Version_Trait<Finished_Impl, Protocol_Version::TLS_V12>
   {
   using Ver_Impl = Finished_Impl_12;
   };

template<>
struct TLS_Message_Factory::Impl_Version_Trait<Finished_Impl, Protocol_Version::TLS_V13>
   {
   using Ver_Impl = Mock_Impl_13<Finished_Impl>; // TODO using Ver_Impl = Finished_Impl_13
   };

}
}


#endif
