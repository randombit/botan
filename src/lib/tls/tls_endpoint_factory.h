/*
* TLS Endpoint Factory
* (C) 2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_ENDPOINT_FACTORY_H_
#define BOTAN_TLS_ENDPOINT_FACTORY_H_

#include <botan/tls_version.h>

#include <exception>
#include <vector>
#include <memory>

namespace Botan {

namespace TLS {

class Client_Impl;
class Server_Impl;

class Client_Impl_12;
class Server_Impl_12;
class Client_Impl_13;
class Server_Impl_13;

class TLS_Endpoint_Factory
   {
   public:
      template<typename Endpint_Base_Type, Protocol_Version::Version_Code Version>
      struct Impl_Version_Trait{};

      template <typename Endpint_Base_Type, Protocol_Version::Version_Code Version, typename ... Args>
      static std::unique_ptr<Endpint_Base_Type> create(Args&& ... args)
         {
         return std::make_unique<typename Impl_Version_Trait<Endpint_Base_Type, Version>::Ver_Impl>(std::forward<Args>(args) ... );
         }
   };

template<>
struct TLS_Endpoint_Factory::Impl_Version_Trait<Client_Impl, Protocol_Version::TLS_V12>
   {
   using Ver_Impl = Client_Impl_12;
   };

#if defined(BOTAN_HAS_TLS_13)
template<>
struct TLS_Endpoint_Factory::Impl_Version_Trait<Client_Impl, Protocol_Version::TLS_V13>
   {
   using Ver_Impl = Client_Impl_13;
   };
#endif

}
}

#endif
