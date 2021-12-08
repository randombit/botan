/*
* TLS Mock Msg Impl 13 - TODO: this file should be deleted when TLS 1.3 implementation is ready
* (C) 2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_MOCK_MSG_IMPL_13_H_
#define BOTAN_TLS_MOCK_MSG_IMPL_13_H_

#include <botan/exceptn.h>
#include <botan/internal/msg_cert_req_impl.h>
#include <botan/internal/msg_certificate_impl.h>
#include <botan/tls_algos.h>

#include <vector>
#include <string>
#include <type_traits>

namespace Botan {

namespace TLS {

namespace detail {

template <typename RetT = void>
[[noreturn]] RetT nyi()
   {
   throw Not_Implemented("Implementation for TLSv1.3 not ready yet. You are welcome to implement it.");
   }

template <typename T>
inline constexpr bool must_be_upcalled = !std::is_abstract_v<T> && !std::is_default_constructible_v<T>;

template <typename T, typename Enable = void>
class Mock_Impl_13_Internal;

template <typename T>
class Mock_Impl_13_Internal<T, std::enable_if_t<!must_be_upcalled<T>>> : public T
{
public:
   template <typename... Args>
   Mock_Impl_13_Internal(Args&&...)
      {
      nyi();
      }

};

template <typename T>
class Mock_Impl_13_Internal<T, std::enable_if_t<must_be_upcalled<T>>> : public T
{
public:
   template <typename... Args>
   Mock_Impl_13_Internal(Args&&... args)
      : T(std::forward<Args>(args)...)
      {
      nyi();
      }

};

}

template <typename T>
class Mock_Impl_13 : public detail::Mock_Impl_13_Internal<T> {
   using detail::Mock_Impl_13_Internal<T>::Mock_Impl_13_Internal;
};

template<>
class Mock_Impl_13<Certificate_Impl> : public detail::Mock_Impl_13_Internal<Certificate_Impl> {
public:
   using Mock_Impl_13_Internal<Certificate_Impl>::Mock_Impl_13_Internal;

   const std::vector<X509_Certificate>& cert_chain() const override { return detail::nyi<const std::vector<X509_Certificate>&>(); }
   size_t count() const override { return detail::nyi<size_t>(); }
   bool empty() const override { return detail::nyi<bool>(); }
   std::vector<unsigned char> serialize() const override { return detail::nyi<std::vector<unsigned char>>(); }
};

template<>
class Mock_Impl_13<Certificate_Req_Impl> : public detail::Mock_Impl_13_Internal<Certificate_Req_Impl> {
public:
   using Mock_Impl_13_Internal<Certificate_Req_Impl>::Mock_Impl_13_Internal;

   const std::vector<std::string>& acceptable_cert_types() const override { return detail::nyi<const std::vector<std::string>&>(); }
   const std::vector<X509_DN>& acceptable_CAs() const override { return detail::nyi<const std::vector<X509_DN>&>(); }
   const std::vector<Signature_Scheme>& signature_schemes() const override { return detail::nyi<const std::vector<Signature_Scheme>&>(); }
   std::vector<unsigned char> serialize() const override { return detail::nyi<std::vector<unsigned char>>(); }
};

}
}


#endif
