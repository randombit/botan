/*
 * TLS Context
 * (C) 2018-2019 Jack Lloyd
 *     2018-2019 Hannes Rantzsch, Tim Oesterreich, Rene Meusel
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_ASIO_TLS_CONTEXT_H_
#define BOTAN_ASIO_TLS_CONTEXT_H_

#include <botan/build.h>

#include <boost/version.hpp>
#if BOOST_VERSION >= 106600

#include <functional>

#include <botan/credentials_manager.h>
#include <botan/ocsp.h>
#include <botan/rng.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_policy.h>
#include <botan/tls_server_info.h>
#include <botan/tls_session_manager.h>

namespace Botan {
namespace TLS {

namespace detail {
template <typename FunT>
struct fn_signature_helper : public std::false_type {};

template <typename R, typename D, typename... Args>
struct fn_signature_helper<R(D::*)(Args...)>
   {
   using type = std::function<R(Args...)>;
   };
}  // namespace detail

/**
 * A helper class to initialize and configure Botan::TLS::Stream
 */
class Context
   {
   public:
      // statically extract the function signature type from Callbacks::tls_verify_cert_chain
      // and reuse it as an std::function<> for the verify callback signature
      using Verify_Callback =
         detail::fn_signature_helper<decltype(&Callbacks::tls_verify_cert_chain)>::type;

      Context(Credentials_Manager*   credentialsManager,
              RandomNumberGenerator* randomNumberGenerator,
              Session_Manager*       sessionManager,
              Policy*                policy,
              Server_Information     serverInfo = Server_Information()) :
         credentialsManager(credentialsManager),
         randomNumberGenerator(randomNumberGenerator),
         sessionManager(sessionManager),
         policy(policy),
         serverInfo(serverInfo)
         {}

      Context(const Context& other) = delete;
      Context& operator=(const Context& other) = delete;
      Context(Context&& other) = default;
      Context& operator=(Context&& other) = default;

      /**
       * @brief Override the tls_verify_cert_chain callback
       *
       * This changes the verify_callback in the stream's TLS::Context, and hence the tls_verify_cert_chain callback
       * used in the handshake.
       * Using this function is equivalent to setting the callback via @see Botan::TLS::Stream::set_verify_callback
       */
      void set_verify_callback(Verify_Callback callback)
         {
         verifyCallback = std::move(callback);
         }

      bool has_verify_callback() const
         {
         return static_cast<bool>(verifyCallback);
         }

   protected:
      template <class S, class C> friend class Stream;

      Credentials_Manager*   credentialsManager;
      RandomNumberGenerator* randomNumberGenerator;
      Session_Manager*       sessionManager;
      Policy*                policy;

      Server_Information     serverInfo;
      Verify_Callback        verifyCallback;

   };
}  // namespace TLS
}  // namespace Botan

#endif  // BOOST_VERSION
#endif  // BOTAN_ASIO_TLS_CONTEXT_H_
