/*
 * TLS Context
 * (C) 2018-2020 Jack Lloyd
 *     2018-2020 Hannes Rantzsch, Tim Oesterreich, Rene Meusel
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_ASIO_TLS_CONTEXT_H_
#define BOTAN_ASIO_TLS_CONTEXT_H_

#include <botan/asio_compat.h>
#if defined(BOTAN_FOUND_COMPATIBLE_BOOST_ASIO_VERSION)

   #include <functional>

   #include <botan/credentials_manager.h>
   #include <botan/ocsp.h>
   #include <botan/rng.h>
   #include <botan/tls_callbacks.h>
   #include <botan/tls_policy.h>
   #include <botan/tls_server_info.h>
   #include <botan/tls_session_manager.h>

   #if defined(BOTAN_HAS_AUTO_SEEDING_RNG) && defined(BOTAN_HAS_CERTSTOR_SYSTEM)
      #define BOTAN_HAS_HAS_DEFAULT_TLS_CONTEXT
   #endif

namespace Botan::TLS {

namespace detail {
template <typename FunT>
struct fn_signature_helper : public std::false_type {};

template <typename R, typename D, typename... Args>
struct fn_signature_helper<R (D::*)(Args...)> {
      using type = std::function<R(Args...)>;
};
}  // namespace detail

/**
 * A helper class to initialize and configure Botan::TLS::Stream
 */
class BOTAN_PUBLIC_API(2, 11) Context {
   public:
      // statically extract the function signature type from Callbacks::tls_verify_cert_chain
      // and reuse it as an std::function<> for the verify callback signature
      /**
       * The signature of the callback function should correspond to the signature of
       * Callbacks::tls_verify_cert_chain
       */
      using Verify_Callback = detail::fn_signature_helper<decltype(&Callbacks::tls_verify_cert_chain)>::type;

   #if defined(BOTAN_HAS_HAS_DEFAULT_TLS_CONTEXT)
      /**
       * @brief Construct a TLS stream context with typical defaults
       *
       * @param server_info  Basic information about the host to connect to (SNI)
       */
      Context(Server_Information server_info = Server_Information());
   #endif

      Context(std::shared_ptr<Credentials_Manager> credentials_manager,
              std::shared_ptr<RandomNumberGenerator> rng,
              std::shared_ptr<Session_Manager> session_manager,
              std::shared_ptr<const Policy> policy,
              Server_Information server_info = Server_Information()) :
            m_credentials_manager(credentials_manager),
            m_rng(rng),
            m_session_manager(session_manager),
            m_policy(policy),
            m_server_info(std::move(server_info)) {}

      virtual ~Context() = default;

      Context(Context&&) = default;
      Context(const Context&) = delete;
      Context& operator=(const Context&) = delete;
      Context& operator=(Context&&) = delete;

      /**
       * @brief Override the tls_verify_cert_chain callback
       *
       * This changes the verify_callback in the stream's TLS::Context, and hence the tls_verify_cert_chain callback
       * used in the handshake.
       * Using this function is equivalent to setting the callback via @see Botan::TLS::Stream::set_verify_callback
       *
       * @note This function should only be called before initiating the TLS handshake
       */
      void set_verify_callback(Verify_Callback callback) { m_verify_callback = std::move(callback); }

      bool has_verify_callback() const { return static_cast<bool>(m_verify_callback); }

      const Verify_Callback& get_verify_callback() const { return m_verify_callback; }

      void set_server_info(Server_Information server_info) { m_server_info = std::move(server_info); }

   protected:
      template <class S, class C>
      friend class Stream;

      std::shared_ptr<Credentials_Manager> m_credentials_manager;
      std::shared_ptr<RandomNumberGenerator> m_rng;
      std::shared_ptr<Session_Manager> m_session_manager;
      std::shared_ptr<const Policy> m_policy;

      Server_Information m_server_info;
      Verify_Callback m_verify_callback;
};

}  // namespace Botan::TLS

#endif
#endif  // BOTAN_ASIO_TLS_CONTEXT_H_
