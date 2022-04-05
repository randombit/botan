/*
* TLS handshake state (machine) implementation for TLS 1.3
* (C) 2022 Jack Lloyd
*     2022 Hannes Rantzsch, René Meusel - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_HANDSHAKE_STATE_13_H_
#define BOTAN_TLS_HANDSHAKE_STATE_13_H_

#include <optional>
#include <variant>
#include <vector>
#include <functional>

#include <botan/tls_magic.h>
#include <botan/tls_messages.h>
#include <botan/tls_exceptn.h>

namespace Botan::TLS {

namespace Internal {
class BOTAN_TEST_API Handshake_State_13_Base
   {
   public:
      bool has_client_hello() const { return m_client_hello.has_value(); }
      bool has_hello_retry_request() const { return m_hello_retry_request.has_value(); }
      bool has_server_finished() const { return m_server_finished.has_value(); }
      bool has_client_finished() const { return m_client_finished.has_value(); }

      bool handshake_finished() const { return has_server_finished() && has_client_finished(); }

      // Client_Hello_13 cannot be const because it might need modification due to a Hello_Retry_Request
      Client_Hello_13&             client_hello() { return get(m_client_hello); }
      const Server_Hello_13&       server_hello() const { return get(m_server_hello); }
      const Hello_Retry_Request&   hello_retry_request() const { return get(m_hello_retry_request); }
      const Encrypted_Extensions&  encrypted_extensions() const { return get(m_encrypted_extensions); }
      const Certificate_13&        certificate() const { return get(m_server_certs); }
      const Certificate_Verify_13& certificate_verify() const { return get(m_server_verify); }
      const Finished_13&           client_finished() const { return get(m_client_finished); }
      const Finished_13&           server_finished() const { return get(m_server_finished); }

   protected:
      Handshake_State_13_Base(Connection_Side whoami) : m_side(whoami) {}

      Client_Hello_13&       store(Client_Hello_13 client_hello, const bool from_peer);
      Server_Hello_13&       store(Server_Hello_13 server_hello, const bool from_peer);
      Server_Hello_12&       store(Server_Hello_12 server_hello, const bool from_peer);
      Hello_Retry_Request&   store(Hello_Retry_Request hello_retry_request, const bool from_peer);
      Encrypted_Extensions&  store(Encrypted_Extensions encrypted_extensions, const bool from_peer);
      Certificate_13&        store(Certificate_13 certificate, const bool from_peer);
      Certificate_Verify_13& store(Certificate_Verify_13 certificate_verify, const bool from_peer);
      Finished_13&           store(Finished_13 finished, const bool from_peer);

   private:
      template<typename MessageT>
      const MessageT& get(const std::optional<MessageT>& opt) const
         {
         if(!opt.has_value())
            { throw Invalid_State("TLS handshake message not set"); }
         return opt.value();
         }

      template<typename MessageT>
      MessageT& get(std::optional<MessageT>& opt)
         {
         if(!opt.has_value())
            { throw Invalid_State("TLS handshake message not set"); }
         return opt.value();
         }

      Connection_Side m_side;

      std::optional<Client_Hello_13> m_client_hello;
      std::optional<Server_Hello_13> m_server_hello;
      std::optional<Server_Hello_12> m_server_hello_12;
      std::optional<Hello_Retry_Request> m_hello_retry_request;
      std::optional<Encrypted_Extensions> m_encrypted_extensions;
      std::optional<Certificate_13> m_server_certs;
      std::optional<Certificate_Verify_13> m_server_verify;
      std::optional<Finished_13> m_server_finished;
      std::optional<Finished_13> m_client_finished;
   };
}

/**
 * Place to store TLS handshake messages
 *
 * This class is used to keep all handshake messages that have been received from and sent to
 * the peer as part of the TLS 1.3 handshake. Getters are provided for all message types.
 * Specializations for the client and server side provide specific setters in the form of
 * `sent` and `received` that only allow those types of handshake messages that are sensible
 * for the respective connection side.
 *
 * The handshake state machine as described in RFC 8446 Appendix A is NOT validated here.
 */
template <Connection_Side whoami, typename Outbound_Message_T, typename Inbound_Message_T>
class BOTAN_TEST_API Handshake_State_13 : public Internal::Handshake_State_13_Base
   {
   public:
      Handshake_State_13() : Handshake_State_13_Base(whoami) {}

      decltype(auto) sent(Outbound_Message_T message)
         {
         return std::visit([&](auto msg) -> Handshake_Message_13_Ref
            {
            return std::reference_wrapper<decltype(msg)>(store(std::move(msg), false));
            }, std::move(message));
         }

      decltype(auto) received(Handshake_Message_13 message)
         {
         return std::visit([&](auto msg) -> as_wrapped_references_t<Inbound_Message_T>
            {
            if constexpr(std::is_constructible_v<Inbound_Message_T, decltype(msg)>)
               {
               return std::reference_wrapper<decltype(msg)>(store(std::move(msg), true));
               }

            throw TLS_Exception(Alert::UNEXPECTED_MESSAGE, "received an illegal handshake message");
            }, std::move(message));
         }
   };

using Client_Handshake_State_13 = Handshake_State_13<Connection_Side::CLIENT,
      Client_Handshake_13_Message,
      Server_Handshake_13_Message>;

using Server_Handshake_State_13 = Handshake_State_13<Connection_Side::SERVER,
      Server_Handshake_13_Message,
      Client_Handshake_13_Message>;
}

#endif
