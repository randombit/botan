/*
* TLS Handshake State
* (C) 2004-2006,2011,2012 Jack Lloyd
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_HANDSHAKE_STATE_H_
#define BOTAN_TLS_HANDSHAKE_STATE_H_

#include <botan/pk_keys.h>
#include <botan/pubkey.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_ciphersuite.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_handshake_msg.h>
#include <botan/internal/tls_handshake_hash.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_handshake_transitions.h>
#include <botan/internal/tls_session_key.h>
#include <functional>
#include <optional>

namespace Botan {

class KDF;

namespace TLS {

class Callbacks;
class Policy;
class Signature_Scheme;

class Hello_Verify_Request;
class Client_Hello_12;
class Server_Hello_12;
class Certificate_12;
class Certificate_Status;
class Server_Key_Exchange;
class Certificate_Request_12;
class Server_Hello_Done;
class Client_Key_Exchange;
class Certificate_Verify_12;
class New_Session_Ticket_12;
class Finished_12;

/**
* SSL/TLS Handshake State
*
* This is a data holder object for all state aggregated during the handshake,
* both on client and server side and across protocol versions.
* It does not implement any logic and offers no guarantees regarding state
* consistency and legal TLS state transitions.
*
* TODO: currently it implements some logic for TLS 1.2, which should be removed
* TODO: investigate moving the handshake_io to the channel
*/
class Handshake_State {
   public:
      Handshake_State(std::unique_ptr<Handshake_IO> io, Callbacks& callbacks);
      virtual ~Handshake_State();

      Handshake_State(const Handshake_State&) = delete;
      Handshake_State& operator=(const Handshake_State&) = delete;

      Handshake_IO& handshake_io() { return *m_handshake_io; }

      /**
      * Return true iff we have received a particular message already
      * @param msg_type the message type
      */
      bool received_handshake_msg(Handshake_Type msg_type) const;

      /**
      * Confirm that we were expecting this message type
      * @param msg_type the message type
      */
      void confirm_transition_to(Handshake_Type msg_type);

      /**
      * Record that we are expecting a particular message type next
      * @param msg_type the message type
      */
      void set_expected_next(Handshake_Type msg_type);

      std::pair<Handshake_Type, std::vector<uint8_t>> get_next_handshake_msg();

      Session_Ticket session_ticket() const;

      std::pair<std::string, Signature_Format> parse_sig_format(const Public_Key& key,
                                                                Signature_Scheme scheme,
                                                                const std::vector<Signature_Scheme>& offered_schemes,
                                                                bool for_client_auth,
                                                                const Policy& policy) const;

      std::pair<std::string, Signature_Format> choose_sig_format(const Private_Key& key,
                                                                 Signature_Scheme& scheme,
                                                                 bool for_client_auth,
                                                                 const Policy& policy) const;

      std::unique_ptr<KDF> protocol_specific_prf() const;

      Protocol_Version version() const { return m_version; }

      void set_version(const Protocol_Version& version);

      void hello_verify_request(const Hello_Verify_Request& hello_verify);

      // TODO: take unique_ptr instead of raw pointers for all of these, as
      // we're taking the ownership
      void client_hello(Client_Hello_12* client_hello);
      void server_hello(Server_Hello_12* server_hello);
      void server_cert_status(Certificate_Status* server_cert_status);
      void server_kex(Server_Key_Exchange* server_kex);
      void cert_req(Certificate_Request_12* cert_req);
      void server_hello_done(Server_Hello_Done* server_hello_done);
      void client_kex(Client_Key_Exchange* client_kex);

      void client_certs(Certificate_12* client_certs);
      void server_certs(Certificate_12* server_certs);

      void client_verify(Certificate_Verify_12* client_verify);
      void server_verify(Certificate_Verify_12* server_verify);

      void server_finished(Finished_12* server_finished);
      void client_finished(Finished_12* client_finished);

      void new_session_ticket(New_Session_Ticket_12* new_session_ticket);

      const Client_Hello_12* client_hello() const { return m_client_hello.get(); }

      const Server_Hello_12* server_hello() const { return m_server_hello.get(); }

      const Certificate_12* server_certs() const { return m_server_certs.get(); }

      const Server_Key_Exchange* server_kex() const { return m_server_kex.get(); }

      const Certificate_Request_12* cert_req() const { return m_cert_req.get(); }

      const Server_Hello_Done* server_hello_done() const { return m_server_hello_done.get(); }

      const Certificate_12* client_certs() const { return m_client_certs.get(); }

      const Client_Key_Exchange* client_kex() const { return m_client_kex.get(); }

      const Certificate_Verify_12* client_verify() const { return m_client_verify.get(); }

      const Certificate_Verify_12* server_verify() const { return m_server_verify.get(); }

      const Certificate_Status* server_cert_status() const { return m_server_cert_status.get(); }

      const New_Session_Ticket_12* new_session_ticket() const { return m_new_session_ticket.get(); }

      const Finished_12* server_finished() const { return m_server_finished.get(); }

      const Finished_12* client_finished() const { return m_client_finished.get(); }

      const Ciphersuite& ciphersuite() const;

      std::optional<std::string> psk_identity() const;

      const Session_Keys& session_keys() const { return m_session_keys; }

      Callbacks& callbacks() const { return m_callbacks; }

      void compute_session_keys();

      void compute_session_keys(const secure_vector<uint8_t>& resume_master_secret);

      Handshake_Hash& hash() { return m_handshake_hash; }

      const Handshake_Hash& hash() const { return m_handshake_hash; }

      void note_message(const Handshake_Message& msg);

   private:
      Callbacks& m_callbacks;

      std::unique_ptr<Handshake_IO> m_handshake_io;

      Handshake_Transitions m_transitions;
      Protocol_Version m_version;
      std::optional<Ciphersuite> m_ciphersuite;
      Session_Keys m_session_keys;
      Handshake_Hash m_handshake_hash;

      std::unique_ptr<Client_Hello_12> m_client_hello;
      std::unique_ptr<Server_Hello_12> m_server_hello;

      std::unique_ptr<Certificate_12> m_server_certs;
      std::unique_ptr<Certificate_Status> m_server_cert_status;
      std::unique_ptr<Server_Key_Exchange> m_server_kex;
      std::unique_ptr<Certificate_Request_12> m_cert_req;
      std::unique_ptr<Server_Hello_Done> m_server_hello_done;
      std::unique_ptr<Certificate_12> m_client_certs;
      std::unique_ptr<Client_Key_Exchange> m_client_kex;
      std::unique_ptr<Certificate_Verify_12> m_client_verify;
      std::unique_ptr<Certificate_Verify_12> m_server_verify;
      std::unique_ptr<New_Session_Ticket_12> m_new_session_ticket;
      std::unique_ptr<Finished_12> m_server_finished;
      std::unique_ptr<Finished_12> m_client_finished;
};

}  // namespace TLS

}  // namespace Botan

#endif
