/*
* TLS Handshaking
* (C) 2004-2006,2011,2012,2015,2016 Jack Lloyd
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_handshake_state.h>

#include <botan/kdf.h>
#include <botan/tls_messages.h>
#include <botan/tls_signature_scheme.h>
#include <botan/internal/tls_record.h>
#include <sstream>

namespace Botan::TLS {

std::string Handshake_Message::type_string() const {
   return handshake_type_to_string(type());
}

const char* handshake_type_to_string(Handshake_Type type) {
   switch(type) {
      case Handshake_Type::HelloVerifyRequest:
         return "hello_verify_request";

      case Handshake_Type::HelloRequest:
         return "hello_request";

      case Handshake_Type::ClientHello:
         return "client_hello";

      case Handshake_Type::ServerHello:
         return "server_hello";

      case Handshake_Type::HelloRetryRequest:
         return "hello_retry_request";

      case Handshake_Type::Certificate:
         return "certificate";

      case Handshake_Type::CertificateUrl:
         return "certificate_url";

      case Handshake_Type::CertificateStatus:
         return "certificate_status";

      case Handshake_Type::ServerKeyExchange:
         return "server_key_exchange";

      case Handshake_Type::CertificateRequest:
         return "certificate_request";

      case Handshake_Type::ServerHelloDone:
         return "server_hello_done";

      case Handshake_Type::CertificateVerify:
         return "certificate_verify";

      case Handshake_Type::ClientKeyExchange:
         return "client_key_exchange";

      case Handshake_Type::NewSessionTicket:
         return "new_session_ticket";

      case Handshake_Type::HandshakeCCS:
         return "change_cipher_spec";

      case Handshake_Type::Finished:
         return "finished";

      case Handshake_Type::EndOfEarlyData:
         return "end_of_early_data";

      case Handshake_Type::EncryptedExtensions:
         return "encrypted_extensions";

      case Handshake_Type::KeyUpdate:
         return "key_update";

      case Handshake_Type::None:
         return "invalid";
   }

   throw TLS_Exception(Alert::UnexpectedMessage,
                       "Unknown TLS handshake message type " + std::to_string(static_cast<size_t>(type)));
}

/*
* Initialize the SSL/TLS Handshake State
*/
Handshake_State::~Handshake_State() = default;

Handshake_State::Handshake_State(std::unique_ptr<Handshake_IO> io, Callbacks& cb) :
      m_callbacks(cb), m_handshake_io(std::move(io)), m_version(m_handshake_io->initial_record_version()) {}

void Handshake_State::note_message(const Handshake_Message& msg) {
   m_callbacks.tls_inspect_handshake_msg(msg);
}

void Handshake_State::hello_verify_request(const Hello_Verify_Request& hello_verify) {
   note_message(hello_verify);

   m_client_hello->update_hello_cookie(hello_verify);
   hash().reset();
   hash().update(handshake_io().send(*m_client_hello));
   note_message(*m_client_hello);
}

void Handshake_State::client_hello(Client_Hello_12* client_hello) {
   if(client_hello == nullptr) {
      m_client_hello.reset();
      hash().reset();
   } else {
      m_client_hello.reset(client_hello);
      note_message(*m_client_hello);
   }
}

void Handshake_State::server_hello(Server_Hello_12* server_hello) {
   m_server_hello.reset(server_hello);
   m_ciphersuite = Ciphersuite::by_id(m_server_hello->ciphersuite());
   note_message(*m_server_hello);
}

void Handshake_State::server_certs(Certificate_12* server_certs) {
   m_server_certs.reset(server_certs);
   note_message(*m_server_certs);
}

void Handshake_State::server_cert_status(Certificate_Status* server_cert_status) {
   m_server_cert_status.reset(server_cert_status);
   note_message(*m_server_cert_status);
}

void Handshake_State::server_kex(Server_Key_Exchange* server_kex) {
   m_server_kex.reset(server_kex);
   note_message(*m_server_kex);
}

void Handshake_State::cert_req(Certificate_Request_12* cert_req) {
   m_cert_req.reset(cert_req);
   note_message(*m_cert_req);
}

void Handshake_State::server_hello_done(Server_Hello_Done* server_hello_done) {
   m_server_hello_done.reset(server_hello_done);
   note_message(*m_server_hello_done);
}

void Handshake_State::client_certs(Certificate_12* client_certs) {
   m_client_certs.reset(client_certs);
   note_message(*m_client_certs);
}

void Handshake_State::client_kex(Client_Key_Exchange* client_kex) {
   m_client_kex.reset(client_kex);
   note_message(*m_client_kex);
}

void Handshake_State::client_verify(Certificate_Verify_12* client_verify) {
   m_client_verify.reset(client_verify);
   note_message(*m_client_verify);
}

void Handshake_State::server_verify(Certificate_Verify_12* server_verify) {
   m_server_verify.reset(server_verify);
   note_message(*m_server_verify);
}

void Handshake_State::new_session_ticket(New_Session_Ticket_12* new_session_ticket) {
   m_new_session_ticket.reset(new_session_ticket);
   note_message(*m_new_session_ticket);
}

void Handshake_State::server_finished(Finished_12* server_finished) {
   m_server_finished.reset(server_finished);
   note_message(*m_server_finished);
}

void Handshake_State::client_finished(Finished_12* client_finished) {
   m_client_finished.reset(client_finished);
   note_message(*m_client_finished);
}

const Ciphersuite& Handshake_State::ciphersuite() const {
   if(!m_ciphersuite.has_value()) {
      throw Invalid_State("Cipher suite is not set");
   }
   return m_ciphersuite.value();
}

std::optional<std::string> Handshake_State::psk_identity() const {
   if(!m_client_kex) {
      return std::nullopt;
   }
   return m_client_kex->psk_identity();
}

void Handshake_State::set_version(const Protocol_Version& version) {
   m_version = version;
}

void Handshake_State::compute_session_keys() {
   m_session_keys = Session_Keys(this, client_kex()->pre_master_secret(), false);
}

void Handshake_State::compute_session_keys(const secure_vector<uint8_t>& resume_master_secret) {
   m_session_keys = Session_Keys(this, resume_master_secret, true);
}

void Handshake_State::confirm_transition_to(Handshake_Type handshake_msg) {
   m_transitions.confirm_transition_to(handshake_msg);
}

void Handshake_State::set_expected_next(Handshake_Type handshake_msg) {
   m_transitions.set_expected_next(handshake_msg);
}

bool Handshake_State::received_handshake_msg(Handshake_Type handshake_msg) const {
   return m_transitions.received_handshake_msg(handshake_msg);
}

std::pair<Handshake_Type, std::vector<uint8_t>> Handshake_State::get_next_handshake_msg() {
   return m_handshake_io->get_next_record(m_transitions.change_cipher_spec_expected());
}

Session_Ticket Handshake_State::session_ticket() const {
   if(new_session_ticket() && !new_session_ticket()->ticket().empty()) {
      return new_session_ticket()->ticket();
   }

   return client_hello()->session_ticket();
}

std::unique_ptr<KDF> Handshake_State::protocol_specific_prf() const {
   const std::string prf_algo = ciphersuite().prf_algo();

   if(prf_algo == "MD5" || prf_algo == "SHA-1") {
      return KDF::create_or_throw("TLS-12-PRF(SHA-256)");
   }

   return KDF::create_or_throw("TLS-12-PRF(" + prf_algo + ")");
}

std::pair<std::string, Signature_Format> Handshake_State::choose_sig_format(const Private_Key& key,
                                                                            Signature_Scheme& chosen_scheme,
                                                                            bool for_client_auth,
                                                                            const Policy& policy) const {
   const std::string sig_algo = key.algo_name();

   const std::vector<Signature_Scheme> allowed = policy.allowed_signature_schemes();

   std::vector<Signature_Scheme> requested =
      (for_client_auth) ? cert_req()->signature_schemes() : client_hello()->signature_schemes();

   for(Signature_Scheme scheme : allowed) {
      if(!scheme.is_available()) {
         continue;
      }

      if(scheme.algorithm_name() == sig_algo) {
         if(std::find(requested.begin(), requested.end(), scheme) != requested.end()) {
            chosen_scheme = scheme;
            break;
         }
      }
   }

   const std::string hash = chosen_scheme.hash_function_name();

   if(!policy.allowed_signature_hash(hash)) {
      throw TLS_Exception(Alert::HandshakeFailure, "Policy refuses to accept signing with any hash supported by peer");
   }

   if(!chosen_scheme.format().has_value()) {
      throw Invalid_Argument(sig_algo + " is invalid/unknown for TLS signatures");
   }

   return std::make_pair(chosen_scheme.padding_string(), chosen_scheme.format().value());
}

namespace {

bool supported_algos_include(const std::vector<Signature_Scheme>& schemes,
                             std::string_view key_type,
                             std::string_view hash_type) {
   for(Signature_Scheme scheme : schemes) {
      if(scheme.is_available() && hash_type == scheme.hash_function_name() && key_type == scheme.algorithm_name()) {
         return true;
      }
   }

   return false;
}

}  // namespace

std::pair<std::string, Signature_Format> Handshake_State::parse_sig_format(
   const Public_Key& key,
   Signature_Scheme scheme,
   const std::vector<Signature_Scheme>& offered_schemes,
   bool for_client_auth,
   const Policy& policy) const {
   const std::string key_type = key.algo_name();

   if(!policy.allowed_signature_method(key_type)) {
      throw TLS_Exception(Alert::HandshakeFailure, "Rejecting " + key_type + " signature");
   }

   if(!scheme.is_available()) {
      throw TLS_Exception(Alert::IllegalParameter, "Peer sent unknown signature scheme");
   }

   if(key_type != scheme.algorithm_name()) {
      throw Decoding_Error("Counterparty sent inconsistent key and sig types");
   }

   if(for_client_auth && !cert_req()) {
      throw TLS_Exception(Alert::HandshakeFailure, "No certificate verify set");
   }

   /*
   Confirm the signature type we just received against the
   supported_algos list that we sent; it better be there.
   */

   const std::vector<Signature_Scheme> supported_algos =
      for_client_auth ? cert_req()->signature_schemes() : offered_schemes;

   const std::string hash_algo = scheme.hash_function_name();

   if(!scheme.is_compatible_with(Protocol_Version::TLS_V12)) {
      throw TLS_Exception(Alert::IllegalParameter, "Peer sent unexceptable signature scheme");
   }

   if(!supported_algos_include(supported_algos, key_type, hash_algo)) {
      throw TLS_Exception(Alert::IllegalParameter,
                          "TLS signature extension did not allow for " + key_type + "/" + hash_algo + " signature");
   }

   if(!scheme.format().has_value()) {
      throw Invalid_Argument(key_type + " is invalid/unknown for TLS signatures");
   }

   return std::make_pair(scheme.padding_string(), scheme.format().value());
}

}  // namespace Botan::TLS
