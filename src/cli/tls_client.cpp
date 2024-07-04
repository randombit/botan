/*
* (C) 2014,2015 Jack Lloyd
*     2016 Matthias Gierlings
*     2017 René Korthaus, Rohde & Schwarz Cybersecurity
*     2022 René Meusel, Hannes Rantzsch - neXenio GmbH
*     2023 René Meusel, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_TLS) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM) && defined(BOTAN_TARGET_OS_HAS_SOCKETS)

   #include <botan/hex.h>
   #include <botan/ocsp.h>
   #include <botan/tls_callbacks.h>
   #include <botan/tls_client.h>
   #include <botan/tls_exceptn.h>
   #include <botan/tls_policy.h>
   #include <botan/tls_session_manager_memory.h>
   #include <botan/x509path.h>
   #include <fstream>

   #if defined(BOTAN_HAS_TLS_SQLITE3_SESSION_MANAGER)
      #include <botan/tls_session_manager_sqlite.h>
   #endif

   #include <memory>
   #include <string>

   #include "socket_utils.h"
   #include "tls_helpers.h"

namespace Botan_CLI {

class TLS_Client;

namespace {

class Callbacks : public Botan::TLS::Callbacks {
   public:
      Callbacks(TLS_Client& client_command) : m_client_command(client_command), m_peer_closed(false) {}

      std::ostream& output();
      bool flag_set(const std::string& flag_name) const;
      std::string get_arg(const std::string& arg_name) const;
      void send(std::span<const uint8_t> buffer);

      int peer_closed() const { return m_peer_closed; }

      void tls_verify_cert_chain(const std::vector<Botan::X509_Certificate>& cert_chain,
                                 const std::vector<std::optional<Botan::OCSP::Response>>& ocsp,
                                 const std::vector<Botan::Certificate_Store*>& trusted_roots,
                                 Botan::Usage_Type usage,
                                 std::string_view hostname,
                                 const Botan::TLS::Policy& policy) override {
         if(cert_chain.empty()) {
            throw Botan::Invalid_Argument("Certificate chain was empty");
         }

         Botan::Path_Validation_Restrictions restrictions(policy.require_cert_revocation_info(),
                                                          policy.minimum_signature_strength());

         auto ocsp_timeout = std::chrono::milliseconds(1000);

         const std::string checked_name = flag_set("skip-hostname-check") ? "" : std::string(hostname);

         Botan::Path_Validation_Result result = Botan::x509_path_validate(
            cert_chain, restrictions, trusted_roots, checked_name, usage, tls_current_timestamp(), ocsp_timeout, ocsp);

         if(result.successful_validation()) {
            output() << "Certificate validation status: " << result.result_string() << "\n";
            auto status = result.all_statuses();

            if(!status.empty() && status[0].contains(Botan::Certificate_Status_Code::OCSP_RESPONSE_GOOD)) {
               output() << "Valid OCSP response for this server\n";
            }
         } else {
            if(flag_set("ignore-cert-error")) {
               output() << "Certificate validation status: " << result.result_string() << "\n";
            } else {
               throw Botan::TLS::TLS_Exception(Botan::TLS::Alert::BadCertificate,
                                               "Certificate validation failure: " + result.result_string());
            }
         }
      }

      void tls_verify_raw_public_key(const Botan::Public_Key& raw_public_key,
                                     Botan::Usage_Type /* usage */,
                                     std::string_view /* hostname */,
                                     const Botan::TLS::Policy& /* policy */) override {
         const auto fingerprint = raw_public_key.fingerprint_public("SHA-256");
         const auto trusted = (fingerprint == get_arg("trusted-pubkey-sha256"));
         output() << "Raw Public Key (" << fingerprint
                  << ") validation status: " << (trusted ? "trusted" : "NOT trusted") << "\n";
      }

      void tls_session_activated() override { output() << "Handshake complete\n"; }

      void tls_session_established(const Botan::TLS::Session_Summary& session) override {
         output() << "Handshake complete, " << session.version().to_string() << " using "
                  << session.ciphersuite().to_string();

         if(const auto& psk = session.external_psk_identity()) {
            output() << " (utilized PSK identity: " << maybe_hex_encode(psk.value()) << ")";
         }

         output() << std::endl;

         if(const auto& session_id = session.session_id(); !session_id.empty()) {
            output() << "Session ID " << Botan::hex_encode(session_id.get()) << "\n";
         }

         if(const auto& session_ticket = session.session_ticket()) {
            output() << "Session ticket " << Botan::hex_encode(session_ticket->get()) << "\n";
         }

         if(flag_set("print-certs")) {
            const std::vector<Botan::X509_Certificate>& certs = session.peer_certs();

            for(size_t i = 0; i != certs.size(); ++i) {
               output() << "Certificate " << i + 1 << "/" << certs.size() << "\n";
               output() << certs[i].to_string();
               output() << certs[i].PEM_encode();
            }
         }
         output() << std::flush;
      }

      void tls_emit_data(std::span<const uint8_t> buf) override {
         if(flag_set("debug")) {
            output() << "<< " << Botan::hex_encode(buf) << "\n";
         }

         send(buf);
      }

      void tls_alert(Botan::TLS::Alert alert) override { output() << "Alert: " << alert.type_string() << "\n"; }

      void tls_record_received(uint64_t /*seq_no*/, std::span<const uint8_t> buf) override {
         for(const auto c : buf) {
            output() << c;
         }
         output() << std::flush;
      }

      std::vector<uint8_t> tls_sign_message(const Botan::Private_Key& key,
                                            Botan::RandomNumberGenerator& rng,
                                            const std::string_view padding,
                                            Botan::Signature_Format format,
                                            const std::vector<uint8_t>& msg) override {
         output() << "Performing client authentication\n";
         return Botan::TLS::Callbacks::tls_sign_message(key, rng, padding, format, msg);
      }

      bool tls_peer_closed_connection() override {
         m_peer_closed = true;
         return Botan::TLS::Callbacks::tls_peer_closed_connection();
      }

   private:
      TLS_Client& m_client_command;
      bool m_peer_closed;
};

}  // namespace

class TLS_Client final : public Command {
   public:
      TLS_Client() :
            Command(
               "tls_client host --port=443 --print-certs --policy=default "
               "--skip-system-cert-store --trusted-cas= --trusted-pubkey-sha256= "
               "--skip-hostname-check --ignore-cert-error "
               "--tls-version=default --session-db= --session-db-pass= "
               "--next-protocols= --type=tcp --client-cert= --client-cert-key= "
               "--psk= --psk-identity= --psk-prf=SHA-256 --debug") {
         init_sockets();
      }

      ~TLS_Client() override { stop_sockets(); }

      TLS_Client(const TLS_Client& other) = delete;
      TLS_Client(TLS_Client&& other) = delete;
      TLS_Client& operator=(const TLS_Client& other) = delete;
      TLS_Client& operator=(TLS_Client&& other) = delete;

      std::string group() const override { return "tls"; }

      std::string description() const override { return "Connect to a host using TLS/DTLS"; }

      void go() override {
         std::shared_ptr<Botan::TLS::Session_Manager> session_mgr;

         auto callbacks = std::make_shared<Callbacks>(*this);

         const std::string sessions_db = get_arg("session-db");
         const std::string host = get_arg("host");
         const uint16_t port = get_arg_u16("port");
         const std::string transport = get_arg("type");
         const std::string next_protos = get_arg("next-protocols");
         const bool use_system_cert_store = flag_set("skip-system-cert-store") == false;
         const std::string trusted_CAs = get_arg("trusted-cas");
         const auto tls_version = get_arg("tls-version");

         if(!sessions_db.empty()) {
   #if defined(BOTAN_HAS_TLS_SQLITE3_SESSION_MANAGER)
            const std::string sessions_passphrase = get_passphrase_arg("Session DB passphrase", "session-db-pass");
            session_mgr =
               std::make_shared<Botan::TLS::Session_Manager_SQLite>(sessions_passphrase, rng_as_shared(), sessions_db);
   #else
            error_output() << "Ignoring session DB file, sqlite not enabled\n";
   #endif
         }

         if(!session_mgr) {
            session_mgr = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng_as_shared());
         }

         auto policy = load_tls_policy(get_arg("policy"));

         if(transport != "tcp" && transport != "udp") {
            throw CLI_Usage_Error("Invalid transport type '" + transport + "' for TLS");
         }

         const std::vector<std::string> protocols_to_offer = Command::split_on(next_protos, ',');

         if(!policy) {
            policy = std::make_shared<Botan::TLS::Policy>();
         }

         const bool use_tcp = (transport == "tcp");
         Botan::TLS::Protocol_Version version = policy->latest_supported_version(!use_tcp);

         if(tls_version != "default") {
            if(tls_version == "1.2") {
               version = use_tcp ? Botan::TLS::Protocol_Version::TLS_V12 : Botan::TLS::Protocol_Version::DTLS_V12;
            } else if(tls_version == "1.3") {
               version = use_tcp ? Botan::TLS::Protocol_Version::TLS_V13 : Botan::TLS::Protocol_Version::DTLS_V13;
            } else {
               error_output() << "Unknown TLS protocol version " << tls_version << '\n';
            }
         }

         m_sockfd = connect_to_host(host, port, use_tcp);

         const auto client_crt_path = get_arg_maybe("client-cert");
         const auto client_key_path = get_arg_maybe("client-cert-key");

         auto psk = [this]() -> std::optional<Botan::secure_vector<uint8_t>> {
            auto psk_hex = get_arg_maybe("psk");
            if(psk_hex) {
               return Botan::hex_decode_locked(psk_hex.value());
            } else {
               return {};
            }
         }();
         const std::optional<std::string> psk_identity = get_arg_maybe("psk-identity");
         const std::optional<std::string> psk_prf = get_arg_maybe("psk-prf");

         auto creds = std::make_shared<Basic_Credentials_Manager>(use_system_cert_store,
                                                                  trusted_CAs,
                                                                  client_crt_path,
                                                                  client_key_path,
                                                                  std::move(psk),
                                                                  psk_identity,
                                                                  psk_prf);

         Botan::TLS::Client client(callbacks,
                                   session_mgr,
                                   creds,
                                   policy,
                                   rng_as_shared(),
                                   Botan::TLS::Server_Information(host, port),
                                   version,
                                   protocols_to_offer);

         bool first_active = true;
         bool we_closed = false;

         while(!client.is_closed()) {
            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(m_sockfd, &readfds);

            if(client.is_active()) {
               FD_SET(STDIN_FILENO, &readfds);
               if(first_active && !protocols_to_offer.empty()) {
                  std::string app = client.application_protocol();
                  if(!app.empty()) {
                     output() << "Server choose protocol: " << client.application_protocol() << "\n";
                  }
                  first_active = false;
               }
            }

            struct timeval timeout = {1, 0};

            ::select(static_cast<int>(m_sockfd + 1), &readfds, nullptr, nullptr, &timeout);

            if(FD_ISSET(m_sockfd, &readfds)) {
               uint8_t buf[4 * 1024] = {0};

               ssize_t got = ::read(m_sockfd, buf, sizeof(buf));

               if(got == 0) {
                  output() << "EOF on socket\n";
                  break;
               } else if(got == -1) {
                  output() << "Socket error: " << errno << " " << err_to_string(errno) << "\n";
                  continue;
               }

               if(flag_set("debug")) {
                  output() << ">> " << Botan::hex_encode(buf, got) << "\n";
               }

               client.received_data(buf, got);
            }

            if(FD_ISSET(STDIN_FILENO, &readfds)) {
               uint8_t buf[1024] = {0};
               ssize_t got = read(STDIN_FILENO, buf, sizeof(buf));

               if(got == 0) {
                  output() << "EOF on stdin\n";
                  client.close();
                  we_closed = true;
                  break;
               } else if(got == -1) {
                  output() << "Stdin error: " << errno << " " << err_to_string(errno) << "\n";
                  continue;
               }

               if(got == 2 && buf[1] == '\n') {
                  char cmd = buf[0];

                  if(cmd == 'R' || cmd == 'r') {
                     output() << "Client initiated renegotiation\n";
                     client.renegotiate(cmd == 'R');
                  } else if(cmd == 'Q') {
                     output() << "Client initiated close\n";
                     client.close();
                     we_closed = true;
                  }
               } else {
                  client.send(buf, got);
               }
            }

            if(client.timeout_check()) {
               output() << "Timeout detected\n";
            }
         }

         set_return_code((we_closed || callbacks->peer_closed()) ? 0 : 1);

         ::close(m_sockfd);
      }

   public:
      using Command::flag_set;
      using Command::get_arg;
      using Command::output;

      void send(std::span<const uint8_t> buf) const {
         while(!buf.empty()) {
            ssize_t sent = ::send(m_sockfd, buf.data(), buf.size(), MSG_NOSIGNAL);

            if(sent == -1) {
               if(errno == EINTR) {
                  sent = 0;
               } else {
                  throw CLI_Error("Socket write failed errno=" + std::to_string(errno));
               }
            }

            buf = buf.subspan(sent);
         }
      }

   private:
      static socket_type connect_to_host(const std::string& host, uint16_t port, bool tcp) {
         addrinfo hints;
         Botan::clear_mem(&hints, 1);
         hints.ai_family = AF_UNSPEC;
         hints.ai_socktype = tcp ? SOCK_STREAM : SOCK_DGRAM;
         addrinfo *res, *rp = nullptr;

         if(::getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0) {
            throw CLI_Error("getaddrinfo failed for " + host);
         }

         socket_type fd = 0;

         for(rp = res; rp != nullptr; rp = rp->ai_next) {
            fd = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

            if(fd == invalid_socket()) {
               continue;
            }

            if(::connect(fd, rp->ai_addr, rp->ai_addrlen) != 0) {
               ::close(fd);
               continue;
            }

            break;
         }

         ::freeaddrinfo(res);

         if(rp == nullptr)  // no address succeeded
         {
            throw CLI_Error("connect failed");
         }

         return fd;
      }

      static void dgram_socket_write(int sockfd, const uint8_t buf[], size_t length) {
         auto r = ::send(sockfd, buf, length, MSG_NOSIGNAL);

         if(r == -1) {
            throw CLI_Error("Socket write failed errno=" + std::to_string(errno));
         }
      }

      socket_type m_sockfd = invalid_socket();
};

namespace {

std::ostream& Callbacks::output() {
   return m_client_command.output();
}

bool Callbacks::flag_set(const std::string& flag_name) const {
   return m_client_command.flag_set(flag_name);
}

std::string Callbacks::get_arg(const std::string& arg_name) const {
   return m_client_command.get_arg(arg_name);
}

void Callbacks::send(std::span<const uint8_t> buffer) {
   m_client_command.send(buffer);
}

}  // namespace

BOTAN_REGISTER_COMMAND("tls_client", TLS_Client);

}  // namespace Botan_CLI

#endif
