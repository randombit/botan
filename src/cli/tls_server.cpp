/*
* TLS echo server using BSD sockets
* (C) 2014 Jack Lloyd
*     2017 René Korthaus, Rohde & Schwarz Cybersecurity
*     2023 René Meusel, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"
#include "sandbox.h"

#if defined(BOTAN_TARGET_OS_HAS_SOCKETS)
   #include <sys/socket.h>
#endif

#if defined(BOTAN_HAS_TLS) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM) && defined(BOTAN_TARGET_OS_HAS_SOCKETS)

   #if defined(SO_MARK) || defined(SO_USER_COOKIE) || defined(SO_RTABLE)
      #if defined(SO_MARK)
         #define BOTAN_SO_SOCKETID SO_MARK
      #elif defined(SO_USER_COOKIE)
         #define BOTAN_SO_SOCKETID SO_USER_COOKIE
      #else
         #define BOTAN_SO_SOCKETID SO_RTABLE
      #endif
   #endif

   #include <botan/hex.h>
   #include <botan/mem_ops.h>
   #include <botan/tls_callbacks.h>
   #include <botan/tls_policy.h>
   #include <botan/tls_server.h>
   #include <botan/tls_session_manager_memory.h>

   #include <chrono>
   #include <fstream>
   #include <list>
   #include <memory>

   #include "socket_utils.h"
   #include "tls_helpers.h"

namespace Botan_CLI {

class TLS_Server;

namespace {

class Callbacks : public Botan::TLS::Callbacks {
   public:
      Callbacks(TLS_Server& server_command) : m_server_command(server_command) {}

      std::ostream& output();
      void send(std::span<const uint8_t> buffer);
      void push_pending_output(std::string line);

      void tls_session_established(const Botan::TLS::Session_Summary& session) override {
         output() << "Handshake complete, " << session.version().to_string() << " using "
                  << session.ciphersuite().to_string();

         if(const auto& psk = session.external_psk_identity()) {
            output() << " (utilized PSK identity: " << maybe_hex_encode(psk.value()) << ")";
         }

         output() << std::endl;

         if(const auto& session_id = session.session_id(); !session_id.empty()) {
            output() << "Session ID " << Botan::hex_encode(session_id.get()) << std::endl;
         }

         if(const auto& session_ticket = session.session_ticket()) {
            output() << "Session ticket " << Botan::hex_encode(session_ticket->get()) << std::endl;
         }
      }

      void tls_record_received(uint64_t /*seq_no*/, std::span<const uint8_t> input) override {
         for(size_t i = 0; i != input.size(); ++i) {
            const char c = static_cast<char>(input[i]);
            m_line_buf += c;
            if(c == '\n') {
               push_pending_output(std::exchange(m_line_buf, {}));
            }
         }
      }

      void tls_emit_data(std::span<const uint8_t> buf) override { send(buf); }

      void tls_alert(Botan::TLS::Alert alert) override { output() << "Alert: " << alert.type_string() << std::endl; }

      std::string tls_server_choose_app_protocol(const std::vector<std::string>& /*client_protos*/) override {
         // we ignore whatever the client sends here
         return "echo/0.1";
      }

      void tls_verify_raw_public_key(const Botan::Public_Key& raw_public_key,
                                     Botan::Usage_Type /* usage */,
                                     std::string_view /* hostname */,
                                     const Botan::TLS::Policy& /* policy */) override {
         const auto fingerprint = raw_public_key.fingerprint_public("SHA-256");
         output() << "received Raw Public Key (" << fingerprint << ")\n";
      }

   private:
      TLS_Server& m_server_command;
      std::string m_line_buf;
};

}  // namespace

class TLS_Server final : public Command {
   public:
   #if defined(BOTAN_SO_SOCKETID)
      TLS_Server() :
            Command(
               "tls_server cert-or-pubkey key --port=443 --psk= --psk-identity= --psk-prf=SHA-256 --type=tcp --policy=default --dump-traces= --max-clients=0 --socket-id=0")
   #else
      TLS_Server() :
            Command(
               "tls_server cert-or-pubkey key --port=443 --psk= --psk-identity= --psk-prf=SHA-256 --type=tcp --policy=default --dump-traces= --max-clients=0")
   #endif
      {
         init_sockets();
      }

      ~TLS_Server() override { stop_sockets(); }

      TLS_Server(const TLS_Server& other) = delete;
      TLS_Server(TLS_Server&& other) = delete;
      TLS_Server& operator=(const TLS_Server& other) = delete;
      TLS_Server& operator=(TLS_Server&& other) = delete;

      std::string group() const override { return "tls"; }

      std::string description() const override { return "Accept TLS/DTLS connections from TLS/DTLS clients"; }

      void go() override {
         const std::string server_cred = get_arg("cert-or-pubkey");
         const std::string server_key = get_arg("key");
         const uint16_t port = get_arg_u16("port");
         const size_t max_clients = get_arg_sz("max-clients");
         const std::string transport = get_arg("type");
         const std::string dump_traces_to = get_arg("dump-traces");
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

   #if defined(BOTAN_SO_SOCKETID)
         m_socket_id = static_cast<uint32_t>(get_arg_sz("socket-id"));
   #endif

         if(transport != "tcp" && transport != "udp") {
            throw CLI_Usage_Error("Invalid transport type '" + transport + "' for TLS");
         }

         m_is_tcp = (transport == "tcp");

         auto policy = load_tls_policy(get_arg("policy"));
         auto session_manager =
            std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng_as_shared());  // TODO sqlite3
         auto creds =
            std::make_shared<Basic_Credentials_Manager>(server_cred, server_key, std::move(psk), psk_identity, psk_prf);
         auto callbacks = std::make_shared<Callbacks>(*this);

         if(!m_sandbox.init()) {
            error_output() << "Failed sandboxing\n";
            return;
         }

         socket_type server_fd = make_server_socket(port);
         size_t clients_served = 0;

         output() << "Listening for new connections on " << transport << " port " << port << std::endl;

         while(true) {
            if(max_clients > 0 && clients_served >= max_clients) {
               break;
            }

            if(m_is_tcp) {
               m_socket = ::accept(server_fd, nullptr, nullptr);
            } else {
               struct sockaddr_in from;
               socklen_t from_len = sizeof(sockaddr_in);

               void* peek_buf = nullptr;
               size_t peek_len = 0;

   #if defined(BOTAN_TARGET_OS_IS_MACOS)
               // macOS handles zero size buffers differently - it will return 0 even if there's no incoming data,
               // and after that connect() will fail as sockaddr_in from is not initialized
               int dummy;
               peek_buf = &dummy;
               peek_len = sizeof(dummy);
   #endif

               if(::recvfrom(server_fd,
                             static_cast<char*>(peek_buf),
                             static_cast<sendrecv_len_type>(peek_len),
                             MSG_PEEK,
                             reinterpret_cast<struct sockaddr*>(&from),
                             &from_len) != 0) {
                  throw CLI_Error("Could not peek next packet");
               }

               if(::connect(server_fd, reinterpret_cast<struct sockaddr*>(&from), from_len) != 0) {
                  throw CLI_Error("Could not connect UDP socket");
               }
               m_socket = server_fd;
            }

            clients_served++;

            Botan::TLS::Server server(callbacks, session_manager, creds, policy, rng_as_shared(), m_is_tcp == false);

            std::unique_ptr<std::ostream> dump_stream;

            if(!dump_traces_to.empty()) {
               auto now = std::chrono::system_clock::now().time_since_epoch();
               uint64_t timestamp = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
               const std::string dump_file = dump_traces_to + "/tls_" + std::to_string(timestamp) + ".bin";
               dump_stream = std::make_unique<std::ofstream>(dump_file.c_str());
            }

            try {
               while(!server.is_closed()) {
                  try {
                     uint8_t buf[4 * 1024] = {0};
                     ssize_t got = ::recv(m_socket, Botan::cast_uint8_ptr_to_char(buf), sizeof(buf), 0);

                     if(got == -1) {
                        error_output() << "Error in socket read - " << err_to_string(errno) << std::endl;
                        break;
                     }

                     if(got == 0) {
                        error_output() << "EOF on socket" << std::endl;
                        break;
                     }

                     if(dump_stream) {
                        dump_stream->write(reinterpret_cast<const char*>(buf), got);
                     }

                     server.received_data(buf, got);

                     while(server.is_active() && !m_pending_output.empty()) {
                        std::string output = m_pending_output.front();
                        m_pending_output.pop_front();
                        server.send(output);

                        if(output == "quit\n") {
                           server.close();
                        }
                     }
                  } catch(std::exception& e) {
                     error_output() << "Connection problem: " << e.what() << std::endl;
                     if(m_is_tcp) {
                        close_socket(m_socket);
                        m_socket = invalid_socket();
                     }
                  }
               }
            } catch(Botan::Exception& e) {
               error_output() << "Connection failed: " << e.what() << "\n";
            }

            if(m_is_tcp) {
               close_socket(m_socket);
               m_socket = invalid_socket();
            }
         }

         close_socket(server_fd);
      }

   public:
      using Command::flag_set;
      using Command::output;

      void send(std::span<const uint8_t> buf) {
         if(m_is_tcp) {
            ssize_t sent = ::send(m_socket, buf.data(), static_cast<sendrecv_len_type>(buf.size()), MSG_NOSIGNAL);

            if(sent == -1) {
               error_output() << "Error writing to socket - " << err_to_string(errno) << std::endl;
            } else if(sent != static_cast<ssize_t>(buf.size())) {
               error_output() << "Packet of length " << buf.size() << " truncated to " << sent << std::endl;
            }
         } else {
            while(!buf.empty()) {
               ssize_t sent = ::send(m_socket, buf.data(), static_cast<sendrecv_len_type>(buf.size()), MSG_NOSIGNAL);

               if(sent == -1) {
                  if(errno == EINTR) {
                     sent = 0;
                  } else {
                     throw CLI_Error("Socket write failed");
                  }
               }

               buf = buf.subspan(sent);
            }
         }
      }

      void push_pending_output(std::string line) { m_pending_output.emplace_back(std::move(line)); }

   private:
      socket_type make_server_socket(uint16_t port) {
         const int type = m_is_tcp ? SOCK_STREAM : SOCK_DGRAM;

         socket_type fd = ::socket(PF_INET, type, 0);
         if(fd == invalid_socket()) {
            throw CLI_Error("Unable to acquire socket");
         }

         sockaddr_in socket_info;
         Botan::clear_mem(&socket_info, 1);
         socket_info.sin_family = AF_INET;
         socket_info.sin_port = htons(port);

         // FIXME: support limiting listeners
         socket_info.sin_addr.s_addr = INADDR_ANY;

         if(::bind(fd, reinterpret_cast<struct sockaddr*>(&socket_info), sizeof(struct sockaddr)) != 0) {
            close_socket(fd);
            throw CLI_Error("server bind failed");
         }

         if(m_is_tcp) {
            constexpr int backlog = std::min(100, SOMAXCONN);
            if(::listen(fd, backlog) != 0) {
               close_socket(fd);
               throw CLI_Error("listen failed");
            }
         }
         if(m_socket_id > 0) {
   #if defined(BOTAN_SO_SOCKETID)
            if(::setsockopt(fd,
                            SOL_SOCKET,
                            BOTAN_SO_SOCKETID,
                            reinterpret_cast<const void*>(&m_socket_id),
                            sizeof(m_socket_id)) != 0) {
               // Failed but not world-ending issue
               output() << "set socket identifier setting failed" << std::endl;
            }
   #endif
         }
         return fd;
      }

      socket_type m_socket = invalid_socket();
      bool m_is_tcp = false;
      uint32_t m_socket_id = 0;
      std::list<std::string> m_pending_output;
      Sandbox m_sandbox;
};

namespace {

std::ostream& Callbacks::output() {
   return m_server_command.output();
}

void Callbacks::send(std::span<const uint8_t> buffer) {
   m_server_command.send(buffer);
}

void Callbacks::push_pending_output(std::string line) {
   m_server_command.push_pending_output(std::move(line));
}

}  // namespace

BOTAN_REGISTER_COMMAND("tls_server", TLS_Server);

}  // namespace Botan_CLI

#endif
