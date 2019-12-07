/*
* (C) 2014,2015 Jack Lloyd
*     2016 Matthias Gierlings
*     2017 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_TLS) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM) && defined(BOTAN_TARGET_OS_HAS_SOCKETS)

#include <botan/tls_client.h>
#include <botan/tls_policy.h>
#include <botan/x509path.h>
#include <botan/ocsp.h>
#include <botan/hex.h>
#include <botan/parsing.h>
#include <fstream>

#if defined(BOTAN_HAS_TLS_SQLITE3_SESSION_MANAGER)
   #include <botan/tls_session_manager_sqlite.h>
#endif

#include <string>
#include <memory>

#include "socket_utils.h"
#include "tls_helpers.h"

namespace Botan_CLI {

class CLI_Policy final : public Botan::TLS::Policy
   {
   public:

      CLI_Policy(Botan::TLS::Protocol_Version req_version) : m_version(req_version) {}

      std::vector<std::string> allowed_ciphers() const override
         {
         // Allow CBC mode only in versions which don't support AEADs
         if(m_version.supports_aead_modes() == false)
            {
            return { "AES-256", "AES-128" };
            }

         return Botan::TLS::Policy::allowed_ciphers();
         }

      bool allow_tls10() const override { return m_version == Botan::TLS::Protocol_Version::TLS_V10; }
      bool allow_tls11() const override { return m_version == Botan::TLS::Protocol_Version::TLS_V11; }
      bool allow_tls12() const override { return m_version == Botan::TLS::Protocol_Version::TLS_V12; }

   private:
      Botan::TLS::Protocol_Version m_version;
   };

class TLS_Client final : public Command, public Botan::TLS::Callbacks
   {
   public:
      TLS_Client()
         : Command("tls_client host --port=443 --print-certs --policy=default "
                   "--tls1.0 --tls1.1 --tls1.2 "
                   "--skip-system-cert-store --trusted-cas= "
                   "--session-db= --session-db-pass= --next-protocols= --type=tcp")
         {
         init_sockets();
         }

      ~TLS_Client()
         {
         stop_sockets();
         }

      std::string group() const override
         {
         return "tls";
         }

      std::string description() const override
         {
         return "Connect to a host using TLS/DTLS";
         }

      void go() override
         {
         // TODO client cert auth

         std::unique_ptr<Botan::TLS::Session_Manager> session_mgr;

         const std::string sessions_db = get_arg("session-db");
         const std::string host = get_arg("host");
         const uint16_t port = get_arg_u16("port");
         const std::string transport = get_arg("type");
         const std::string next_protos = get_arg("next-protocols");
         const bool use_system_cert_store = flag_set("skip-system-cert-store") == false;
         const std::string trusted_CAs = get_arg("trusted-cas");

         if(!sessions_db.empty())
            {
#if defined(BOTAN_HAS_TLS_SQLITE3_SESSION_MANAGER)
            const std::string sessions_passphrase = get_passphrase_arg("Session DB passphrase", "session-db-pass");
            session_mgr.reset(new Botan::TLS::Session_Manager_SQLite(sessions_passphrase, rng(), sessions_db));
#else
            error_output() << "Ignoring session DB file, sqlite not enabled\n";
#endif
            }

         if(!session_mgr)
            {
            session_mgr.reset(new Botan::TLS::Session_Manager_In_Memory(rng()));
            }

         auto policy = load_tls_policy(get_arg("policy"));

         if(transport != "tcp" && transport != "udp")
            {
            throw CLI_Usage_Error("Invalid transport type '" + transport + "' for TLS");
            }

         const bool use_tcp = (transport == "tcp");

         const std::vector<std::string> protocols_to_offer = Botan::split_on(next_protos, ',');

         Botan::TLS::Protocol_Version version =
            use_tcp ? Botan::TLS::Protocol_Version::TLS_V12 : Botan::TLS::Protocol_Version::DTLS_V12;

         if(flag_set("tls1.0"))
            {
            version = Botan::TLS::Protocol_Version::TLS_V10;
            if(!policy)
               policy.reset(new CLI_Policy(version));
            }
         else if(flag_set("tls1.1"))
            {
            version = Botan::TLS::Protocol_Version::TLS_V11;
            if(!policy)
               policy.reset(new CLI_Policy(version));
            }
         else if(flag_set("tls1.2"))
            {
            version = Botan::TLS::Protocol_Version::TLS_V12;
            if(!policy)
               policy.reset(new CLI_Policy(version));
            }
         else if(!policy)
            {
            policy.reset(new Botan::TLS::Policy);
            }

         if(policy->acceptable_protocol_version(version) == false)
            {
            throw CLI_Usage_Error("The policy specified does not allow the requested TLS version");
            }

         struct sockaddr_storage addrbuf;
         std::string hostname;
         if(!host.empty() &&
               inet_pton(AF_INET, host.c_str(), &addrbuf) != 1 &&
               inet_pton(AF_INET6, host.c_str(), &addrbuf) != 1)
            {
            hostname = host;
            }

         m_sockfd = connect_to_host(host, port, use_tcp);

         Basic_Credentials_Manager creds(use_system_cert_store, trusted_CAs);

         Botan::TLS::Client client(*this, *session_mgr, creds, *policy, rng(),
                                   Botan::TLS::Server_Information(hostname, port),
                                   version, protocols_to_offer);

         bool first_active = true;

         while(!client.is_closed())
            {
            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(m_sockfd, &readfds);

            if(client.is_active())
               {
               FD_SET(STDIN_FILENO, &readfds);
               if(first_active && !protocols_to_offer.empty())
                  {
                  std::string app = client.application_protocol();
                  if(app != "")
                     {
                     output() << "Server choose protocol: " << client.application_protocol() << "\n";
                     }
                  first_active = false;
                  }
               }

            struct timeval timeout = { 1, 0 };

            ::select(static_cast<int>(m_sockfd + 1), &readfds, nullptr, nullptr, &timeout);

            if(FD_ISSET(m_sockfd, &readfds))
               {
               uint8_t buf[4 * 1024] = { 0 };

               ssize_t got = ::read(m_sockfd, buf, sizeof(buf));

               if(got == 0)
                  {
                  output() << "EOF on socket\n";
                  break;
                  }
               else if(got == -1)
                  {
                  output() << "Socket error: " << errno << " " << err_to_string(errno) << "\n";
                  continue;
                  }

               client.received_data(buf, got);
               }

            if(FD_ISSET(STDIN_FILENO, &readfds))
               {
               uint8_t buf[1024] = { 0 };
               ssize_t got = read(STDIN_FILENO, buf, sizeof(buf));

               if(got == 0)
                  {
                  output() << "EOF on stdin\n";
                  client.close();
                  break;
                  }
               else if(got == -1)
                  {
                  output() << "Stdin error: " << errno << " " << err_to_string(errno) << "\n";
                  continue;
                  }

               if(got == 2 && buf[1] == '\n')
                  {
                  char cmd = buf[0];

                  if(cmd == 'R' || cmd == 'r')
                     {
                     output() << "Client initiated renegotiation\n";
                     client.renegotiate(cmd == 'R');
                     }
                  else if(cmd == 'Q')
                     {
                     output() << "Client initiated close\n";
                     client.close();
                     }
                  }
               else
                  {
                  client.send(buf, got);
                  }
               }

            if(client.timeout_check())
               {
               output() << "Timeout detected\n";
               }
            }

         ::close(m_sockfd);
         }

   private:
      socket_type connect_to_host(const std::string& host, uint16_t port, bool tcp)
         {
         addrinfo hints;
         Botan::clear_mem(&hints, 1);
         hints.ai_family = AF_UNSPEC;
         hints.ai_socktype = tcp ? SOCK_STREAM : SOCK_DGRAM;
         addrinfo* res, *rp = nullptr;

         if(::getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0)
            {
            throw CLI_Error("getaddrinfo failed for " + host);
            }

         socket_type fd = 0;

         for(rp = res; rp != nullptr; rp = rp->ai_next)
            {
            fd = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

            if(fd == invalid_socket())
               {
               continue;
               }

            if(::connect(fd, rp->ai_addr, static_cast<socklen_t>(rp->ai_addrlen)) != 0)
               {
               ::close(fd);
               continue;
               }

            break;
            }

         ::freeaddrinfo(res);

         if(rp == nullptr) // no address succeeded
            {
            throw CLI_Error("connect failed");
            }

         return fd;
         }

      void tls_verify_cert_chain(
         const std::vector<Botan::X509_Certificate>& cert_chain,
         const std::vector<std::shared_ptr<const Botan::OCSP::Response>>& ocsp,
         const std::vector<Botan::Certificate_Store*>& trusted_roots,
         Botan::Usage_Type usage,
         const std::string& hostname,
         const Botan::TLS::Policy& policy) override
         {
         if(cert_chain.empty())
            {
            throw Botan::Invalid_Argument("Certificate chain was empty");
            }

         Botan::Path_Validation_Restrictions restrictions(
            policy.require_cert_revocation_info(),
            policy.minimum_signature_strength());

         auto ocsp_timeout = std::chrono::milliseconds(1000);

         Botan::Path_Validation_Result result = Botan::x509_path_validate(
               cert_chain,
               restrictions,
               trusted_roots,
               hostname,
               usage,
               std::chrono::system_clock::now(),
               ocsp_timeout,
               ocsp);

         output() << "Certificate validation status: " << result.result_string() << "\n";
         if(result.successful_validation())
            {
            auto status = result.all_statuses();

            if(status.size() > 0 && status[0].count(Botan::Certificate_Status_Code::OCSP_RESPONSE_GOOD))
               {
               output() << "Valid OCSP response for this server\n";
               }
            }
         }

      bool tls_session_established(const Botan::TLS::Session& session) override
         {
         output() << "Handshake complete, " << session.version().to_string()
                  << " using " << session.ciphersuite().to_string() << "\n";

         if(!session.session_id().empty())
            {
            output() << "Session ID " << Botan::hex_encode(session.session_id()) << "\n";
            }

         if(!session.session_ticket().empty())
            {
            output() << "Session ticket " << Botan::hex_encode(session.session_ticket()) << "\n";
            }

         if(flag_set("print-certs"))
            {
            const std::vector<Botan::X509_Certificate>& certs = session.peer_certs();

            for(size_t i = 0; i != certs.size(); ++i)
               {
               output() << "Certificate " << i + 1 << "/" << certs.size() << "\n";
               output() << certs[i].to_string();
               output() << certs[i].PEM_encode();
               }
            }

         return true;
         }

      static void dgram_socket_write(int sockfd, const uint8_t buf[], size_t length)
         {
         int r = ::send(sockfd, buf, length, MSG_NOSIGNAL);

         if(r == -1)
            {
            throw CLI_Error("Socket write failed errno=" + std::to_string(errno));
            }
         }

      void tls_emit_data(const uint8_t buf[], size_t length) override
         {
         size_t offset = 0;

         while(length)
            {
            ssize_t sent = ::send(m_sockfd, buf + offset, length, MSG_NOSIGNAL);

            if(sent == -1)
               {
               if(errno == EINTR)
                  {
                  sent = 0;
                  }
               else
                  {
                  throw CLI_Error("Socket write failed errno=" + std::to_string(errno));
                  }
               }

            offset += sent;
            length -= sent;
            }
         }

      void tls_alert(Botan::TLS::Alert alert) override
         {
         output() << "Alert: " << alert.type_string() << "\n";
         }

      void tls_record_received(uint64_t /*seq_no*/, const uint8_t buf[], size_t buf_size) override
         {
         for(size_t i = 0; i != buf_size; ++i)
            {
            output() << buf[i];
            }
         }

      socket_type m_sockfd = invalid_socket();
   };

BOTAN_REGISTER_COMMAND("tls_client", TLS_Client);

}

#endif
