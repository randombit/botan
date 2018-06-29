/*
* TLS echo server using BSD sockets
* (C) 2014 Jack Lloyd
*     2017 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_TLS) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM) && \
   (defined(BOTAN_TARGET_OS_HAS_SOCKETS) || defined(BOTAN_TARGET_OS_HAS_WINSOCK2))

#include <botan/tls_server.h>
#include <botan/tls_policy.h>
#include <botan/hex.h>
#include <botan/internal/os_utils.h>

#include <list>
#include <fstream>

#include "credentials.h"
#include "socket_utils.h"

namespace Botan_CLI {

class TLS_Server final : public Command, public Botan::TLS::Callbacks
   {
   public:
      TLS_Server() : Command("tls_server cert key --port=443 --type=tcp --policy= --dump-traces= --max-clients=0")
         {
         init_sockets();
         }

      ~TLS_Server()
         {
         stop_sockets();
         }

      std::string group() const override
         {
         return "tls";
         }

      std::string description() const override
         {
         return "Accept TLS/DTLS connections from TLS/DTLS clients";
         }

      void go() override
         {
         const std::string server_crt = get_arg("cert");
         const std::string server_key = get_arg("key");
         const int port = get_arg_sz("port");
         const size_t max_clients = get_arg_sz("max-clients");
         const std::string transport = get_arg("type");
         const std::string dump_traces_to = get_arg("dump-traces");

         if(transport != "tcp" && transport != "udp")
            {
            throw CLI_Usage_Error("Invalid transport type '" + transport + "' for TLS");
            }

         m_is_tcp = (transport == "tcp");

         std::unique_ptr<Botan::TLS::Policy> policy;
         const std::string policy_file = get_arg("policy");
         if(policy_file.size() > 0)
            {
            std::ifstream policy_stream(policy_file);
            if(!policy_stream.good())
               {
               error_output() << "Failed reading policy file\n";
               return;
               }
            policy.reset(new Botan::TLS::Text_Policy(policy_stream));
            }

         if(!policy)
            {
            policy.reset(new Botan::TLS::Policy);
            }

         Botan::TLS::Session_Manager_In_Memory session_manager(rng()); // TODO sqlite3

         Basic_Credentials_Manager creds(rng(), server_crt, server_key);

         output() << "Listening for new connections on " << transport << " port " << port << std::endl;

         int server_fd = make_server_socket(port);
         size_t clients_served = 0;

         while(true)
            {
            if(max_clients > 0 && clients_served >= max_clients)
               break;

            if(m_is_tcp)
               {
               m_socket = ::accept(server_fd, nullptr, nullptr);
               }
            else
               {
               struct sockaddr_in from;
               socklen_t from_len = sizeof(sockaddr_in);

               if(::recvfrom(server_fd, nullptr, 0, MSG_PEEK, reinterpret_cast<struct sockaddr*>(&from), &from_len) != 0)
                  {
                  throw CLI_Error("Could not peek next packet");
                  }

               if(::connect(server_fd, reinterpret_cast<struct sockaddr*>(&from), from_len) != 0)
                  {
                  throw CLI_Error("Could not connect UDP socket");
                  }
               m_socket = server_fd;
               }

            clients_served++;

            Botan::TLS::Server server(
               *this,
               session_manager,
               creds,
               *policy,
               rng(),
               m_is_tcp == false);

            std::unique_ptr<std::ostream> dump_stream;

            if(!dump_traces_to.empty())
               {
               uint64_t timestamp = Botan::OS::get_high_resolution_clock();
               const std::string dump_file =
                  dump_traces_to + "/tls_" + std::to_string(timestamp) + ".bin";
               dump_stream.reset(new std::ofstream(dump_file.c_str()));
               }

            try
               {
               while(!server.is_closed())
                  {
                  try
                     {
                     uint8_t buf[4 * 1024] = { 0 };
                     ssize_t got = ::read(m_socket, buf, sizeof(buf));

                     if(got == -1)
                        {
                        error_output() << "Error in socket read - " << std::strerror(errno) << std::endl;
                        break;
                        }

                     if(got == 0)
                        {
                        error_output() << "EOF on socket" << std::endl;
                        break;
                        }

                     if(dump_stream)
                        {
                        dump_stream->write(reinterpret_cast<const char*>(buf), got);
                        }

                     server.received_data(buf, got);

                     while(server.is_active() && !m_pending_output.empty())
                        {
                        std::string output = m_pending_output.front();
                        m_pending_output.pop_front();
                        server.send(output);

                        if(output == "quit\n")
                           {
                           server.close();
                           }
                        }
                     }
                  catch(std::exception& e)
                     {
                     error_output() << "Connection problem: " << e.what() << std::endl;
                     if(m_is_tcp)
                        {
                        ::close(m_socket);
                        m_socket = -1;
                        }
                     }
                  }
               }
            catch(Botan::Exception& e)
               {
               error_output() << "Connection failed: " << e.what() << "\n";
               }

            if(m_is_tcp)
               {
               ::close(m_socket);
               m_socket = -1;
               }
            }

         ::close(server_fd);
         }
   private:
      int make_server_socket(uint16_t port)
         {
         const int type = m_is_tcp ? SOCK_STREAM : SOCK_DGRAM;

         int fd = ::socket(PF_INET, type, 0);
         if(fd == -1)
            {
            throw CLI_Error("Unable to acquire socket");
            }

         sockaddr_in socket_info;
         ::memset(&socket_info, 0, sizeof(socket_info));
         socket_info.sin_family = AF_INET;
         socket_info.sin_port = htons(port);

         // FIXME: support limiting listeners
         socket_info.sin_addr.s_addr = INADDR_ANY;

         if(::bind(fd, reinterpret_cast<struct sockaddr*>(&socket_info), sizeof(struct sockaddr)) != 0)
            {
            ::close(fd);
            throw CLI_Error("server bind failed");
            }

         if(m_is_tcp)
            {
            if(::listen(fd, 100) != 0)
               {
               ::close(fd);
               throw CLI_Error("listen failed");
               }
            }
         return fd;
         }

      bool tls_session_established(const Botan::TLS::Session& session) override
         {
         output() << "Handshake complete, " << session.version().to_string()
                  << " using " << session.ciphersuite().to_string() << std::endl;

         if(!session.session_id().empty())
            {
            output() << "Session ID " << Botan::hex_encode(session.session_id()) << std::endl;
            }

         if(!session.session_ticket().empty())
            {
            output() << "Session ticket " << Botan::hex_encode(session.session_ticket()) << std::endl;
            }

         return true;
         }

      void tls_record_received(uint64_t, const uint8_t input[], size_t input_len) override
         {
         for(size_t i = 0; i != input_len; ++i)
            {
            const char c = static_cast<char>(input[i]);
            m_line_buf += c;
            if(c == '\n')
               {
               m_pending_output.push_back(m_line_buf);
               m_line_buf.clear();
               }
            }
         };

      void tls_emit_data(const uint8_t buf[], size_t length) override
         {
         if(m_is_tcp)
            {
            ssize_t sent = ::send(m_socket, buf, length, MSG_NOSIGNAL);

            if(sent == -1)
               {
               error_output() << "Error writing to socket - " << std::strerror(errno) << std::endl;
               }
            else if(sent != static_cast<ssize_t>(length))
               {
               error_output() << "Packet of length " << length << " truncated to " << sent << std::endl;
               }
            }
         else
            {
            while(length)
               {
               ssize_t sent = ::send(m_socket, buf, length, MSG_NOSIGNAL);

               if(sent == -1)
                  {
                  if(errno == EINTR)
                     {
                     sent = 0;
                     }
                  else
                     {
                     throw CLI_Error("Socket write failed");
                     }
                  }

               buf += sent;
               length -= sent;
               }
            }
         }

      void tls_alert(Botan::TLS::Alert alert) override
         {
         output() << "Alert: " << alert.type_string() << std::endl;
         }

      std::string tls_server_choose_app_protocol(const std::vector<std::string>&) override
         {
         // we ignore whatever the client sends here
         return "echo/0.1";
         }

      int m_socket = -1;
      bool m_is_tcp = false;
      std::string m_line_buf;
      std::list<std::string> m_pending_output;
   };

BOTAN_REGISTER_COMMAND("tls_server", TLS_Server);

}

#endif
