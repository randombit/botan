/*
* TLS echo server using BSD sockets
* (C) 2014 Jack Lloyd
*     2017 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"
#include "sandbox.h"

#if defined(BOTAN_HAS_TLS) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM) && \
   defined(BOTAN_TARGET_OS_HAS_SOCKETS)

#if defined(SO_USER_COOKIE)
#define SOCKET_ID 1
#else
#define SOCKET_ID 0
#endif

#include <botan/tls_server.h>
#include <botan/tls_policy.h>
#include <botan/hex.h>
#include <botan/internal/os_utils.h>
#include <botan/mem_ops.h>

#include <list>
#include <fstream>

#include "tls_helpers.h"
#include "socket_utils.h"

namespace Botan_CLI {

class TLS_Server final : public Command, public Botan::TLS::Callbacks
   {
   public:
#if SOCKET_ID
      TLS_Server() : Command("tls_server cert key --port=443 --type=tcp --policy=default --dump-traces= --max-clients=0 --socket-id=0")
#else
      TLS_Server() : Command("tls_server cert key --port=443 --type=tcp --policy=default --dump-traces= --max-clients=0")
#endif
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
         const uint16_t port = get_arg_u16("port");
         const size_t max_clients = get_arg_sz("max-clients");
         const std::string transport = get_arg("type");
         const std::string dump_traces_to = get_arg("dump-traces");
#if SOCKET_ID
         m_socket_id = get_arg_sz("socket-id");
#endif

         if(transport != "tcp" && transport != "udp")
            {
            throw CLI_Usage_Error("Invalid transport type '" + transport + "' for TLS");
            }

         m_is_tcp = (transport == "tcp");

         auto policy = load_tls_policy(get_arg("policy"));

         Botan::TLS::Session_Manager_In_Memory session_manager(rng()); // TODO sqlite3

         Basic_Credentials_Manager creds(rng(), server_crt, server_key);

         output() << "Listening for new connections on " << transport << " port " << port << std::endl;

         if(!m_sandbox.init())
            {
            error_output() << "Failed sandboxing\n";
            return;
            }

         socket_type server_fd = make_server_socket(port);
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

               void* peek_buf = nullptr;
               size_t peek_len = 0;

#if defined(BOTAN_TARGET_OS_IS_MACOS)
               // macOS handles zero size buffers differently - it will return 0 even if there's no incoming data,
               // and after that connect() will fail as sockaddr_in from is not initialized
               int dummy;
               peek_buf = &dummy;
               peek_len = sizeof(dummy);
#endif

               if(::recvfrom(server_fd, static_cast<char*>(peek_buf), static_cast<sendrecv_len_type>(peek_len),
                             MSG_PEEK, reinterpret_cast<struct sockaddr*>(&from), &from_len) != 0)
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
                     ssize_t got = ::recv(m_socket, Botan::cast_uint8_ptr_to_char(buf), sizeof(buf), 0);

                     if(got == -1)
                        {
                        error_output() << "Error in socket read - " << err_to_string(errno) << std::endl;
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
                        close_socket(m_socket);
                        m_socket = invalid_socket();
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
               close_socket(m_socket);
               m_socket = invalid_socket();
               }
            }

         close_socket(server_fd);
         }
   private:
      socket_type make_server_socket(uint16_t port)
         {
         const int type = m_is_tcp ? SOCK_STREAM : SOCK_DGRAM;

         socket_type fd = ::socket(PF_INET, type, 0);
         if(fd == invalid_socket())
            {
            throw CLI_Error("Unable to acquire socket");
            }

         sockaddr_in socket_info;
         Botan::clear_mem(&socket_info, 1);
         socket_info.sin_family = AF_INET;
         socket_info.sin_port = htons(port);

         // FIXME: support limiting listeners
         socket_info.sin_addr.s_addr = INADDR_ANY;

         if(::bind(fd, reinterpret_cast<struct sockaddr*>(&socket_info), sizeof(struct sockaddr)) != 0)
            {
            close_socket(fd);
            throw CLI_Error("server bind failed");
            }

         if(m_is_tcp)
            {
            if(::listen(fd, 100) != 0)
               {
               close_socket(fd);
               throw CLI_Error("listen failed");
               }
            }
         if(m_socket_id > 0)
            {
#if SOCKET_ID
            // Other oses could have other means to trace sockets
#if defined(SO_USER_COOKIE)
            if(::setsockopt(fd, SOL_SOCKET, SO_USER_COOKIE, reinterpret_cast<const void *>(&m_socket_id), sizeof(m_socket_id)) != 0)
               {
               // Failed but not world-ending issue
               output() << "set socket cookie id failed" << std::endl;
               }
#endif
#endif
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
         }

      void tls_emit_data(const uint8_t buf[], size_t length) override
         {
         if(m_is_tcp)
            {
            ssize_t sent = ::send(m_socket, buf, static_cast<sendrecv_len_type>(length), MSG_NOSIGNAL);

            if(sent == -1)
               {
               error_output() << "Error writing to socket - " << err_to_string(errno) << std::endl;
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
               ssize_t sent = ::send(m_socket, buf, static_cast<sendrecv_len_type>(length), MSG_NOSIGNAL);

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

      socket_type m_socket = invalid_socket();
      bool m_is_tcp = false;
      uint32_t m_socket_id = 0;
      std::string m_line_buf;
      std::list<std::string> m_pending_output;
      Sandbox m_sandbox;
   };

BOTAN_REGISTER_COMMAND("tls_server", TLS_Server);

}

#endif
