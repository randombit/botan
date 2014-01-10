#include "apps.h"
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#define _GLIBCXX_HAVE_GTHR_DEFAULT
#include <boost/asio.hpp>
#include <boost/bind.hpp>
//#include <boost/thread.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>

#include <botan/tls_server.h>
#include <botan/x509cert.h>
#include <botan/pkcs8.h>
#include <botan/auto_rng.h>
#include <botan/init.h>

#include "credentials.h"

using Botan::byte;
using boost::asio::ip::tcp;

namespace {

class tls_server_session : public boost::enable_shared_from_this<tls_server_session>
   {
   public:
      typedef boost::shared_ptr<tls_server_session> pointer;

      static pointer create(boost::asio::io_service& io_service,
                            Botan::TLS::Session_Manager& session_manager,
                            Botan::Credentials_Manager& credentials,
                            Botan::TLS::Policy& policy,
                            Botan::RandomNumberGenerator& rng)
         {
         return pointer(
            new tls_server_session(
               io_service,
               session_manager,
               credentials,
               policy,
               rng)
            );
         }

      tcp::socket& socket() { return m_socket; }

      void start()
         {
         m_socket.async_read_some(
            boost::asio::buffer(m_read_buf, sizeof(m_read_buf)),
            m_strand.wrap(
               boost::bind(&tls_server_session::handle_read, shared_from_this(),
                           boost::asio::placeholders::error,
                           boost::asio::placeholders::bytes_transferred)));
         }

      void stop() { m_socket.close(); }

   private:
      tls_server_session(boost::asio::io_service& io_service,
                         Botan::TLS::Session_Manager& session_manager,
                         Botan::Credentials_Manager& credentials,
                         Botan::TLS::Policy& policy,
                         Botan::RandomNumberGenerator& rng) :
         m_strand(io_service),
         m_socket(io_service),
         m_tls(boost::bind(&tls_server_session::tls_output_wanted, this, _1, _2),
               boost::bind(&tls_server_session::tls_data_recv, this, _1, _2),
               boost::bind(&tls_server_session::tls_alert_cb, this, _1, _2, _3),
               boost::bind(&tls_server_session::tls_handshake_complete, this, _1),
               session_manager,
               credentials,
               policy,
               rng)
         {
         }

      void handle_read(const boost::system::error_code& error,
                       size_t bytes_transferred)
         {
         if(!error)
            {
            try
               {
               m_tls.received_data(m_read_buf, bytes_transferred);
               }
            catch(std::exception& e)
               {
               std::cout << "Read failed " << e.what() << "\n";
               stop();
               return;
               }

            m_socket.async_read_some(
               boost::asio::buffer(m_read_buf, sizeof(m_read_buf)),
               m_strand.wrap(boost::bind(&tls_server_session::handle_read, shared_from_this(),
                                         boost::asio::placeholders::error,
                                         boost::asio::placeholders::bytes_transferred)));
            }
         else
            {
            stop();
            }
         }

      void handle_write(const boost::system::error_code& error)
         {
         if(!error)
            {
            m_write_buf.clear();

            // initiate another write if needed
            tls_output_wanted(NULL, 0);
            }
         else
            {
            stop();
            }
         }

      void tls_output_wanted(const byte buf[], size_t buf_len)
         {
         if(buf_len > 0)
            m_outbox.insert(m_outbox.end(), buf, buf + buf_len);

         // no write pending and have output pending
         if(m_write_buf.empty() && !m_outbox.empty())
            {
            std::swap(m_outbox, m_write_buf);

            boost::asio::async_write(m_socket,
                              boost::asio::buffer(&m_write_buf[0], m_write_buf.size()),
                              m_strand.wrap(
                                 boost::bind(&tls_server_session::handle_write,
                                             shared_from_this(),
                                             boost::asio::placeholders::error)));
            }
         }

      void tls_alert_cb(Botan::TLS::Alert alert, const byte buf[], size_t buf_len)
         {
         if(alert.type() == Botan::TLS::Alert::CLOSE_NOTIFY)
            {
            m_tls.close();
            return;
            }
         }

      void tls_data_recv(const byte buf[], size_t buf_len)
         {
         m_client_data.insert(m_client_data.end(), buf, buf + buf_len);

         if(ready_to_respond())
            write_response();
         }

      bool ready_to_respond()
         {
         return true; // parse headers?
         }

      void write_response()
         {
         std::string out;
         out += "\r\n";
         out += "HTTP/1.0 200 OK\r\n";
         out += "Server: Botan ASIO test server\r\n";
         if(m_hostname != "")
            out += "Host: " + m_hostname + "\r\n";
         out += "Content-Type: text/html\r\n";
         out += "\r\n";
         out += "<html><body>Greets. You said: ";
         out += std::string((const char*)&m_client_data[0], m_client_data.size());
         out += "</body></html>\r\n\r\n";

         m_tls.send(out);
         m_tls.close();
         }

      bool tls_handshake_complete(const Botan::TLS::Session& session)
         {
         m_hostname = session.server_info().hostname();
         return true;
         }

      boost::asio::io_service::strand m_strand; // serialization

      tcp::socket m_socket;
      Botan::TLS::Server m_tls;
      std::string m_hostname;

      unsigned char m_read_buf[1024];

      // used to hold the data currently being written by the system
      std::vector<byte> m_write_buf;

      // used to hold data queued for writing
      std::vector<byte> m_outbox;

      std::vector<byte> m_client_data;
   };

class asio_tls_server
   {
   public:
      typedef tls_server_session session;

      asio_tls_server(boost::asio::io_service& io_service, unsigned short port) :
         m_acceptor(io_service, tcp::endpoint(tcp::v4(), port)),
         m_session_manager(m_rng),
         m_creds(m_rng)
         {
         session::pointer new_session = make_session();

         m_acceptor.async_accept(
            new_session->socket(),
            boost::bind(
               &asio_tls_server::handle_accept,
               this,
               new_session,
               boost::asio::placeholders::error)
            );
         }

   private:
      session::pointer make_session()
         {
         return session::create(
            m_acceptor.get_io_service(),
            m_session_manager,
            m_creds,
            m_policy,
            m_rng
            );
         }

      void handle_accept(session::pointer new_session,
                         const boost::system::error_code& error)
         {
         if (!error)
            {
            new_session->start();

            new_session = make_session();

            m_acceptor.async_accept(
               new_session->socket(),
               boost::bind(
                  &asio_tls_server::handle_accept,
                  this,
                  new_session,
                  boost::asio::placeholders::error)
               );
            }
         }

      tcp::acceptor m_acceptor;

      Botan::AutoSeeded_RNG m_rng;
      Botan::TLS::Session_Manager_In_Memory m_session_manager;
      Botan::TLS::Policy m_policy;
      Credentials_Manager_Simple m_creds;
   };

size_t choose_thread_count()
   {
   size_t result = std::thread::hardware_concurrency();

   if(result)
      return result;

   return 2;
   }

}

int tls_server_asio_main(int argc, char* argv[])
   {
   try
      {
      Botan::LibraryInitializer init("thread_safe=true");
      boost::asio::io_service io_service;

      const unsigned short port = 4434;
      asio_tls_server server(io_service, port);

      size_t num_threads = choose_thread_count();
      if(argc == 2)
         std::istringstream(argv[1]) >> num_threads;

      std::cout << "Using " << num_threads << " threads\n";

      std::vector<boost::shared_ptr<std::thread> > threads;

      for(size_t i = 0; i != num_threads; ++i)
         {
         boost::shared_ptr<std::thread> thread(
            new std::thread(
               boost::bind(&boost::asio::io_service::run, &io_service)));
         threads.push_back(thread);
         }

      // Wait for all threads in the pool to exit.
      for (size_t i = 0; i < threads.size(); ++i)
         threads[i]->join();
      }
   catch (std::exception& e)
      {
      std::cerr << e.what() << std::endl;
      }

   return 0;
   }

