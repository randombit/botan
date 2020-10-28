/*
* TLS ASIO Stream Client-Server Interaction Test
* (C) 2018-2020 Jack Lloyd
*     2018-2020 Hannes Rantzsch, Rene Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_TLS) && defined(BOTAN_HAS_TLS_ASIO_STREAM) && defined(BOTAN_TARGET_OS_HAS_THREADS)

// first version to be compatible with Networking TS (N4656) and boost::beast
#include <boost/version.hpp>
#if BOOST_VERSION >= 106600

#include <functional>

#include <botan/asio_stream.h>
#include <botan/auto_rng.h>

#include <boost/asio.hpp>

#include "../cli/tls_helpers.h"  // for Basic_Credentials_Manager

namespace {

namespace net = boost::asio;

using tcp = net::ip::tcp;
using error_code = boost::system::error_code;
using ssl_stream = Botan::TLS::Stream<net::ip::tcp::socket>;
using namespace std::placeholders;
using Result = Botan_Tests::Test::Result;

static const auto k_timeout = std::chrono::seconds(3);
static const auto k_endpoints = std::vector<tcp::endpoint> {tcp::endpoint{net::ip::make_address("127.0.0.1"), 8082}};

enum { max_msg_length = 512 };

static std::string server_cert() { return Botan_Tests::Test::data_dir() + "/x509/certstor/cert1.crt"; }
static std::string server_key() { return Botan_Tests::Test::data_dir() + "/x509/certstor/key01.pem"; }

class Timeout_Exception : public std::runtime_error
   {
      using std::runtime_error::runtime_error;
   };

class Side
   {
   public:
      Side()
         : m_credentials_manager(true, ""),
           m_ctx(m_credentials_manager, m_rng, m_session_mgr, m_policy, Botan::TLS::Server_Information()) {}

      Side(const std::string& server_cert, const std::string& server_key)
         : m_credentials_manager(m_rng, server_cert, server_key),
           m_ctx(m_credentials_manager, m_rng, m_session_mgr, m_policy, Botan::TLS::Server_Information()) {}

      virtual ~Side() {}

      net::mutable_buffer buffer() { return net::buffer(m_data, max_msg_length); }
      net::mutable_buffer buffer(size_t size) { return net::buffer(m_data, size); }

      std::string message() const { return std::string(m_data); }

      // This is a CompletionCondition for net::async_read().
      // Our toy protocol always expects a single \0-terminated string.
      std::size_t received_zero_byte(const boost::system::error_code& error,
                                     std::size_t bytes_transferred)
         {
         if(error)
            {
            return 0;
            }

         if(bytes_transferred > 0 && m_data[bytes_transferred - 1] == '\0')
            {
            return 0;
            }

         return max_msg_length - bytes_transferred;
         }

   protected:
      Botan::AutoSeeded_RNG m_rng;
      Basic_Credentials_Manager m_credentials_manager;
      Botan::TLS::Session_Manager_Noop m_session_mgr;
      Botan::TLS::Policy m_policy;
      Botan::TLS::Context m_ctx;
      std::unique_ptr<ssl_stream> m_stream;

      char m_data[max_msg_length];
   };

class Result_Wrapper
   {
   public:
      Result_Wrapper(net::io_context& ioc, const std::string& name) : m_timer(ioc), m_result(name) {}

      Result& result() { return m_result; }

      void set_timer(const std::string& msg)
         {
         m_timer.expires_after(k_timeout);
         m_timer.async_wait([this, msg](const error_code &ec)
            {
            if(ec != net::error::operation_aborted)  // timer cancelled
               {
               m_result.test_failure(m_result.who() + ": timeout in " + msg);
               throw Timeout_Exception(m_result.who());
               }
            });
         }

      void stop_timer()
         {
         m_timer.cancel();
         }

      void expect_success(const std::string& msg, const error_code& ec)
         {
         error_code success;
         expect_ec(msg, success, ec);
         }

      void expect_ec(const std::string& msg, const error_code& expected, const error_code& ec)
         {
         if(ec != expected)
            { m_result.test_failure(msg, "Unexpected error code: " + ec.message()); }
         else
            { m_result.test_success(msg); }
         }

      void confirm(const std::string& msg, bool condition)
         {
         m_result.confirm(msg, condition);
         }

      void test_failure(const std::string& msg)
         {
         m_result.test_failure(msg);
         }

   private:
      net::system_timer m_timer;
      Result m_result;
   };

class Server : public Side, public std::enable_shared_from_this<Server>
   {
   public:
      Server(net::io_context& ioc)
         : Side(server_cert(), server_key()),
           m_acceptor(ioc),
           m_result(ioc, "Server"),
           m_short_read_expected(false) {}

      // Control messages
      // The messages below can be used by the test clients in order to configure the server's behavior during a test
      // case.
      //
      // Tell the server that the next read should result in a StreamTruncated error
      std::string expect_short_read_message = "SHORT_READ";
      // Prepare the server for the test case "Shutdown No Response"
      std::string prepare_shutdown_no_response_message = "SHUTDOWN_NOW";

      void listen()
         {
         error_code ec;
         const auto endpoint = k_endpoints.back();

         m_acceptor.open(endpoint.protocol(), ec);
         m_acceptor.set_option(net::socket_base::reuse_address(true), ec);
         m_acceptor.bind(endpoint, ec);
         m_acceptor.listen(net::socket_base::max_listen_connections, ec);

         m_result.expect_success("listen", ec);

         m_result.set_timer("accept");
         m_acceptor.async_accept(std::bind(&Server::start_session, shared_from_this(), _1, _2));
         }

      void expect_short_read()
         {
         m_short_read_expected = true;
         }

      Result result() { return m_result.result(); }

   private:
      void start_session(const error_code& ec, tcp::socket socket)
         {
         // Note: If this fails with 'Operation canceled', it likely means the timer expired and the port is taken.
         m_result.expect_success("accept", ec);

         // Note: If this was a real server, we should create a new session (with its own stream) for each accepted
         // connection. In this test we only have one connection.
         m_stream = std::unique_ptr<ssl_stream>(new ssl_stream(std::move(socket), m_ctx));

         m_result.set_timer("handshake");
         m_stream->async_handshake(Botan::TLS::Connection_Side::SERVER,
                                   std::bind(&Server::handle_handshake, shared_from_this(), _1));
         }

      void shutdown()
         {
         error_code shutdown_ec;
         m_stream->shutdown(shutdown_ec);
         m_result.expect_success("shutdown", shutdown_ec);
         handle_write(error_code{});
         }


      void handle_handshake(const error_code& ec)
         {
         m_result.expect_success("handshake", ec);
         handle_write(error_code{});
         }

      void handle_write(const error_code& ec)
         {
         m_result.expect_success("send_response", ec);
         m_result.set_timer("read_message");
         net::async_read(*m_stream, buffer(),
                         std::bind(&Server::received_zero_byte, shared_from_this(), _1, _2),
                         std::bind(&Server::handle_read, shared_from_this(), _1, _2));
         }

      void handle_read(const error_code& ec, size_t bytes_transferred=0)
         {
         if(m_short_read_expected)
            {
            m_result.expect_ec("received stream truncated error", Botan::TLS::StreamTruncated, ec);
            quit();
            return;
            }

         if(ec)
            {
            if(m_stream->shutdown_received())
               {
               m_result.expect_ec("received EOF after close_notify", net::error::eof, ec);
               m_result.set_timer("shutdown");
               m_stream->async_shutdown(std::bind(&Server::handle_shutdown, shared_from_this(), _1));
               }
            else
               {
               m_result.test_failure("Unexpected error code: " + ec.message());
               quit();
               }
            return;
            }

         m_result.expect_success("read_message", ec);

         if(message() == prepare_shutdown_no_response_message)
            {
            m_short_read_expected = true;
            shutdown();
            return;
            }

         if(message() == expect_short_read_message)
            {
            m_short_read_expected = true;
            }

         m_result.set_timer("send_response");
         net::async_write(*m_stream, buffer(bytes_transferred),
                          std::bind(&Server::handle_write, shared_from_this(), _1));
         }

      void handle_shutdown(const error_code& ec)
         {
         m_result.expect_success("shutdown", ec);
         quit();
         }

      void quit()
         {
         m_result.stop_timer();
         }

   private:
      tcp::acceptor m_acceptor;
      Result_Wrapper m_result;
      bool m_short_read_expected;
   };

class Client : public Side
   {
      static void accept_all(
         const std::vector<Botan::X509_Certificate>&,
         const std::vector<std::shared_ptr<const Botan::OCSP::Response>>&,
         const std::vector<Botan::Certificate_Store*>&, Botan::Usage_Type,
         const std::string&, const Botan::TLS::Policy&) {}

   public:
      Client(net::io_context& ioc)
         : Side()
         {
         m_ctx.set_verify_callback(accept_all);
         m_stream = std::unique_ptr<ssl_stream>(new ssl_stream(ioc, m_ctx));
         }

      ssl_stream& stream() {return *m_stream; }

      void close_socket()
         {
         // Shutdown on TCP level before closing the socket for portable behavior. Otherwise the peer will see a
         // connection_reset error rather than EOF on Windows.
         // See the remark in
         // https://www.boost.org/doc/libs/1_68_0/doc/html/boost_asio/reference/basic_stream_socket/close/overload1.html
         m_stream->lowest_layer().shutdown(tcp::socket::shutdown_both);
         m_stream->lowest_layer().close();
         }

   };

#include <boost/asio/yield.hpp>

class TestBase
   {
   public:
      TestBase(net::io_context& ioc, std::shared_ptr<Server> server, const std::string& name)
         : m_client(ioc),
           m_server(server),
           m_result(ioc, name) {}

      virtual ~TestBase() = default;

      virtual void finishAsynchronousWork() {}

      Result result() { return m_result.result(); }

   protected:
      Client m_client;
      std::shared_ptr<Server> m_server;
      Result_Wrapper m_result;
   };

class Synchronous_Test : public TestBase
   {
   public:
      using TestBase::TestBase;

      void finishAsynchronousWork() override
         {
         m_client_thread.join();
         }

      void run(const error_code&)
         {
         m_client_thread = std::thread(std::bind(&Synchronous_Test::run_synchronous_client, this));
         }

      virtual void run_synchronous_client() = 0;

   private:
      std::thread m_client_thread;
   };

/* In this test case both parties perform the handshake, exchange a message, and do a full shutdown.
 *
 * The client expects the server to echo the same message it sent. The client then initiates the shutdown. The server is
 * expected to receive a close_notify and complete its shutdown with an error_code Success, the client is expected to
 * receive a close_notify and complete its shutdown with an error_code EOF.
 */
class Test_Conversation : public TestBase, public net::coroutine, public std::enable_shared_from_this<Test_Conversation>
   {
   public:
      Test_Conversation(net::io_context& ioc, std::shared_ptr<Server> server)
         : TestBase(ioc, server, "Test Conversation") {}

      void run(const error_code& ec)
         {
         static auto test_case = &Test_Conversation::run;
         const std::string message("Time is an illusion. Lunchtime doubly so.");

         reenter(*this)
            {
            m_result.set_timer("connect");
            yield net::async_connect(m_client.stream().lowest_layer(), k_endpoints,
                                     std::bind(test_case, shared_from_this(), _1));
            m_result.expect_success("connect", ec);

            m_result.set_timer("handshake");
            yield m_client.stream().async_handshake(Botan::TLS::Connection_Side::CLIENT,
                                                    std::bind(test_case, shared_from_this(), _1));
            m_result.expect_success("handshake", ec);

            m_result.set_timer("send_message");
            yield net::async_write(m_client.stream(),
                                   net::buffer(message.c_str(), message.size() + 1), // including \0 termination
                                   std::bind(test_case, shared_from_this(), _1));
            m_result.expect_success("send_message", ec);

            m_result.set_timer("receive_response");
            yield net::async_read(m_client.stream(),
                                  m_client.buffer(),
                                  std::bind(&Client::received_zero_byte, &m_client, _1, _2),
                                  std::bind(test_case, shared_from_this(), _1));
            m_result.expect_success("receive_response", ec);
            m_result.confirm("correct message", m_client.message() == message);

            m_result.set_timer("shutdown");
            yield m_client.stream().async_shutdown(std::bind(test_case, shared_from_this(), _1));
            m_result.expect_success("shutdown", ec);

            m_result.set_timer("await close_notify");
            yield net::async_read(m_client.stream(), m_client.buffer(),
                                  std::bind(test_case, shared_from_this(), _1));
            m_result.confirm("received close_notify", m_client.stream().shutdown_received());
            m_result.expect_ec("closed with EOF", net::error::eof, ec);

            m_result.stop_timer();
            }
         }
   };

class Test_Conversation_Sync : public Synchronous_Test
   {
   public:
      Test_Conversation_Sync(net::io_context& ioc, std::shared_ptr<Server> server)
         : Synchronous_Test(ioc, server, "Test Conversation Sync") {}

      void run_synchronous_client() override
         {
         const std::string message("Time is an illusion. Lunchtime doubly so.");
         error_code ec;

         net::connect(m_client.stream().lowest_layer(), k_endpoints, ec);
         m_result.expect_success("connect", ec);

         m_client.stream().handshake(Botan::TLS::Connection_Side::CLIENT, ec);
         m_result.expect_success("handshake", ec);

         net::write(m_client.stream(),
                    net::buffer(message.c_str(), message.size() + 1), // including \0 termination
                    ec);
         m_result.expect_success("send_message", ec);

         net::read(m_client.stream(),
                   m_client.buffer(),
                   std::bind(&Client::received_zero_byte, &m_client, _1, _2),
                   ec);
         m_result.expect_success("receive_response", ec);
         m_result.confirm("correct message", m_client.message() == message);

         m_client.stream().shutdown(ec);
         m_result.expect_success("shutdown", ec);

         net::read(m_client.stream(), m_client.buffer(), ec);
         m_result.confirm("received close_notify", m_client.stream().shutdown_received());
         m_result.expect_ec("closed with EOF", net::error::eof, ec);
         }
   };

/* In this test case the client shuts down the SSL connection, but does not wait for the server's response before
 * closing the socket. Accordingly, it will not receive the server's close_notify alert. Instead, the async_read
 * operation will be aborted. The server should be able to successfully shutdown nonetheless.
 */
class Test_Eager_Close : public TestBase, public net::coroutine, public std::enable_shared_from_this<Test_Eager_Close>
   {
   public:
      Test_Eager_Close(net::io_context& ioc, std::shared_ptr<Server> server)
         : TestBase(ioc, server, "Test Eager Close") {}

      void run(const error_code& ec)
         {
         static auto test_case = &Test_Eager_Close::run;
         reenter(*this)
            {
            m_result.set_timer("connect");
            yield net::async_connect(m_client.stream().lowest_layer(), k_endpoints,
                                     std::bind(test_case, shared_from_this(), _1));
            m_result.expect_success("connect", ec);

            m_result.set_timer("handshake");
            yield m_client.stream().async_handshake(Botan::TLS::Connection_Side::CLIENT,
                                                    std::bind(test_case, shared_from_this(), _1));
            m_result.expect_success("handshake", ec);

            m_result.set_timer("shutdown");
            yield m_client.stream().async_shutdown(std::bind(test_case, shared_from_this(), _1));
            m_result.expect_success("shutdown", ec);
            m_result.stop_timer();

            m_client.close_socket();
            m_result.confirm("did not receive close_notify", !m_client.stream().shutdown_received());
            }
         }
   };

class Test_Eager_Close_Sync : public Synchronous_Test
   {
   public:
      Test_Eager_Close_Sync(net::io_context& ioc, std::shared_ptr<Server> server)
         : Synchronous_Test(ioc, server, "Test Eager Close Sync") {}

      void run_synchronous_client() override
         {
         error_code ec;

         net::connect(m_client.stream().lowest_layer(), k_endpoints, ec);
         m_result.expect_success("connect", ec);

         m_client.stream().handshake(Botan::TLS::Connection_Side::CLIENT, ec);
         m_result.expect_success("handshake", ec);

         m_client.stream().shutdown(ec);
         m_result.expect_success("shutdown", ec);

         m_client.close_socket();
         m_result.confirm("did not receive close_notify", !m_client.stream().shutdown_received());
         }
   };

/* In this test case the client closes the socket without properly shutting down the connection.
 * The server should see a StreamTruncated error.
 */
class Test_Close_Without_Shutdown
   : public TestBase,
     public net::coroutine,
     public std::enable_shared_from_this<Test_Close_Without_Shutdown>
   {
   public:
      Test_Close_Without_Shutdown(net::io_context& ioc, std::shared_ptr<Server> server)
         : TestBase(ioc, server, "Test Close Without Shutdown") {}

      void run(const error_code& ec)
         {
         static auto test_case = &Test_Close_Without_Shutdown::run;
         reenter(*this)
            {
            m_result.set_timer("connect");
            yield net::async_connect(m_client.stream().lowest_layer(), k_endpoints,
                                     std::bind(test_case, shared_from_this(), _1));
            m_result.expect_success("connect", ec);

            m_result.set_timer("handshake");
            yield m_client.stream().async_handshake(Botan::TLS::Connection_Side::CLIENT,
                                                    std::bind(test_case, shared_from_this(), _1));
            m_result.expect_success("handshake", ec);

            // send the control message to configure the server to expect a short-read
            m_result.set_timer("send expect_short_read message");
            yield net::async_write(m_client.stream(),
                                   net::buffer(m_server->expect_short_read_message.c_str(),
                                               m_server->expect_short_read_message.size() + 1), // including \0 termination
                                   std::bind(test_case, shared_from_this(), _1));
            m_result.expect_success("send expect_short_read message", ec);

            // read the confirmation of the control message above
            m_result.set_timer("receive_response");
            yield net::async_read(m_client.stream(),
                                  m_client.buffer(),
                                  std::bind(&Client::received_zero_byte, &m_client, _1, _2),
                                  std::bind(test_case, shared_from_this(), _1));
            m_result.expect_success("receive_response", ec);

            m_result.stop_timer();

            m_client.close_socket();
            m_result.confirm("did not receive close_notify", !m_client.stream().shutdown_received());
            }
         }
   };

class Test_Close_Without_Shutdown_Sync : public Synchronous_Test
   {
   public:
      Test_Close_Without_Shutdown_Sync(net::io_context& ioc, std::shared_ptr<Server> server)
         : Synchronous_Test(ioc, server, "Test Close Without Shutdown Sync") {}

      void run_synchronous_client() override
         {
         error_code ec;
         net::connect(m_client.stream().lowest_layer(), k_endpoints, ec);
         m_result.expect_success("connect", ec);

         m_client.stream().handshake(Botan::TLS::Connection_Side::CLIENT, ec);
         m_result.expect_success("handshake", ec);

         m_server->expect_short_read();

         m_client.close_socket();
         m_result.confirm("did not receive close_notify", !m_client.stream().shutdown_received());
         }
   };

/* In this test case the server shuts down the connection but the client doesn't send the corresponding close_notify
 * response. Instead, it closes the socket immediately.
 * The server should see a short-read error.
 */
class Test_No_Shutdown_Response : public TestBase, public net::coroutine,
   public std::enable_shared_from_this<Test_No_Shutdown_Response>
   {
   public:
      Test_No_Shutdown_Response(net::io_context& ioc, std::shared_ptr<Server> server)
         : TestBase(ioc, server, "Test No Shutdown Response") {}

      void run(const error_code& ec)
         {
         static auto test_case = &Test_No_Shutdown_Response::run;
         reenter(*this)
            {
            m_result.set_timer("connect");
            yield net::async_connect(m_client.stream().lowest_layer(), k_endpoints,
                                     std::bind(test_case, shared_from_this(), _1));
            m_result.expect_success("connect", ec);

            m_result.set_timer("handshake");
            yield m_client.stream().async_handshake(Botan::TLS::Connection_Side::CLIENT,
                                                    std::bind(test_case, shared_from_this(), _1));
            m_result.expect_success("handshake", ec);

            // send a control message to make the server shut down
            m_result.set_timer("send shutdown message");
            yield net::async_write(m_client.stream(),
                                   net::buffer(m_server->prepare_shutdown_no_response_message.c_str(),
                                               m_server->prepare_shutdown_no_response_message.size() + 1), // including \0 termination
                                   std::bind(test_case, shared_from_this(), _1));
            m_result.expect_success("send shutdown message", ec);

            // read the server's close-notify message
            m_result.set_timer("read close_notify");
            yield net::async_read(m_client.stream(), m_client.buffer(),
                                  std::bind(test_case, shared_from_this(), _1));
            m_result.expect_ec("read gives EOF", net::error::eof, ec);
            m_result.confirm("received close_notify", m_client.stream().shutdown_received());

            m_result.stop_timer();

            // close the socket rather than shutting down
            m_client.close_socket();
            }
         }
   };

class Test_No_Shutdown_Response_Sync : public Synchronous_Test
   {
   public:
      Test_No_Shutdown_Response_Sync(net::io_context& ioc, std::shared_ptr<Server> server)
         : Synchronous_Test(ioc, server, "Test No Shutdown Response Sync") {}

      void run_synchronous_client() override
         {
         error_code ec;
         net::connect(m_client.stream().lowest_layer(), k_endpoints, ec);
         m_result.expect_success("connect", ec);

         m_client.stream().handshake(Botan::TLS::Connection_Side::CLIENT, ec);
         m_result.expect_success("handshake", ec);

         net::write(m_client.stream(),
                    net::buffer(m_server->prepare_shutdown_no_response_message.c_str(),
                                m_server->prepare_shutdown_no_response_message.size() + 1), // including \0 termination
                    ec);
         m_result.expect_success("send expect_short_read message", ec);

         net::read(m_client.stream(), m_client.buffer(), ec);
         m_result.expect_ec("read gives EOF", net::error::eof, ec);
         m_result.confirm("received close_notify", m_client.stream().shutdown_received());

         // close the socket rather than shutting down
         m_client.close_socket();
         }
   };

#include <boost/asio/unyield.hpp>

template<typename TestT>
void run_test_case(std::vector<Result>& results)
   {
   net::io_context ioc;

   auto s = std::make_shared<Server>(ioc);
   s->listen();

   auto t = std::make_shared<TestT>(ioc, s);
   t->run(error_code{});

   try
      {
      ioc.run();
      }
   catch(Timeout_Exception&) { /* the test result will already contain a failure */ }

   t->finishAsynchronousWork();

   results.push_back(s->result());
   results.push_back(t->result());
   }

}  // namespace

namespace Botan_Tests {

class Tls_Stream_Integration_Tests final : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;

         run_test_case<Test_Conversation>(results);
         run_test_case<Test_Eager_Close>(results);
         run_test_case<Test_Close_Without_Shutdown>(results);
         run_test_case<Test_No_Shutdown_Response>(results);
         run_test_case<Test_Conversation_Sync>(results);
         run_test_case<Test_Eager_Close_Sync>(results);
         run_test_case<Test_Close_Without_Shutdown_Sync>(results);
         run_test_case<Test_No_Shutdown_Response_Sync>(results);

         return results;
         }
   };

BOTAN_REGISTER_TEST("tls", "tls_stream_integration", Tls_Stream_Integration_Tests);

}  // namespace Botan_Tests

#endif // BOOST_VERSION
#endif // BOTAN_HAS_TLS && BOTAN_HAS_BOOST_ASIO
