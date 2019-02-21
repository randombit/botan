#include "tests.h"

#include <iostream>

#if defined(BOTAN_HAS_TLS) && defined(BOTAN_HAS_BOOST_ASIO)

#include <botan/asio_stream.h>
#include <botan/tls_callbacks.h>

#include <boost/beast/experimental/test/stream.hpp>
#include <boost/bind.hpp>

namespace Botan_Tests {

namespace asio   = boost::asio;
using error_code = boost::system::error_code;

constexpr uint8_t     TEST_DATA[] = "The story so far: In the beginning the Universe was created. "
                                    "This has made a lot of people very angry and been widely regarded as a bad move.";
constexpr std::size_t TEST_DATA_SIZE = 142;
static_assert(sizeof(TEST_DATA) == TEST_DATA_SIZE, "size of TEST_DATA must match TEST_DATA_SIZE");

// use memcmp to check if the data in a is a prefix of the data in b
bool contains(const void* a, const void* b, const std::size_t size) { return memcmp(a, b, size) == 0; }

/**
 * Mocked Botan::TLS::Channel. Pretends to perform TLS operations and triggers appropriate callbacks in StreamCore.
 */
class MockChannel
   {
   public:
      MockChannel(Botan::TLS::StreamCore& core)
         : m_callbacks(core)
         , m_bytes_till_complete_record(TEST_DATA_SIZE)
         , m_active(false)
         {
         }

   public:
      std::size_t received_data(const uint8_t[], std::size_t buf_size)
         {
         if(m_bytes_till_complete_record <= buf_size)
            {
            m_callbacks.tls_record_received(0, TEST_DATA, TEST_DATA_SIZE);
            m_active = true;  // claim to be active once a full record has been received (for handshake test)
            return 0;
            }
         m_bytes_till_complete_record -= buf_size;
         return m_bytes_till_complete_record;
         }

      void send(const uint8_t buf[], std::size_t buf_size) { m_callbacks.tls_emit_data(buf, buf_size); }

      bool is_active() { return m_active; }

   protected:
      Botan::TLS::StreamCore& m_callbacks;
      std::size_t m_bytes_till_complete_record;  // number of bytes still to read before tls record is completed
      bool        m_active;
   };

/**
 * Mocked network socket. As all data from the socket is first processed in the (also mocked) channel and never directly
 * in the tested Stream, this socket will not perform any actual reading or writing to buffers. It will only claim to
 * have done so, while the channel is responsible for faking the data for the testee.
 */
struct MockSocket
   {
   MockSocket(std::size_t buf_size = 64)
      : buf_size(buf_size)
      {
      }

   template <typename MutableBufferSequence>
   std::size_t read_some(const MutableBufferSequence& buffers, error_code& ec)
      {
      ec = error;
      if(ec)
         {
         return 0;
         }
      return std::min(asio::buffer_size(buffers), buf_size);
      }

   template <typename ConstBufferSequence>
   std::size_t write_some(const ConstBufferSequence& buffers, error_code& ec)
      {
      ec = error;
      if(ec)
         {
         return 0;
         }
      const auto max_write = std::min(asio::buffer_size(buffers), buf_size);
      for(auto it = asio::buffer_sequence_begin(buffers);
            it != asio::buffer_sequence_end(buffers);
            it++)
         {
         const auto from = (const uint8_t*)it->data();
         const auto to = (const uint8_t*)it->data() + max_write;
         std::copy(from, to, std::back_inserter(write_buf));
         }
      return max_write;
      }

   template <typename MutableBufferSequence, typename ReadHandler>
   BOOST_ASIO_INITFN_RESULT_TYPE(ReadHandler, void(error_code, std::size_t))
   async_read_some(const MutableBufferSequence& buffers, ReadHandler&& handler)
      {
      handler(error, read_some(buffers, error));
      }

   template <typename ConstBufferSequence, typename WriteHandler>
   BOOST_ASIO_INITFN_RESULT_TYPE(WriteHandler, void(error_code, std::size_t))
   async_write_some(const ConstBufferSequence& buffers, WriteHandler&& handler)
      {
      handler(error, write_some(buffers, error));
      }

   using lowest_layer_type = MockSocket;
   using executor_type     = MockSocket;

   error_code  error;
   std::size_t buf_size;            // pretend to read/write only buf_size
   std::vector<uint8_t> write_buf;  // store everything that is written
   };
}  // namespace Botan_Tests

namespace Botan {

namespace TLS {

/**
 * A specification of StreamBase for the MockChannel used in this test. It
 * matches the specifications for StreamBase<Botan::TLS::Client> and
 * StreamBase<Botan::TLS::Server> except for the underlying channel type and the
 * simplified constructor.
 */
template <>
class StreamBase<Botan_Tests::MockChannel>
   {
   public:
      StreamBase()
         : m_channel(m_core)
         {
         }

      StreamBase(const StreamBase&) = delete;
      StreamBase& operator=(const StreamBase&) = delete;

      using handshake_type = Botan::TLS::handshake_type;

   protected:
      StreamCore               m_core;
      Botan::AutoSeeded_RNG    m_rng;
      Botan_Tests::MockChannel m_channel;

      void validate_handshake_type(handshake_type) {}

      bool validate_handshake_type(handshake_type, boost::system::error_code&) { return true; }
   };

}  // namespace TLS

}  // namespace Botan

namespace Botan_Tests {

/**
  Synchronous tests for Botan::Stream.

  This test validates the asynchronous behavior Botan::Stream, including its utility classes StreamCore and Async_*_Op.
  The stream's channel, i.e. TLS_Client or TLS_Server, is mocked and pretends to perform TLS operations (noop) and
  provides the test data to the stream.
  The underlying network socket, claiming it read / wrote a number of bytes.
*/
class Asio_Stream_Tests final : public Test
   {
      using AsioStream = Botan::TLS::Stream<MockSocket&, MockChannel>;

      void test_sync_handshake(std::vector<Test::Result>& results)
         {
         MockSocket socket;
         AsioStream ssl{socket};

         ssl.handshake(AsioStream::handshake_type::client);

         Test::Result result("sync TLS handshake");
         result.test_eq("feeds data into channel until active", ssl.native_handle()->is_active(), true);
         results.push_back(result);
         }

      void test_sync_handshake_error(std::vector<Test::Result>& results)
         {
         MockSocket socket;
         AsioStream ssl{socket};

         const auto expected_ec = asio::error::host_unreachable;
         socket.error           = expected_ec;

         error_code ec;
         ssl.handshake(AsioStream::handshake_type::client, ec);

         Test::Result result("sync TLS handshake error");
         result.test_eq("does not activate channel", ssl.native_handle()->is_active(), false);
         result.confirm("propagates error code", ec == expected_ec);
         results.push_back(result);
         }

      void test_async_handshake(std::vector<Test::Result>& results)
         {
         MockSocket socket;
         AsioStream ssl{socket};

         Test::Result result("async TLS handshake");

         auto handler = [&](const error_code&)
            {
            result.test_eq("feeds data into channel until active", ssl.native_handle()->is_active(), true);
            };

         ssl.async_handshake(AsioStream::handshake_type::client, handler);
         results.push_back(result);
         }

      void test_async_handshake_error(std::vector<Test::Result>& results)
         {
         MockSocket socket;
         AsioStream ssl{socket};

         const auto expected_ec = asio::error::host_unreachable;
         socket.error           = expected_ec;

         Test::Result result("async TLS handshake error");

         auto handler = [&](const error_code &ec)
            {
            result.test_eq("does not activate channel", ssl.native_handle()->is_active(), false);
            result.confirm("propagates error code", ec == expected_ec);
            };

         ssl.async_handshake(AsioStream::handshake_type::client, handler);
         results.push_back(result);
         }

      void test_sync_read_some_success(std::vector<Test::Result>& results)
         {
         MockSocket socket;
         AsioStream ssl{socket};
         const std::size_t buf_size = 128;
         uint8_t           buf[buf_size];
         error_code        ec;

         auto bytes_transferred = asio::read(ssl, asio::buffer(buf, sizeof(buf)), ec);

         Test::Result result("sync read_some success");
         result.confirm("reads the correct data", contains(buf, TEST_DATA, buf_size));
         result.test_eq("reads the correct amount of data", bytes_transferred, buf_size);
         result.confirm("does not report an error", !ec);

         results.push_back(result);
         }

      void test_sync_read_some_error(std::vector<Test::Result>& results)
         {
         MockSocket socket;
         AsioStream ssl{socket};
         const auto expected_ec = asio::error::eof;
         socket.error           = expected_ec;

         uint8_t    buf[128];
         error_code ec;

         auto bytes_transferred = asio::read(ssl, asio::buffer(buf, sizeof(buf)), ec);

         Test::Result result("sync read_some error");
         result.test_eq("didn't transfer anything", bytes_transferred, 0);
         result.confirm("propagates error code", ec == expected_ec);

         results.push_back(result);
         }

      void test_async_read_some_success(std::vector<Test::Result>& results)
         {
         MockSocket socket;
         AsioStream ssl{socket};
         const std::size_t buf_size = 128;
         uint8_t           buf[buf_size];
         error_code        ec;

         Test::Result result("async read_some success");

         auto read_handler = [&](const error_code &ec, std::size_t bytes_transferred)
            {
            result.confirm("reads the correct data", contains(buf, TEST_DATA, buf_size));
            result.test_eq("reads the correct amount of data", bytes_transferred, buf_size);
            result.confirm("does not report an error", !ec);
            };

         asio::async_read(ssl, asio::buffer(buf, sizeof(buf)), read_handler);

         results.push_back(result);
         }

      void test_async_read_some_error(std::vector<Test::Result>& results)
         {
         MockSocket socket;
         AsioStream ssl{socket};
         uint8_t    buf[128];
         error_code ec;

         const auto expected_ec = asio::error::eof;
         socket.error           = expected_ec;

         Test::Result result("async read_some error");

         auto read_handler = [&](const error_code &ec, std::size_t bytes_transferred)
            {
            result.test_eq("didn't transfer anything", bytes_transferred, 0);
            result.confirm("propagates error code", ec == expected_ec);
            };

         asio::async_read(ssl, asio::buffer(buf, sizeof(buf)), read_handler);

         results.push_back(result);
         }

      void test_sync_write_some_success(std::vector<Test::Result>& results)
         {
         MockSocket socket;
         AsioStream ssl{socket};
         error_code ec;

         auto bytes_transferred = asio::write(ssl, asio::buffer(TEST_DATA, TEST_DATA_SIZE), ec);

         Test::Result result("sync write_some success");
         result.confirm("writes the correct data", contains(socket.write_buf.data(), TEST_DATA, TEST_DATA_SIZE));
         result.test_eq("writes the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
         result.confirm("does not report an error", !ec);

         results.push_back(result);
         }

      void test_sync_write_some_error(std::vector<Test::Result>& results)
         {
         MockSocket socket;
         AsioStream ssl{socket};
         error_code ec;

         const auto expected_ec = asio::error::eof;
         socket.error           = expected_ec;

         auto bytes_transferred = asio::write(ssl, asio::buffer(TEST_DATA, TEST_DATA_SIZE), ec);

         Test::Result result("sync write_some error");
         result.test_eq("didn't transfer anything", bytes_transferred, 0);
         result.confirm("propagates error code", ec == expected_ec);

         results.push_back(result);
         }

      void test_async_write_some_success(std::vector<Test::Result>& results)
         {
         MockSocket socket;
         AsioStream ssl{socket};
         error_code ec;

         Test::Result result("async write_some success");

         auto write_handler = [&](const error_code &ec, std::size_t bytes_transferred)
            {
            result.confirm("writes the correct data", contains(socket.write_buf.data(), TEST_DATA, TEST_DATA_SIZE));
            result.test_eq("writes the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
            result.confirm("does not report an error", !ec);
            };

         asio::async_write(ssl, asio::buffer(TEST_DATA, TEST_DATA_SIZE), write_handler);

         results.push_back(result);
         }

      void test_async_write_some_error(std::vector<Test::Result>& results)
         {
         MockSocket socket;
         AsioStream ssl{socket};
         error_code ec;

         const auto expected_ec = asio::error::eof;
         socket.error           = expected_ec;

         Test::Result result("async write_some error");

         auto write_handler = [&](const error_code &ec, std::size_t bytes_transferred)
            {
            result.test_eq("didn't transfer anything", bytes_transferred, 0);
            result.confirm("propagates error code", ec == expected_ec);
            };

         asio::async_write(ssl, asio::buffer(TEST_DATA, TEST_DATA_SIZE), write_handler);

         results.push_back(result);
         }

   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;

         test_sync_handshake(results);
         test_sync_handshake_error(results);

         test_async_handshake(results);
         test_async_handshake_error(results);

         test_sync_read_some_success(results);
         test_sync_read_some_error(results);

         test_async_read_some_success(results);
         test_async_read_some_error(results);

         test_sync_write_some_success(results);
         test_sync_write_some_error(results);

         test_async_write_some_success(results);
         test_async_write_some_error(results);

         return results;
         }
   };

/**
  Tests for Botan::Stream based on boost::beast::test::stream.

  This test validates the asynchronous behavior Botan::Stream, including its utility classes StreamCore and Async_*_Op.
  The stream's channel, i.e. TLS_Client or TLS_Server, is mocked and pretends to perform TLS operations (noop) and
  provides the test data to the stream.
  The underlying network socket is a beast::test::socket that mimics asynchronous IO.
*/
class Asio_Stream_Tests_Beast final : public Test
   {
      using TestStream = boost::beast::test::stream;
      using AsioStream = Botan::TLS::Stream<TestStream&, MockChannel>;

      boost::string_view test_data() const { return boost::string_view((const char*)TEST_DATA, TEST_DATA_SIZE); }

      void test_async_handshake(std::vector<Test::Result>& results)
         {
         asio::io_context    ioc;
         TestStream socket{ioc}, remote{ioc};
         socket.connect(remote);
         socket.append(test_data());

         AsioStream ssl{socket};
         // mimic handshake initialization
         ssl.native_handle()->send(TEST_DATA, TEST_DATA_SIZE);

         Test::Result result("async TLS handshake");

         auto handler = [&](const error_code&)
            {
            result.confirm("reads from socket", socket.nread() > 0);
            result.confirm("writes from socket", socket.nwrite() > 0);
            result.test_eq("feeds data into channel until active", ssl.native_handle()->is_active(), true);
            };

         ssl.async_handshake(AsioStream::handshake_type::client, handler);

         socket.close_remote();
         ioc.run();
         results.push_back(result);
         }

      void test_async_handshake_error(std::vector<Test::Result>& results)
         {
         asio::io_context    ioc;
         TestStream socket{ioc}, remote{ioc};
         socket.connect(remote);
         socket.close_remote();  // close socket right away

         AsioStream ssl{socket};
         // mimic handshake initialization
         ssl.native_handle()->send(TEST_DATA, TEST_DATA_SIZE);

         Test::Result result("async TLS handshake error");

         auto handler = [&](const error_code &ec)
            {
            result.test_eq("does not activate channel", ssl.native_handle()->is_active(), false);
            result.confirm("propagates error code", (bool)ec);
            };

         ssl.async_handshake(AsioStream::handshake_type::client, handler);

         ioc.run();
         results.push_back(result);
         }

      void test_async_read_some_success(std::vector<Test::Result>& results)
         {
         asio::io_context    ioc;
         TestStream socket{ioc};
         socket.append(test_data());

         AsioStream ssl{socket};
         uint8_t    data[TEST_DATA_SIZE];
         error_code ec;

         Test::Result result("async read_some success");

         auto read_handler = [&](const error_code &ec, std::size_t bytes_transferred)
            {
            result.confirm("reads the correct data", contains(data, TEST_DATA, TEST_DATA_SIZE));
            result.test_eq("reads the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
            result.confirm("does not report an error", !ec);
            };

         asio::mutable_buffer buf = asio::buffer(data, TEST_DATA_SIZE);
         asio::async_read(ssl, buf, read_handler);

         socket.close_remote();
         ioc.run();
         results.push_back(result);
         }

      void test_async_read_some_error(std::vector<Test::Result>& results)
         {
         asio::io_context    ioc;
         TestStream socket{ioc};
         // socket.append(test_data());  // no data to read -> EOF

         AsioStream ssl{socket};
         uint8_t    data[TEST_DATA_SIZE];
         error_code ec;

         Test::Result result("async read_some error");

         auto read_handler = [&](const error_code &ec, std::size_t bytes_transferred)
            {
            result.test_eq("didn't transfer anything", bytes_transferred, 0);
            result.confirm("propagates error code", (bool)ec);
            };

         asio::mutable_buffer buf = asio::buffer(data, TEST_DATA_SIZE);
         asio::async_read(ssl, buf, read_handler);

         socket.close_remote();
         ioc.run();
         results.push_back(result);
         }

      void test_async_write_some_success(std::vector<Test::Result>& results)
         {
         asio::io_context    ioc;
         TestStream socket{ioc}, remote{ioc};
         socket.connect(remote);

         AsioStream ssl{socket};
         error_code ec;

         Test::Result result("async write_some success");

         auto write_handler = [&](const error_code &ec, std::size_t bytes_transferred)
            {
            result.confirm("writes the correct data", remote.str() == test_data());
            result.test_eq("writes the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
            result.confirm("does not report an error", !ec);
            };

         asio::async_write(ssl, asio::buffer(TEST_DATA, TEST_DATA_SIZE), write_handler);

         ioc.run();
         results.push_back(result);
         }

      void test_async_write_some_error(std::vector<Test::Result>& results)
         {
         asio::io_context    ioc;
         TestStream socket{ioc}, remote{ioc};
         //  socket.connect(remote);  // will cause connection_reset error

         AsioStream ssl{socket};
         error_code ec;

         Test::Result result("async write_some error");

         auto write_handler = [&](const error_code &ec, std::size_t bytes_transferred)
            {
            result.test_eq("didn't transfer anything", bytes_transferred, 0);
            result.confirm("propagates error code", (bool)ec);
            };

         asio::async_write(ssl, asio::buffer(TEST_DATA, TEST_DATA_SIZE), write_handler);

         ioc.run();
         results.push_back(result);
         }

      void test_sync_read_some_buffer_sequence(std::vector<Test::Result>& results)
         {
         asio::io_context    ioc;
         TestStream socket{ioc};
         socket.append(test_data());

         AsioStream ssl{socket};
         error_code ec;

         std::vector<asio::mutable_buffer> data;
         uint8_t buf1[TEST_DATA_SIZE/2];
         uint8_t buf2[TEST_DATA_SIZE/2];
         data.emplace_back(asio::buffer(buf1, TEST_DATA_SIZE/2));
         data.emplace_back(asio::buffer(buf2, TEST_DATA_SIZE/2));

         auto bytes_transferred = asio::read(ssl, data, ec);

         Test::Result result("sync read_some buffer sequence");

         result.confirm("reads the correct data",
                        contains(buf1, TEST_DATA, TEST_DATA_SIZE/2) &&
                        contains(buf2, TEST_DATA+TEST_DATA_SIZE/2, TEST_DATA_SIZE/2));
         result.test_eq("reads the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
         result.confirm("does not report an error", !ec);

         results.push_back(result);
         }

      void test_sync_write_some_buffer_sequence(std::vector<Test::Result>& results)
         {
         asio::io_context    ioc;
         TestStream socket{ioc}, remote{ioc};
         socket.connect(remote);

         AsioStream ssl{socket};
         error_code ec;

         // this should be Botan::TLS::MAX_PLAINTEXT_SIZE + 1024 + 1
         std::array<uint8_t, 17 * 1024 + 1> random_data;
         random_data.fill('4');  // chosen by fair dice roll
         random_data.back() = '5';

         std::vector<asio::const_buffer> data;
         data.emplace_back(asio::buffer(random_data.data(), 1));
         for(std::size_t i = 1; i < random_data.size(); i += 1024)
            {
            data.emplace_back(asio::buffer(random_data.data() + i, 1024));
            }

         auto bytes_transferred = asio::write(ssl, data, ec);

         Test::Result result("sync write_some buffer sequence");

         result.confirm("[precondition] MAX_PLAINTEXT_SIZE is still smaller than random_data.size()",
                        Botan::TLS::MAX_PLAINTEXT_SIZE < random_data.size());

         result.confirm("writes the correct data",
                        contains(remote.buffer().data().data(), random_data.data(), random_data.size()));
         result.test_eq("writes the correct amount of data", bytes_transferred, random_data.size());
         result.test_eq("correct number of writes", socket.nwrite(), 2);
         result.confirm("does not report an error", !ec);

         results.push_back(result);
         }

      void test_async_read_some_buffer_sequence(std::vector<Test::Result>& results)
         {
         asio::io_context    ioc;
         TestStream socket{ioc};
         socket.append(test_data());

         AsioStream ssl{socket};
         error_code ec;

         std::vector<asio::mutable_buffer> data;
         uint8_t buf1[TEST_DATA_SIZE/2];
         uint8_t buf2[TEST_DATA_SIZE/2];
         data.emplace_back(asio::buffer(buf1, TEST_DATA_SIZE/2));
         data.emplace_back(asio::buffer(buf2, TEST_DATA_SIZE/2));

         Test::Result result("async read_some buffer sequence");

         auto read_handler = [&](const error_code &ec, std::size_t bytes_transferred)
            {
            result.confirm("reads the correct data",
                           contains(buf1, TEST_DATA, TEST_DATA_SIZE/2) &&
                           contains(buf2, TEST_DATA+TEST_DATA_SIZE/2, TEST_DATA_SIZE/2));
            result.test_eq("reads the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
            result.confirm("does not report an error", !ec);
            };

         asio::async_read(ssl, data, read_handler);

         socket.close_remote();
         ioc.run();
         results.push_back(result);
         }

      void test_async_write_some_buffer_sequence(std::vector<Test::Result>& results)
         {
         asio::io_context    ioc;
         TestStream socket{ioc}, remote{ioc};
         socket.connect(remote);

         AsioStream ssl{socket};
         error_code ec;

         // this should be Botan::TLS::MAX_PLAINTEXT_SIZE + 1024 + 1
         std::array<uint8_t, 17 * 1024 + 1> random_data;
         random_data.fill('4');  // chosen by fair dice roll
         random_data.back() = '5';

         std::vector<asio::const_buffer> src;
         src.emplace_back(asio::buffer(random_data.data(), 1));
         for(std::size_t i = 1; i < random_data.size(); i += 1024)
            {
            src.emplace_back(asio::buffer(random_data.data() + i, 1024));
            }

         Test::Result result("async write_some buffer sequence");

         result.confirm("[precondition] MAX_PLAINTEXT_SIZE is still smaller than random_data.size()",
                        Botan::TLS::MAX_PLAINTEXT_SIZE < random_data.size());

         auto write_handler = [&](const error_code &ec, std::size_t bytes_transferred)
            {
            result.confirm("writes the correct data",
                           contains(remote.buffer().data().data(), random_data.data(), random_data.size()));
            result.test_eq("writes the correct amount of data", bytes_transferred, random_data.size());
            result.test_eq("correct number of writes", socket.nwrite(), 2);
            result.confirm("does not report an error", !ec);
            };

         asio::async_write(ssl, src, write_handler);

         ioc.run();
         results.push_back(result);
         }

   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;

         test_async_handshake(results);
         test_async_handshake_error(results);

         test_async_read_some_success(results);
         test_async_read_some_error(results);

         test_async_write_some_success(results);
         test_async_write_some_error(results);

         test_sync_read_some_buffer_sequence(results);
         test_sync_write_some_buffer_sequence(results);

         test_async_read_some_buffer_sequence(results);
         test_async_write_some_buffer_sequence(results);

         return results;
         }
   };

BOTAN_REGISTER_TEST("asio_stream", Asio_Stream_Tests);

BOTAN_REGISTER_TEST("asio_stream_beast", Asio_Stream_Tests_Beast );

}  // namespace Botan_Tests

#endif
