#include "tests.h"

#include <iostream>

#if defined(BOTAN_HAS_TLS) && defined(BOTAN_HAS_BOOST_ASIO)

#include <botan/asio_stream.h>
#include <botan/tls_callbacks.h>

namespace Botan_Tests {

/**
  Tests for Botan::Stream.

  Tested Entities:
  * Botan::Stream, including StreamCore and Async_*_Op

  Mocked Entities:
  * the stream's channel, i.e. TLS_Client or TLS_Server, pretends to perform TLS operations (noop) and provides the test
    data to the stream
  * the underlying network socket, claiming it read / wrote a number of bytes
*/

using namespace std::placeholders;
namespace asio   = boost::asio;
using error_code = boost::system::error_code;

constexpr std::size_t TEST_DATA_SIZE = 128;
constexpr uint8_t     TEST_DATA[]
   {
   '4', 'f', '8', 'y', 'z', 's', '9', 'g', '2', '6', 'c', 'v', 't', 'y', 'q', 'm', 'o', 'v', 'x', 'a', '3', '1',
   't', 'm', 'y', '7', 'n', '1', '4', 't', 'k', 'q', 'r', 'z', 'w', '0', '4', 't', 'c', 't', 'm', 'u', '4', 'h',
   'l', 'z', 'x', 'f', 'e', '9', 'b', '3', 'o', 'j', 'a', '4', 'o', 'd', '9', 'j', '6', 'u', 'f', '8', '2', 'd',
   'r', 'z', 'n', 'l', 'p', '7', 'p', 'a', '1', 'o', 'f', 'z', 'q', 'd', 'x', 'f', 'k', '8', 'r', 'l', 'a', 'i',
   '0', 'b', 'x', 'h', '2', 'w', '5', 'w', 'h', 'k', 'h', '2', 'r', '8', 'a', 'f', 'd', 'j', 'c', '0', 'j', 'o',
   'k', 'w', 'v', '4', '9', 'm', 's', 'a', 'o', 'f', '0', 'n', 'u', 'l', 'v', 'z', 'g', 'm'
   };
static_assert(sizeof(TEST_DATA) == TEST_DATA_SIZE, "size of TEST_DATA must match TEST_DATA_SIZE");

// use memcmp to check if the data in a is a prefix of the data in b
bool contains(const void* a, const void* b) { return memcmp(a, b, sizeof(a)) == 0; }

class MockChannel
   {
   public:
      MockChannel(Botan::StreamCore& core)
         : callbacks_(core)
         , bytes_till_complete_record_(TEST_DATA_SIZE)
         , active_(false)
         {
         }

   public:
      std::size_t received_data(const uint8_t[], std::size_t buf_size)
         {
         if(bytes_till_complete_record_ < buf_size)
            {
            callbacks_.tls_record_received(0, TEST_DATA, TEST_DATA_SIZE);
            active_ = true;  // claim to be active once a full record has been received (for handshake test)
            return 0;
            }
         bytes_till_complete_record_ -= buf_size;
         return bytes_till_complete_record_;
         }

      void send(const uint8_t buf[], std::size_t buf_size) { callbacks_.tls_emit_data(buf, buf_size); }

      bool is_active() { return active_; }

   protected:
      Botan::StreamCore& callbacks_;
      std::size_t        bytes_till_complete_record_;  // number of bytes still to read before tls record is completed
      bool               active_;
   };

/**
 * Mocked network socket. As all data from the socket is first processed in the (also mocked) channel and never directly
 * in the tested Stream, this socket will not perform any actual reading or writing to buffers. It will only claim to
 * have done so, while the channel is responsible for faking the data for the testee.
 */
struct MockSocket
   {
   MockSocket(std::size_t buf_size = 64)
      : buf_size_(buf_size)
      {
      }

   template <typename MutableBufferSequence>
   std::size_t read_some(const MutableBufferSequence& buffers, error_code& ec)
      {
      ec = ec_;
      if(ec)
         {
         return 0;
         }
      return std::min(asio::buffer_size(buffers), buf_size_);
      }

   template <typename ConstBufferSequence>
   std::size_t write_some(const ConstBufferSequence& buffers, error_code& ec)
      {
      ec = ec_;
      if(ec)
         {
         return 0;
         }
      return asio::buffer_copy(asio::buffer(write_buf_, buf_size_), buffers);
      }

   template <typename MutableBufferSequence, typename ReadHandler>
   BOOST_ASIO_INITFN_RESULT_TYPE(ReadHandler, void(error_code, std::size_t))
   async_read_some(const MutableBufferSequence& buffers, ReadHandler&& handler)
      {
      handler(ec_, read_some(buffers, ec_));
      }

   template <typename ConstBufferSequence, typename WriteHandler>
   BOOST_ASIO_INITFN_RESULT_TYPE(WriteHandler, void(error_code, std::size_t))
   async_write_some(const ConstBufferSequence& buffers, WriteHandler&& handler)
      {
      handler(ec_, write_some(buffers, ec_));
      }

   using lowest_layer_type = MockSocket;
   using executor_type     = MockSocket;

   error_code  ec_;
   std::size_t buf_size_;
   uint8_t     write_buf_[TEST_DATA_SIZE];
   };
}  // namespace Botan_Tests

namespace Botan {

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
         : channel_(core_)
         {
         }

      StreamBase(const StreamBase&) = delete;
      StreamBase& operator=(const StreamBase&) = delete;

   protected:
      StreamCore               core_;
      Botan::AutoSeeded_RNG    rng_;
      Botan_Tests::MockChannel channel_;
   };

}  // namespace Botan

namespace Botan_Tests {

class ASIO_Stream_Tests final : public Test
   {
      using TestStream = Botan::Stream<MockSocket&, MockChannel>;

      void test_sync_handshake(std::vector<Test::Result>& results)
         {
         MockSocket socket;
         TestStream ssl{socket};

         ssl.handshake();

         Test::Result result("sync TLS handshake");
         result.test_eq("feeds data into channel until active", ssl.channel().is_active(), true);
         results.push_back(result);
         }

      void test_sync_handshake_error(std::vector<Test::Result>& results)
         {
         MockSocket socket;
         TestStream ssl{socket};

         const auto expected_ec = asio::error::host_unreachable;
         socket.ec_             = expected_ec;

         error_code ec;
         ssl.handshake(ec);

         Test::Result result("sync TLS handshake error");
         result.test_eq("does not activate channel", ssl.channel().is_active(), false);
         result.confirm("propagates error code", ec == expected_ec);
         results.push_back(result);
         }

      void test_async_handshake(std::vector<Test::Result>& results)
         {
         MockSocket socket;
         TestStream ssl{socket};

         Test::Result result("async TLS handshake");

         auto handler = [&](const boost::system::error_code&)
            {
            result.test_eq("feeds data into channel until active", ssl.channel().is_active(), true);
            };

         ssl.async_handshake(handler);
         results.push_back(result);
         }

      void test_async_handshake_error(std::vector<Test::Result>& results)
         {
         MockSocket socket;
         TestStream ssl{socket};

         const auto expected_ec = asio::error::host_unreachable;
         socket.ec_             = expected_ec;

         Test::Result result("async TLS handshake error");

         auto handler = [&](const boost::system::error_code &ec)
            {
            result.test_eq("does not activate channel", ssl.channel().is_active(), false);
            result.confirm("propagates error code", ec == expected_ec);
            };

         ssl.async_handshake(handler);
         results.push_back(result);
         }

      void test_sync_read_some_success(std::vector<Test::Result>& results)
         {
         MockSocket socket;
         TestStream ssl{socket};
         char       buf[128];
         error_code ec;

         auto bytes_transferred = asio::read(ssl, asio::buffer(buf, sizeof(buf)), ec);

         Test::Result result("sync read_some success");
         result.confirm("reads the correct data", contains(buf, TEST_DATA));
         result.test_eq("reads the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
         result.confirm("does not report an error", !ec);

         results.push_back(result);
         }

      void test_sync_read_some_large_socket_buffer(std::vector<Test::Result>& results)
         {
         MockSocket socket(512);
         TestStream ssl{socket};
         char       buf[128];
         error_code ec;

         auto bytes_transferred = asio::read(ssl, asio::buffer(buf, sizeof(buf)), ec);

         Test::Result result("sync read_some with large socket buffer");
         result.confirm("reads the correct data", contains(buf, TEST_DATA));
         result.test_eq("reads the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
         result.confirm("does not report an error", !ec);

         results.push_back(result);
         }

      void test_sync_read_some_error(std::vector<Test::Result>& results)
         {
         MockSocket socket;
         TestStream ssl{socket};
         const auto expected_ec = asio::error::eof;
         socket.ec_             = expected_ec;

         char       buf[128];
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
         TestStream ssl{socket};
         char       buf[128];
         error_code ec;

         Test::Result result("async read_some success");

         auto read_handler = [&](const boost::system::error_code &ec, std::size_t bytes_transferred)
            {
            result.confirm("reads the correct data", contains(buf, TEST_DATA));
            result.test_eq("reads the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
            result.confirm("does not report an error", !ec);
            };

         asio::async_read(ssl, asio::buffer(buf, sizeof(buf)), read_handler);

         results.push_back(result);
         }

      void test_async_read_some_large_socket_buffer(std::vector<Test::Result>& results)
         {
         MockSocket socket(512);
         TestStream ssl{socket};
         char       buf[128];
         error_code ec;

         Test::Result result("async read_some with large socket buffer");

         auto read_handler = [&](const boost::system::error_code &ec, std::size_t bytes_transferred)
            {
            result.confirm("reads the correct data", contains(buf, TEST_DATA));
            result.test_eq("reads the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
            result.confirm("does not report an error", !ec);
            };

         asio::async_read(ssl, asio::buffer(buf, sizeof(buf)), read_handler);

         results.push_back(result);
         }

      void test_async_read_some_error(std::vector<Test::Result>& results)
         {
         MockSocket socket;
         TestStream ssl{socket};
         char       buf[128];
         error_code ec;

         const auto expected_ec = asio::error::eof;
         socket.ec_             = expected_ec;

         Test::Result result("async read_some error");

         auto read_handler = [&](const boost::system::error_code &ec, std::size_t bytes_transferred)
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
         TestStream ssl{socket};
         error_code ec;

         auto bytes_transferred = asio::write(ssl, asio::buffer(TEST_DATA, TEST_DATA_SIZE), ec);

         Test::Result result("sync write_some success");
         // socket.write_buf_ should contain the end of TEST_DATA, the start has already been overwritten
         const auto end_of_test_data = TEST_DATA + TEST_DATA_SIZE - socket.buf_size_;
         result.confirm("writes the correct data", contains(socket.write_buf_, end_of_test_data));
         result.test_eq("writes the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
         result.confirm("does not report an error", !ec);

         results.push_back(result);
         }

      void test_sync_write_some_large_socket_buffer(std::vector<Test::Result>& results)
         {
         MockSocket socket(512);
         TestStream ssl{socket};
         error_code ec;

         auto bytes_transferred = asio::write(ssl, asio::buffer(TEST_DATA, TEST_DATA_SIZE), ec);

         Test::Result result("sync write_some with large socket buffer");
         // this test assumes that socket.buf_size_ is larger than TEST_DATA_SIZE
         result.confirm("writes the correct data", contains(TEST_DATA, socket.write_buf_));
         result.test_eq("writes the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
         result.confirm("does not report an error", !ec);

         results.push_back(result);
         }

      void test_sync_write_some_error(std::vector<Test::Result>& results)
         {
         MockSocket socket;
         TestStream ssl{socket};
         error_code ec;

         const auto expected_ec = asio::error::eof;
         socket.ec_             = expected_ec;

         auto bytes_transferred = asio::write(ssl, asio::buffer(TEST_DATA, TEST_DATA_SIZE), ec);

         Test::Result result("sync write_some error");
         result.test_eq("didn't transfer anything", bytes_transferred, 0);
         result.confirm("propagates error code", ec == expected_ec);

         results.push_back(result);
         }

      void test_async_write_some_success(std::vector<Test::Result>& results)
         {
         MockSocket socket;
         TestStream ssl{socket};
         error_code ec;

         Test::Result result("async write_some success");

         auto write_handler = [&](const boost::system::error_code &ec, std::size_t bytes_transferred)
            {
            // socket.write_buf_ should contain the end of TEST_DATA, the start has already been overwritten
            const auto end_of_test_data = TEST_DATA + TEST_DATA_SIZE - socket.buf_size_;
            result.confirm("writes the correct data", contains(socket.write_buf_, end_of_test_data));
            result.test_eq("writes the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
            result.confirm("does not report an error", !ec);
            };

         asio::async_write(ssl, asio::buffer(TEST_DATA, TEST_DATA_SIZE), write_handler);

         results.push_back(result);
         }

      void test_async_write_some_large_socket_buffer(std::vector<Test::Result>& results)
         {
         MockSocket socket(512);
         TestStream ssl{socket};
         error_code ec;

         Test::Result result("async write_some with large socket buffer");

         auto write_handler = [&](const boost::system::error_code &ec, std::size_t bytes_transferred)
            {
            // this test assumes that socket.buf_size_ is larger than TEST_DATA_SIZE
            result.confirm("writes the correct data", contains(TEST_DATA, socket.write_buf_));
            result.test_eq("writes the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
            result.confirm("does not report an error", !ec);
            };

         asio::async_write(ssl, asio::buffer(TEST_DATA, TEST_DATA_SIZE), write_handler);

         results.push_back(result);
         }

      void test_async_write_some_error(std::vector<Test::Result>& results)
         {
         MockSocket socket;
         TestStream ssl{socket};
         error_code ec;

         const auto expected_ec = asio::error::eof;
         socket.ec_             = expected_ec;

         Test::Result result("async write_some error");

         auto write_handler = [&](const boost::system::error_code &ec, std::size_t bytes_transferred)
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
         test_sync_read_some_large_socket_buffer(results);
         test_sync_read_some_error(results);

         test_async_read_some_success(results);
         test_async_read_some_large_socket_buffer(results);
         test_async_read_some_error(results);

         test_sync_write_some_success(results);
         test_sync_write_some_large_socket_buffer(results);
         test_sync_write_some_error(results);

         test_async_write_some_success(results);
         test_async_write_some_large_socket_buffer(results);
         test_async_write_some_error(results);

         return results;
         }
   };

BOTAN_REGISTER_TEST("asio_stream", ASIO_Stream_Tests);

#endif

}  // namespace Botan_Tests
