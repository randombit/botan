/*
* TLS ASIO Stream Unit Tests
* (C) 2018-2020 Jack Lloyd
*     2018-2020 Hannes Rantzsch, Tim Oesterreich, Rene Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_TLS) && defined(BOTAN_HAS_TLS_ASIO_STREAM)

   #include <botan/asio_compat.h>
   #if defined(BOTAN_FOUND_COMPATIBLE_BOOST_ASIO_VERSION)

      #include <botan/asio_stream.h>
      #include <botan/tls_callbacks.h>
      #include <botan/tls_session_manager_noop.h>

      #include <boost/beast/_experimental/test/stream.hpp>
      #include <boost/bind.hpp>
      #include <utility>

namespace Botan_Tests {

namespace net = boost::asio;
using error_code = boost::system::error_code;

constexpr uint8_t TEST_DATA[] =
   "The story so far: In the beginning the Universe was created. "
   "This has made a lot of people very angry and been widely regarded as a bad move.";
constexpr std::size_t TEST_DATA_SIZE = 142;
static_assert(sizeof(TEST_DATA) == TEST_DATA_SIZE, "size of TEST_DATA must match TEST_DATA_SIZE");

/**
 * Mocked Botan::TLS::Channel. Pretends to perform TLS operations and triggers appropriate callbacks in StreamCore.
 */
class MockChannel {
   public:
      MockChannel(std::shared_ptr<Botan::TLS::Callbacks> core) :
            m_callbacks(std::move(core)),
            m_bytes_till_complete_record(TEST_DATA_SIZE),
            m_active(false),
            m_close_notify_received(false) {}

   public:
      std::size_t received_data(std::span<const uint8_t> data) {
         if(m_bytes_till_complete_record <= data.size()) {
            m_callbacks->tls_record_received(0, TEST_DATA);
            m_active = true;  // claim to be active once a full record has been received (for handshake test)
            return 0;
         }
         m_bytes_till_complete_record -= data.size();
         return m_bytes_till_complete_record;
      }

      void send(std::span<const uint8_t> buf) { m_callbacks->tls_emit_data(buf); }

      bool is_active() const { return m_active; }

      bool is_handshake_complete() const { return m_active; }

      bool is_closed_for_reading() const { return m_close_notify_received; }

      bool is_closed_for_writing() const { return m_close_notify_received; }

      void received_close_notify() {
         m_close_notify_received = true;
         m_callbacks->tls_alert(Botan::TLS::AlertType::CloseNotify);
         const auto close_notify_record = Botan::hex_decode("15030300020100");
         send(close_notify_record);
      }

   private:
      std::shared_ptr<Botan::TLS::Callbacks> m_callbacks;
      std::size_t m_bytes_till_complete_record;  // number of bytes still to read before tls record is completed
      bool m_active;
      bool m_close_notify_received;
};

class ThrowingMockChannel : public MockChannel {
   public:
      static boost::system::error_code expected_ec() { return Botan::TLS::Alert::UnexpectedMessage; }

      ThrowingMockChannel(std::shared_ptr<Botan::TLS::Callbacks> core) : MockChannel(std::move(core)) {}

      std::size_t received_data(std::span<const uint8_t>) { throw Botan::TLS::Unexpected_Message("test_error"); }

      void send(std::span<const uint8_t>) { throw Botan::TLS::Unexpected_Message("test_error"); }
};

class CancellingMockChannel : public MockChannel {
   public:
      CancellingMockChannel(std::shared_ptr<Botan::TLS::Callbacks> core) : MockChannel(std::move(core)) {}

      std::size_t received_data(std::span<const uint8_t>) {
         received_close_notify();
         return 0;
      }
};

// Unfortunately, boost::beast::test::stream keeps lowest_layer_type private and
// only friends boost::asio::ssl::stream. We need to make our own.
class TestStream : public boost::beast::test::stream {
   public:
      // NOLINTNEXTLINE(modernize-type-traits)
      using boost::beast::test::stream::stream;
      using lowest_layer_type = boost::beast::test::stream;
};

using FailCount = boost::beast::test::fail_count;

class AsioStream : public Botan::TLS::Stream<TestStream, MockChannel> {
   public:
      template <typename... Args>
      AsioStream(std::shared_ptr<Botan::TLS::Context> context, Args&&... args) :
            Stream(context, std::forward<Args>(args)...) {
         m_native_handle = std::make_unique<MockChannel>(m_core);
      }
};

class ThrowingAsioStream : public Botan::TLS::Stream<TestStream, ThrowingMockChannel> {
   public:
      template <typename... Args>
      ThrowingAsioStream(std::shared_ptr<Botan::TLS::Context> context, Args&&... args) :
            Stream(context, std::forward<Args>(args)...) {
         m_native_handle = std::make_unique<ThrowingMockChannel>(m_core);
      }
};

class CancellingAsioStream : public Botan::TLS::Stream<TestStream, CancellingMockChannel> {
   public:
      template <typename... Args>
      CancellingAsioStream(std::shared_ptr<Botan::TLS::Context> context, Args&&... args) :
            Stream(context, std::forward<Args>(args)...) {
         m_native_handle = std::make_unique<CancellingMockChannel>(m_core);
      }
};

/**
 * Synchronous tests for Botan::Stream.
 *
 * This test validates the asynchronous behavior Botan::Stream, including its utility classes StreamCore and Async_*_Op.
 * The stream's channel, i.e. TLS_Client or TLS_Server, is mocked and pretends to perform TLS operations (noop) and
 * provides the test data to the stream.
 * The underlying network socket, claiming it read / wrote a number of bytes.
 */
class Asio_Stream_Tests final : public Test {
      std::shared_ptr<Botan::TLS::Context> get_context() {
         return std::make_shared<Botan::TLS::Context>(std::make_shared<Botan::Credentials_Manager>(),
                                                      std::make_shared<Botan::Null_RNG>(),
                                                      std::make_shared<Botan::TLS::Session_Manager_Noop>(),
                                                      std::make_shared<Botan::TLS::Default_Policy>());
      }

      // use memcmp to check if the data in a is a prefix of the data in b
      bool contains(const void* a, const void* b, const std::size_t size) { return memcmp(a, b, size) == 0; }

      boost::string_view test_data() const {
         return boost::string_view(reinterpret_cast<const char*>(TEST_DATA), TEST_DATA_SIZE);
      }

      void test_sync_handshake(std::vector<Test::Result>& results) {
         net::io_context ioc;
         auto ctx = get_context();
         AsioStream ssl(ctx, ioc, test_data());

         ssl.handshake(Botan::TLS::Connection_Side::Client);

         Test::Result result("sync TLS handshake");
         result.test_eq("feeds data into channel until active", ssl.native_handle()->is_active(), true);
         results.push_back(result);
      }

      void test_sync_handshake_error(std::vector<Test::Result>& results) {
         net::io_context ioc;
         // fail right away
         FailCount fc{0, net::error::no_recovery};
         TestStream remote{ioc};

         auto ctx = get_context();
         AsioStream ssl(ctx, ioc, fc);
         ssl.next_layer().connect(remote);

         // mimic handshake initialization
         ssl.native_handle()->send(TEST_DATA);

         error_code ec;
         ssl.handshake(Botan::TLS::Connection_Side::Client, ec);

         Test::Result result("sync TLS handshake error");
         result.test_eq("does not activate channel", ssl.native_handle()->is_active(), false);
         result.confirm("propagates error code", ec == net::error::no_recovery);
         results.push_back(result);
      }

      void test_sync_handshake_cancellation(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         auto ctx = get_context();
         CancellingAsioStream ssl(ctx, ioc, test_data());
         ssl.next_layer().connect(remote);

         // mimic handshake initialization
         ssl.native_handle()->send(TEST_DATA);

         error_code ec;
         ssl.handshake(Botan::TLS::Connection_Side::Client, ec);

         Test::Result result("sync TLS handshake cancellation");
         result.test_eq("does not activate channel", ssl.native_handle()->is_active(), false);
         result.test_eq("does not finish handshake", ssl.native_handle()->is_handshake_complete(), false);
         result.confirm("cancelled handshake means EOF", ec == net::error::eof);
         results.push_back(result);
      }

      void test_sync_handshake_throw(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         auto ctx = get_context();
         ThrowingAsioStream ssl(ctx, ioc, test_data());
         ssl.next_layer().connect(remote);

         error_code ec;
         ssl.handshake(Botan::TLS::Connection_Side::Client, ec);

         Test::Result result("sync TLS handshake error");
         result.test_eq("does not activate channel", ssl.native_handle()->is_active(), false);
         result.confirm("propagates error code", ec == ThrowingMockChannel::expected_ec());
         results.push_back(result);
      }

      void test_async_handshake(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         auto ctx = get_context();
         AsioStream ssl(ctx, ioc, test_data());
         ssl.next_layer().connect(remote);

         // mimic handshake initialization
         ssl.native_handle()->send(TEST_DATA);

         Test::Result result("async TLS handshake");

         auto handler = [&](const error_code&) {
            result.confirm("reads from socket", ssl.next_layer().nread() > 0);
            result.confirm("writes from socket", ssl.next_layer().nwrite() > 0);
            result.test_eq("feeds data into channel until active", ssl.native_handle()->is_active(), true);
         };

         ssl.async_handshake(Botan::TLS::Connection_Side::Client, handler);

         ssl.next_layer().close_remote();
         ioc.run();
         results.push_back(result);
      }

      void test_async_handshake_error(std::vector<Test::Result>& results) {
         net::io_context ioc;
         // fail right away
         FailCount fc{0, net::error::no_recovery};
         TestStream remote{ioc};

         auto ctx = get_context();
         AsioStream ssl(ctx, ioc, fc);
         ssl.next_layer().connect(remote);

         // mimic handshake initialization
         ssl.native_handle()->send(TEST_DATA);

         Test::Result result("async TLS handshake error");

         auto handler = [&](const error_code& ec) {
            result.test_eq("does not activate channel", ssl.native_handle()->is_active(), false);
            result.confirm("propagates error code", ec == net::error::no_recovery);
         };

         ssl.async_handshake(Botan::TLS::Connection_Side::Client, handler);

         ioc.run();
         results.push_back(result);
      }

      void test_async_handshake_cancellation(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         auto ctx = get_context();
         CancellingAsioStream ssl(ctx, ioc, test_data());
         ssl.next_layer().connect(remote);

         // mimic handshake initialization
         ssl.native_handle()->send(TEST_DATA);

         Test::Result result("async TLS handshake cancellation");

         auto handler = [&](const error_code& ec) {
            result.test_eq("does not activate channel", ssl.native_handle()->is_active(), false);
            result.test_eq("does not finish handshake", ssl.native_handle()->is_handshake_complete(), false);
            result.confirm("cancelled handshake means EOF", ec == net::error::eof);
         };

         ssl.async_handshake(Botan::TLS::Connection_Side::Client, handler);

         ioc.run();
         results.push_back(result);
      }

      void test_async_handshake_throw(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         auto ctx = get_context();
         ThrowingAsioStream ssl(ctx, ioc, test_data());
         ssl.next_layer().connect(remote);

         Test::Result result("async TLS handshake throw");

         auto handler = [&](const error_code& ec) {
            result.test_eq("does not activate channel", ssl.native_handle()->is_active(), false);
            result.confirm("propagates error code", ec == ThrowingMockChannel::expected_ec());
         };

         ssl.async_handshake(Botan::TLS::Connection_Side::Client, handler);

         ioc.run();
         results.push_back(result);
      }

      void test_sync_read_some_success(std::vector<Test::Result>& results) {
         net::io_context ioc;

         auto ctx = get_context();
         AsioStream ssl(ctx, ioc, test_data());

         const std::size_t buf_size = 128;
         uint8_t buf[buf_size];
         error_code ec;

         auto bytes_transferred = net::read(ssl, net::mutable_buffer(buf, sizeof(buf)), ec);

         Test::Result result("sync read_some success");
         result.confirm("reads the correct data", contains(buf, TEST_DATA, buf_size));
         result.test_eq("reads the correct amount of data", bytes_transferred, buf_size);
         result.confirm("does not report an error", !ec);

         results.push_back(result);
      }

      void test_sync_read_some_buffer_sequence(std::vector<Test::Result>& results) {
         net::io_context ioc;

         auto ctx = get_context();
         AsioStream ssl(ctx, ioc, test_data());
         error_code ec;

         std::vector<net::mutable_buffer> data;
         uint8_t buf1[TEST_DATA_SIZE / 2];
         uint8_t buf2[TEST_DATA_SIZE / 2];
         data.emplace_back(net::mutable_buffer(buf1, TEST_DATA_SIZE / 2));
         data.emplace_back(net::mutable_buffer(buf2, TEST_DATA_SIZE / 2));

         auto bytes_transferred = net::read(ssl, data, ec);

         Test::Result result("sync read_some buffer sequence");

         result.confirm("reads the correct data",
                        contains(buf1, TEST_DATA, TEST_DATA_SIZE / 2) &&
                           contains(buf2, TEST_DATA + TEST_DATA_SIZE / 2, TEST_DATA_SIZE / 2));
         result.test_eq("reads the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
         result.confirm("does not report an error", !ec);

         results.push_back(result);
      }

      void test_sync_read_some_error(std::vector<Test::Result>& results) {
         net::io_context ioc;
         // fail right away
         FailCount fc{0, net::error::no_recovery};
         TestStream remote{ioc};

         auto ctx = get_context();
         AsioStream ssl(ctx, ioc, fc);
         ssl.next_layer().connect(remote);

         uint8_t buf[128];
         error_code ec;

         auto bytes_transferred = net::read(ssl, net::mutable_buffer(buf, sizeof(buf)), ec);

         Test::Result result("sync read_some error");
         result.test_eq("didn't transfer anything", bytes_transferred, 0);
         result.confirm("propagates error code", ec == net::error::no_recovery);

         results.push_back(result);
      }

      void test_sync_read_some_throw(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         auto ctx = get_context();
         ThrowingAsioStream ssl(ctx, ioc, test_data());
         ssl.next_layer().connect(remote);

         uint8_t buf[128];
         error_code ec;

         auto bytes_transferred = net::read(ssl, net::mutable_buffer(buf, sizeof(buf)), ec);

         Test::Result result("sync read_some throw");
         result.test_eq("didn't transfer anything", bytes_transferred, 0);
         result.confirm("propagates error code", ec == ThrowingMockChannel::expected_ec());

         results.push_back(result);
      }

      void test_sync_read_zero_buffer(std::vector<Test::Result>& results) {
         net::io_context ioc;

         auto ctx = get_context();
         AsioStream ssl(ctx, ioc);

         const std::size_t buf_size = 128;
         uint8_t buf[buf_size];
         error_code ec;

         auto bytes_transferred = net::read(ssl, net::mutable_buffer(buf, std::size_t(0)), ec);

         Test::Result result("sync read_some into zero-size buffer");
         result.test_eq("reads the correct amount of data", bytes_transferred, 0);
         // This relies on an implementation detail of TestStream: A "real" asio::tcp::stream
         // would block here. TestStream sets error_code::eof.
         result.confirm("does not report an error", !ec);

         results.push_back(result);
      }

      void test_async_read_some_success(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         auto ctx = get_context();
         AsioStream ssl(ctx, ioc, test_data());
         uint8_t data[TEST_DATA_SIZE];

         Test::Result result("async read_some success");

         auto read_handler = [&](const error_code& ec, std::size_t bytes_transferred) {
            result.confirm("reads the correct data", contains(data, TEST_DATA, TEST_DATA_SIZE));
            result.test_eq("reads the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
            result.confirm("does not report an error", !ec);
         };

         net::mutable_buffer buf{data, TEST_DATA_SIZE};
         net::async_read(ssl, buf, read_handler);

         ssl.next_layer().close_remote();
         ioc.run();
         results.push_back(result);
      }

      void test_async_read_some_buffer_sequence(std::vector<Test::Result>& results) {
         net::io_context ioc;
         auto ctx = get_context();
         AsioStream ssl(ctx, ioc, test_data());

         std::vector<net::mutable_buffer> data;
         uint8_t buf1[TEST_DATA_SIZE / 2];
         uint8_t buf2[TEST_DATA_SIZE / 2];
         data.emplace_back(net::mutable_buffer(buf1, TEST_DATA_SIZE / 2));
         data.emplace_back(net::mutable_buffer(buf2, TEST_DATA_SIZE / 2));

         Test::Result result("async read_some buffer sequence");

         auto read_handler = [&](const error_code& ec, std::size_t bytes_transferred) {
            result.confirm("reads the correct data",
                           contains(buf1, TEST_DATA, TEST_DATA_SIZE / 2) &&
                              contains(buf2, TEST_DATA + TEST_DATA_SIZE / 2, TEST_DATA_SIZE / 2));
            result.test_eq("reads the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
            result.confirm("does not report an error", !ec);
         };

         net::async_read(ssl, data, read_handler);

         ssl.next_layer().close_remote();
         ioc.run();
         results.push_back(result);
      }

      void test_async_read_some_error(std::vector<Test::Result>& results) {
         net::io_context ioc;
         // fail right away
         FailCount fc{0, net::error::no_recovery};
         auto ctx = get_context();
         AsioStream ssl(ctx, ioc, fc);
         uint8_t data[TEST_DATA_SIZE];

         Test::Result result("async read_some error");

         auto read_handler = [&](const error_code& ec, std::size_t bytes_transferred) {
            result.test_eq("didn't transfer anything", bytes_transferred, 0);
            result.confirm("propagates error code", ec == net::error::no_recovery);
         };

         net::mutable_buffer buf{data, TEST_DATA_SIZE};
         net::async_read(ssl, buf, read_handler);

         ssl.next_layer().close_remote();
         ioc.run();
         results.push_back(result);
      }

      void test_async_read_some_throw(std::vector<Test::Result>& results) {
         net::io_context ioc;
         auto ctx = get_context();
         ThrowingAsioStream ssl(ctx, ioc, test_data());
         uint8_t data[TEST_DATA_SIZE];

         Test::Result result("async read_some throw");

         auto read_handler = [&](const error_code& ec, std::size_t bytes_transferred) {
            result.test_eq("didn't transfer anything", bytes_transferred, 0);
            result.confirm("propagates error code", ec == ThrowingMockChannel::expected_ec());
         };

         net::mutable_buffer buf{data, TEST_DATA_SIZE};
         net::async_read(ssl, buf, read_handler);

         ssl.next_layer().close_remote();
         ioc.run();
         results.push_back(result);
      }

      void test_async_read_zero_buffer(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         auto ctx = get_context();
         AsioStream ssl(ctx, ioc);
         uint8_t data[TEST_DATA_SIZE];

         Test::Result result("async read_some into zero-size buffer");

         auto read_handler = [&](const error_code& ec, std::size_t bytes_transferred) {
            result.test_eq("reads the correct amount of data", bytes_transferred, 0);
            // This relies on an implementation detail of TestStream: A "real" asio::tcp::stream
            // would block here. TestStream sets error_code::eof.
            result.confirm("does not report an error", !ec);
         };

         net::mutable_buffer buf{data, std::size_t(0)};
         net::async_read(ssl, buf, read_handler);

         ssl.next_layer().close_remote();
         ioc.run();
         results.push_back(result);
      }

      void test_sync_write_some_success(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         auto ctx = get_context();
         AsioStream ssl(ctx, ioc);
         ssl.next_layer().connect(remote);
         error_code ec;

         auto bytes_transferred = net::write(ssl, net::const_buffer(TEST_DATA, TEST_DATA_SIZE), ec);

         Test::Result result("sync write_some success");
         result.confirm("writes the correct data", remote.str() == test_data());
         result.test_eq("writes the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
         result.confirm("does not report an error", !ec);

         results.push_back(result);
      }

      void test_sync_no_handshake(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         auto ctx = get_context();
         Botan::TLS::Stream<TestStream> ssl(ctx, ioc);  // Note that we're not using MockChannel here
         ssl.next_layer().connect(remote);
         error_code ec;

         net::write(ssl, net::const_buffer(TEST_DATA, TEST_DATA_SIZE), ec);

         Test::Result result("sync write_some without handshake fails gracefully");
         result.confirm("reports an error", ec.failed());

         results.push_back(result);
      }

      void test_sync_write_some_buffer_sequence(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         auto ctx = get_context();
         AsioStream ssl(ctx, ioc);
         ssl.next_layer().connect(remote);
         error_code ec;

         // this should be Botan::TLS::MAX_PLAINTEXT_SIZE + 1024 + 1
         std::array<uint8_t, 17 * 1024 + 1> random_data;
         random_data.fill('4');  // chosen by fair dice roll
         random_data.back() = '5';

         std::vector<net::const_buffer> data;
         data.emplace_back(net::const_buffer(random_data.data(), 1));
         for(std::size_t i = 1; i < random_data.size(); i += 1024) {
            data.emplace_back(net::const_buffer(random_data.data() + i, 1024));
         }

         auto bytes_transferred = net::write(ssl, data, ec);

         Test::Result result("sync write_some buffer sequence");

         result.confirm("[precondition] MAX_PLAINTEXT_SIZE is still smaller than random_data.size()",
                        Botan::TLS::MAX_PLAINTEXT_SIZE < random_data.size());

         result.confirm("writes the correct data",
                        contains(remote.buffer().data().data(), random_data.data(), random_data.size()));
         result.test_eq("writes the correct amount of data", bytes_transferred, random_data.size());
         result.test_eq("correct number of writes", ssl.next_layer().nwrite(), 2);
         result.confirm("does not report an error", !ec);

         results.push_back(result);
      }

      void test_sync_write_some_error(std::vector<Test::Result>& results) {
         net::io_context ioc;
         // fail right away
         FailCount fc{0, net::error::no_recovery};
         TestStream remote{ioc};

         auto ctx = get_context();
         AsioStream ssl(ctx, ioc, fc);
         ssl.next_layer().connect(remote);

         error_code ec;

         auto bytes_transferred = net::write(ssl, net::const_buffer(TEST_DATA, TEST_DATA_SIZE), ec);

         Test::Result result("sync write_some error");
         result.test_eq("didn't transfer anything", bytes_transferred, 0);
         result.confirm("propagates error code", ec == net::error::no_recovery);

         results.push_back(result);
      }

      void test_sync_write_some_throw(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         auto ctx = get_context();
         ThrowingAsioStream ssl(ctx, ioc);
         ssl.next_layer().connect(remote);
         error_code ec;

         auto bytes_transferred = net::write(ssl, net::const_buffer(TEST_DATA, TEST_DATA_SIZE), ec);

         Test::Result result("sync write_some throw");
         result.test_eq("didn't transfer anything", bytes_transferred, 0);
         result.confirm("propagates error code", ec == ThrowingMockChannel::expected_ec());

         results.push_back(result);
      }

      void test_async_write_some_success(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         auto ctx = get_context();
         AsioStream ssl(ctx, ioc);
         ssl.next_layer().connect(remote);

         Test::Result result("async write_some success");

         auto write_handler = [&](const error_code& ec, std::size_t bytes_transferred) {
            result.confirm("writes the correct data", remote.str() == test_data());
            result.test_eq("writes the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
            result.confirm("does not report an error", !ec);
         };

         net::async_write(ssl, net::const_buffer(TEST_DATA, TEST_DATA_SIZE), write_handler);

         ioc.run();
         results.push_back(result);
      }

      void test_async_write_some_buffer_sequence(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         auto ctx = get_context();
         AsioStream ssl(ctx, ioc);
         ssl.next_layer().connect(remote);

         // this should be Botan::TLS::MAX_PLAINTEXT_SIZE + 1024 + 1
         std::array<uint8_t, 17 * 1024 + 1> random_data;
         random_data.fill('4');  // chosen by fair dice roll
         random_data.back() = '5';

         std::vector<net::const_buffer> src;
         src.emplace_back(net::const_buffer(random_data.data(), 1));
         for(std::size_t i = 1; i < random_data.size(); i += 1024) {
            src.emplace_back(net::const_buffer(random_data.data() + i, 1024));
         }

         Test::Result result("async write_some buffer sequence");

         result.confirm("[precondition] MAX_PLAINTEXT_SIZE is still smaller than random_data.size()",
                        Botan::TLS::MAX_PLAINTEXT_SIZE < random_data.size());

         auto write_handler = [&](const error_code& ec, std::size_t bytes_transferred) {
            result.confirm("writes the correct data",
                           contains(remote.buffer().data().data(), random_data.data(), random_data.size()));
            result.test_eq("writes the correct amount of data", bytes_transferred, random_data.size());
            result.test_eq("correct number of writes", ssl.next_layer().nwrite(), 2);
            result.confirm("does not report an error", !ec);
         };

         net::async_write(ssl, src, write_handler);

         ioc.run();
         results.push_back(result);
      }

      void test_async_write_some_error(std::vector<Test::Result>& results) {
         net::io_context ioc;
         // fail right away
         FailCount fc{0, net::error::no_recovery};
         TestStream remote{ioc};

         auto ctx = get_context();
         AsioStream ssl(ctx, ioc, fc);
         ssl.next_layer().connect(remote);

         Test::Result result("async write_some error");

         auto write_handler = [&](const error_code& ec, std::size_t bytes_transferred) {
            result.test_eq("committed some bytes to the core", bytes_transferred, TEST_DATA_SIZE);
            result.confirm("propagates error code", ec == net::error::no_recovery);
         };

         net::async_write(ssl, net::const_buffer(TEST_DATA, TEST_DATA_SIZE), write_handler);

         ioc.run();
         results.push_back(result);
      }

      void test_async_write_throw(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         auto ctx = get_context();
         ThrowingAsioStream ssl(ctx, ioc);
         ssl.next_layer().connect(remote);

         Test::Result result("async write_some throw");

         auto write_handler = [&](const error_code& ec, std::size_t bytes_transferred) {
            result.test_eq("didn't transfer anything", bytes_transferred, 0);
            result.confirm("propagates error code", ec == ThrowingMockChannel::expected_ec());
         };

         net::async_write(ssl, net::const_buffer(TEST_DATA, TEST_DATA_SIZE), write_handler);

         ioc.run();
         results.push_back(result);
      }

   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         test_sync_no_handshake(results);

         test_sync_handshake(results);
         test_sync_handshake_error(results);
         test_sync_handshake_cancellation(results);
         test_sync_handshake_throw(results);

         test_async_handshake(results);
         test_async_handshake_error(results);
         test_async_handshake_cancellation(results);
         test_async_handshake_throw(results);

         test_sync_read_some_success(results);
         test_sync_read_some_buffer_sequence(results);
         test_sync_read_some_error(results);
         test_sync_read_some_throw(results);
         test_sync_read_zero_buffer(results);

         test_async_read_some_success(results);
         test_async_read_some_buffer_sequence(results);
         test_async_read_some_error(results);
         test_async_read_some_throw(results);
         test_async_read_zero_buffer(results);

         test_sync_write_some_success(results);
         test_sync_write_some_buffer_sequence(results);
         test_sync_write_some_error(results);
         test_sync_write_some_throw(results);

         test_async_write_some_success(results);
         test_async_write_some_buffer_sequence(results);
         test_async_write_some_error(results);
         test_async_write_throw(results);

         return results;
      }
};

BOTAN_REGISTER_TEST("tls", "tls_asio_stream", Asio_Stream_Tests);

}  // namespace Botan_Tests

   #endif
#endif  // BOTAN_HAS_TLS && BOTAN_HAS_TLS_ASIO_STREAM
