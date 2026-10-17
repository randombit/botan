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
      #include <botan/hex.h>
      #include <botan/tls_callbacks.h>
      #include <botan/tls_session_manager_noop.h>

      #include <algorithm>
      #include <array>
      #include <boost/beast/_experimental/test/stream.hpp>
      #include <functional>
      #include <limits>
      #include <memory>
      #include <random>
      #include <stdexcept>
      #include <string>
      #include <utility>

namespace Botan_Tests {

namespace {

namespace net = boost::asio;
using boost::system::error_code;

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
      explicit MockChannel(std::shared_ptr<Botan::TLS::Callbacks> core) :
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

      static std::vector<uint8_t> close_notify_record() { return Botan::hex_decode("15030300020100"); }

      void received_close_notify() {
         m_close_notify_received = true;
         m_callbacks->tls_alert(Botan::TLS::AlertType::CloseNotify);
         send(close_notify_record());
      }

      void close() { send(close_notify_record()); }

   private:
      std::shared_ptr<Botan::TLS::Callbacks> m_callbacks;
      std::size_t m_bytes_till_complete_record;  // number of bytes still to read before tls record is completed
      bool m_active;
      bool m_close_notify_received;
};

class ThrowingMockChannel : public MockChannel {
   public:
      static boost::system::error_code expected_ec() { return Botan::TLS::Alert::UnexpectedMessage; }

      explicit ThrowingMockChannel(std::shared_ptr<Botan::TLS::Callbacks> core) : MockChannel(std::move(core)) {}

      // NOLINTNEXTLINE(bugprone-derived-method-shadowing-base-method)
      std::size_t received_data(std::span<const uint8_t> /*data*/) {
         throw Botan::TLS::Unexpected_Message("test_error");
      }

      // NOLINTNEXTLINE(bugprone-derived-method-shadowing-base-method)
      void send(std::span<const uint8_t> /*data*/) { throw Botan::TLS::Unexpected_Message("test_error"); }
};

class CancellingMockChannel : public MockChannel {
   public:
      explicit CancellingMockChannel(std::shared_ptr<Botan::TLS::Callbacks> core) : MockChannel(std::move(core)) {}

      // NOLINTNEXTLINE(bugprone-derived-method-shadowing-base-method)
      std::size_t received_data(std::span<const uint8_t> /*data*/) {
         received_close_notify();
         return 0;
      }
};

/**
 * Mocked channel that answers the first @p replies records it receives with a
 * record of its own (like the real TLS implementation does, for instance, with
 * a no_renegotiation alert) and delivers application data only afterwards.
 */
class EmittingMockChannel : public MockChannel {
   public:
      EmittingMockChannel(std::shared_ptr<Botan::TLS::Callbacks> core,
                          std::vector<uint8_t> record,
                          size_t replies = 1) :
            MockChannel(std::move(core)), m_record(std::move(record)), m_replies(replies) {}

      // NOLINTNEXTLINE(bugprone-derived-method-shadowing-base-method)
      std::size_t received_data(std::span<const uint8_t> data) {
         ++m_records_received;

         if(m_replies > 0) {
            --m_replies;
            send(m_record);
            return 0;
         }

         return MockChannel::received_data(data);
      }

      size_t records_received() const { return m_records_received; }

   private:
      std::vector<uint8_t> m_record;
      size_t m_replies;
      size_t m_records_received = 0;
};

/**
 * Mocked channel that, like the real TLS implementation, sends a fatal alert
 * before reporting its failure to process the peer's data.
 */
class AlertingMockChannel : public MockChannel {
   public:
      // fatal unexpected_message
      static std::vector<uint8_t> alert_record() { return Botan::hex_decode("1503030002020A"); }

      static boost::system::error_code expected_ec() { return Botan::TLS::Alert::UnexpectedMessage; }

      explicit AlertingMockChannel(std::shared_ptr<Botan::TLS::Callbacks> core) : MockChannel(std::move(core)) {}

      // NOLINTNEXTLINE(bugprone-derived-method-shadowing-base-method)
      std::size_t received_data(std::span<const uint8_t> /*data*/) {
         send(alert_record());
         throw Botan::TLS::Unexpected_Message("test_error");
      }
};

/**
 * Mocked channel that receives the peer's close_notify with the first record
 * (replying with its own, like the real TLS implementation does) and, as a
 * closed TLS session would, rejects any further data for sending.
 */
class ClosingMockChannel : public MockChannel {
   public:
      explicit ClosingMockChannel(std::shared_ptr<Botan::TLS::Callbacks> core) : MockChannel(std::move(core)) {}

      // NOLINTNEXTLINE(bugprone-derived-method-shadowing-base-method)
      std::size_t received_data(std::span<const uint8_t> /*data*/) {
         received_close_notify();
         return 0;
      }

      // NOLINTNEXTLINE(bugprone-derived-method-shadowing-base-method)
      void send(std::span<const uint8_t> data) {
         if(is_closed_for_writing()) {
            throw Botan::Invalid_State("Data cannot be sent on inactive TLS connection");
         }
         MockChannel::send(data);
      }

      // NOLINTNEXTLINE(bugprone-derived-method-shadowing-base-method)
      void close() {
         if(!is_closed_for_writing()) {
            MockChannel::close();
         }
      }
};

/**
 * Mocked channel that receives application data and the peer's close_notify
 * in one go (replying with its own close_notify).
 */
class CoalescedMockChannel : public MockChannel {
   public:
      explicit CoalescedMockChannel(std::shared_ptr<Botan::TLS::Callbacks> core) : MockChannel(std::move(core)) {}

      // NOLINTNEXTLINE(bugprone-derived-method-shadowing-base-method)
      std::size_t received_data(std::span<const uint8_t> /*data*/) {
         MockChannel::received_data(TEST_DATA);
         received_close_notify();
         return 0;
      }
};

/**
 * Mocked channel whose send() emits one record and then fails, like the real
 * TLS implementation might for a large write (TLS 1.2 generates and emits one
 * record at a time).
 */
class PartialSendMockChannel : public MockChannel {
   public:
      explicit PartialSendMockChannel(std::shared_ptr<Botan::TLS::Callbacks> core) : MockChannel(std::move(core)) {}

      // NOLINTNEXTLINE(bugprone-derived-method-shadowing-base-method)
      void send(std::span<const uint8_t> data) {
         MockChannel::send(data.first(data.size() / 2));
         throw Botan::Internal_Error("test_error");
      }
};

/**
 * Mocked channel that refuses to send before the handshake is complete, like
 * the real TLS implementation does.
 */
class InactiveSendMockChannel : public MockChannel {
   public:
      explicit InactiveSendMockChannel(std::shared_ptr<Botan::TLS::Callbacks> core) : MockChannel(std::move(core)) {}

      // NOLINTNEXTLINE(bugprone-derived-method-shadowing-base-method)
      void send(std::span<const uint8_t> data) {
         if(!is_active()) {
            throw Botan::Invalid_State("Data cannot be sent on inactive TLS connection");
         }
         MockChannel::send(data);
      }
};

/**
 * Mocked channel that fails while sending (see PartialSendMockChannel) and,
 * once active, answers the next record it receives with a close_notify.
 */
class PartialSendClosingMockChannel : public PartialSendMockChannel {
   public:
      using PartialSendMockChannel::PartialSendMockChannel;

      // NOLINTNEXTLINE(bugprone-derived-method-shadowing-base-method)
      std::size_t received_data(std::span<const uint8_t> data) {
         if(!is_active()) {
            return MockChannel::received_data(data);
         }
         received_close_notify();
         return 0;
      }
};

/**
 * Mocked channel that, once active, answers a record with an alert that is too
 * large to be buffered and swallows that failure, like Channel::send_alert()
 * does. Its close() does the same with the close_notify and, like the real TLS
 * implementation, considers the channel closed afterwards all the same.
 */
class SwallowingMockChannel : public MockChannel {
   public:
      explicit SwallowingMockChannel(std::shared_ptr<Botan::TLS::Callbacks> core) : MockChannel(std::move(core)) {}

      // NOLINTNEXTLINE(bugprone-derived-method-shadowing-base-method)
      std::size_t received_data(std::span<const uint8_t> data) {
         if(!is_active()) {
            return MockChannel::received_data(data);
         }
         emit_oversized_record();
         return 0;
      }

      // NOLINTNEXTLINE(bugprone-derived-method-shadowing-base-method)
      void close() {
         emit_oversized_record();
         m_closed = true;
      }

      // NOLINTNEXTLINE(bugprone-derived-method-shadowing-base-method)
      bool is_active() const { return MockChannel::is_active() && !m_closed; }

   private:
      void emit_oversized_record() {
         try {
            // never dereferenced: buffering fails before anything is copied. Larger than
            // any object can be, yet small enough that computing its end does not wrap.
            const auto oversized = static_cast<std::size_t>(std::numeric_limits<std::ptrdiff_t>::max()) + 1;
            send(std::span<const uint8_t>(TEST_DATA, oversized));
         } catch(...) { /* swallowed, like Channel::send_alert() does */
         }
      }

      bool m_closed = false;
};

/**
 * Mocked channel that, once active, throws on received data but stays active.
 */
class FailingReceiveMockChannel : public MockChannel {
   public:
      explicit FailingReceiveMockChannel(std::shared_ptr<Botan::TLS::Callbacks> core) : MockChannel(std::move(core)) {}

      // NOLINTNEXTLINE(bugprone-derived-method-shadowing-base-method)
      std::size_t received_data(std::span<const uint8_t> data) {
         if(!is_active()) {
            return MockChannel::received_data(data);
         }
         throw Botan::TLS::Unexpected_Message("test_error");
      }
};

/**
 * Mocked channel for the randomized interleaving test. Every record it emits is
 * numbered, so that the bytes the transport receives can be compared with the
 * bytes emitted. Processing the peer's data randomly emits a reply (like a
 * KeyUpdate would provoke one), delivers application data, or does nothing (as
 * for an incomplete record).
 */
class NumberedMockChannel : public MockChannel {
   public:
      NumberedMockChannel(std::shared_ptr<Botan::TLS::Callbacks> core, std::mt19937& rng) :
            MockChannel(core), m_core(std::move(core)), m_rng(rng) {}

      // NOLINTNEXTLINE(bugprone-derived-method-shadowing-base-method)
      std::size_t received_data(std::span<const uint8_t> /*data*/) {
         switch(m_rng() % 3) {
            case 0:
               emit_record();
               break;
            case 1:
               m_core->tls_record_received(0, TEST_DATA);
               break;
            default:
               break;
         }
         return 0;
      }

      // The plaintext is replaced by a numbered record
      // NOLINTNEXTLINE(bugprone-derived-method-shadowing-base-method)
      void send(std::span<const uint8_t> /*plaintext*/) {
         emit_record();
         m_last_send_end = m_emitted.size();
      }

      //! Everything emitted so far, in order
      const std::vector<uint8_t>& emitted() const { return m_emitted; }

      //! End of the records the last send() emitted, as a position in emitted()
      std::size_t last_send_end() const { return m_last_send_end; }

   private:
      void emit_record() {
         // 2 to 63 bytes, starting with the record number
         std::vector<uint8_t> record(2 + m_rng() % 62, static_cast<uint8_t>(m_records));
         record[0] = static_cast<uint8_t>(m_records >> 8);
         record[1] = static_cast<uint8_t>(m_records);
         ++m_records;

         m_emitted.insert(m_emitted.end(), record.begin(), record.end());
         MockChannel::send(record);
      }

      std::shared_ptr<Botan::TLS::Callbacks> m_core;
      std::mt19937& m_rng;
      std::vector<uint8_t> m_emitted;
      std::size_t m_last_send_end = 0;
      uint16_t m_records = 0;
};

// Unfortunately, boost::beast::test::stream keeps lowest_layer_type private and
// only friends boost::asio::ssl::stream. We need to make our own.
// NOLINTNEXTLINE(*-exception-escape) moving a beast test stream allocates
class TestStream : public boost::beast::test::stream {
   public:
      // NOLINTNEXTLINE(modernize-type-traits)
      using boost::beast::test::stream::stream;
      using lowest_layer_type = boost::beast::test::stream;
};

using FailCount = boost::beast::test::fail_count;

/**
 * A next layer that keeps only a view of the buffers it is asked to write and
 * copies them out when the write completes, like a socket does with a write
 * that cannot be serviced immediately. Writes that lend out storage which is
 * modified while the write is pending are exposed this way.
 *
 * By default a write completes in a later turn of the event loop. After
 * hold_writes() it completes only when complete_write() is called, which
 * allows stalling the transport.
 */
class DeferredWriteStream {
   public:
      using executor_type = TestStream::executor_type;

      template <typename... Args>
      explicit DeferredWriteStream(Args&&... args) : m_inner(std::forward<Args>(args)...) {}

      executor_type get_executor() noexcept { return m_inner.get_executor(); }

      TestStream& inner() { return m_inner; }

      template <class MutableBufferSequence>
      std::size_t read_some(const MutableBufferSequence& buffers, error_code& ec) {
         return m_inner.read_some(buffers, ec);
      }

      template <class ConstBufferSequence>
      std::size_t write_some(const ConstBufferSequence& buffers, error_code& ec) {
         return m_inner.write_some(buffers, ec);
      }

      void hold_writes() { m_hold_writes = true; }

      bool write_pending() const { return static_cast<bool>(m_pending_write); }

      //! Complete the pending write, with @p ec as its result, accepting at most @p max_bytes
      void complete_write(error_code ec = {}, std::size_t max_bytes = std::numeric_limits<std::size_t>::max()) {
         auto complete = std::move(m_pending_write);
         m_pending_write = nullptr;
         complete(ec, max_bytes);
      }

      template <class MutableBufferSequence, class ReadHandler>
      auto async_read_some(const MutableBufferSequence& buffers, ReadHandler&& handler) {
         return m_inner.async_read_some(buffers, std::forward<ReadHandler>(handler));
      }

      template <class ConstBufferSequence, class WriteHandler>
      // NOLINTNEXTLINE(*-missing-std-forward)
      auto async_write_some(const ConstBufferSequence& buffers, WriteHandler&& handler) {
         return net::async_initiate<WriteHandler, void(error_code, std::size_t)>(
            [this](auto completion_handler, const ConstBufferSequence& bufs) {
               // handlers are move-only, but std::function needs a copyable callable
               auto h = std::make_shared<decltype(completion_handler)>(std::move(completion_handler));

               // A zero-byte write completes right away
               if(net::buffer_size(bufs) == 0) {
                  net::post(get_executor(), [h] { (*h)(error_code{}, 0); });
                  return;
               }

               if(m_pending_write) {
                  throw std::logic_error("overlapping writes to the next layer");
               }

               m_pending_write = [this, h, bufs](error_code ec, std::size_t max_bytes) {
                  std::size_t n = 0;
                  if(!ec) {
                     // The caller's storage is dereferenced only now
                     std::vector<uint8_t> copy(std::min(net::buffer_size(bufs), max_bytes));
                     net::buffer_copy(net::buffer(copy), bufs);
                     n = m_inner.write_some(net::buffer(copy), ec);
                  }
                  net::post(get_executor(), [h, ec, n] { (*h)(ec, n); });
               };

               // A cancellation completes the pending write with operation_aborted and nothing transferred
               auto slot = net::get_associated_cancellation_slot(*h);
               if(slot.is_connected()) {
                  slot.assign([this](net::cancellation_type) {
                     if(m_pending_write) {
                        complete_write(net::error::operation_aborted);
                     }
                  });
               }

               if(!m_hold_writes) {
                  net::post(get_executor(), [this] { complete_write(); });
               }
            },
            handler,
            buffers);
      }

   private:
      TestStream m_inner;
      std::function<void(error_code, std::size_t)> m_pending_write;
      bool m_hold_writes = false;
};

// NOLINTNEXTLINE(*-exception-escape) see TestStream
class AsioStream : public Botan::TLS::Stream<TestStream, MockChannel> {
   public:
      template <typename... Args>
      explicit AsioStream(std::shared_ptr<Botan::TLS::Context> context, Args&&... args) :
            Stream(std::move(context), std::forward<Args>(args)...) {
         m_native_handle = std::make_unique<MockChannel>(m_core);
      }
};

class ThrowingAsioStream : public Botan::TLS::Stream<TestStream, ThrowingMockChannel> {
   public:
      template <typename... Args>
      explicit ThrowingAsioStream(std::shared_ptr<Botan::TLS::Context> context, Args&&... args) :
            Stream(std::move(context), std::forward<Args>(args)...) {
         m_native_handle = std::make_unique<ThrowingMockChannel>(m_core);
      }
};

class CancellingAsioStream : public Botan::TLS::Stream<TestStream, CancellingMockChannel> {
   public:
      template <typename... Args>
      explicit CancellingAsioStream(std::shared_ptr<Botan::TLS::Context> context, Args&&... args) :
            Stream(std::move(context), std::forward<Args>(args)...) {
         m_native_handle = std::make_unique<CancellingMockChannel>(m_core);
      }
};

class EmittingAsioStream : public Botan::TLS::Stream<TestStream, EmittingMockChannel> {
   public:
      template <typename... Args>
      explicit EmittingAsioStream(std::shared_ptr<Botan::TLS::Context> context,
                                  std::vector<uint8_t> record,
                                  Args&&... args) :
            Stream(std::move(context), std::forward<Args>(args)...) {
         m_native_handle = std::make_unique<EmittingMockChannel>(m_core, std::move(record));
      }
};

class AlertingAsioStream : public Botan::TLS::Stream<TestStream, AlertingMockChannel> {
   public:
      template <typename... Args>
      explicit AlertingAsioStream(std::shared_ptr<Botan::TLS::Context> context, Args&&... args) :
            Stream(std::move(context), std::forward<Args>(args)...) {
         m_native_handle = std::make_unique<AlertingMockChannel>(m_core);
      }
};

class CoalescedAsioStream : public Botan::TLS::Stream<TestStream, CoalescedMockChannel> {
   public:
      template <typename... Args>
      explicit CoalescedAsioStream(std::shared_ptr<Botan::TLS::Context> context, Args&&... args) :
            Stream(std::move(context), std::forward<Args>(args)...) {
         m_native_handle = std::make_unique<CoalescedMockChannel>(m_core);
      }
};

class PartialSendAsioStream : public Botan::TLS::Stream<TestStream, PartialSendMockChannel> {
   public:
      template <typename... Args>
      explicit PartialSendAsioStream(std::shared_ptr<Botan::TLS::Context> context, Args&&... args) :
            Stream(std::move(context), std::forward<Args>(args)...) {
         m_native_handle = std::make_unique<PartialSendMockChannel>(m_core);
      }
};

class InactiveSendAsioStream : public Botan::TLS::Stream<TestStream, InactiveSendMockChannel> {
   public:
      template <typename... Args>
      explicit InactiveSendAsioStream(std::shared_ptr<Botan::TLS::Context> context, Args&&... args) :
            Stream(std::move(context), std::forward<Args>(args)...) {
         m_native_handle = std::make_unique<InactiveSendMockChannel>(m_core);
      }
};

/**
 * A stream whose native handle is created on request only, as the real
 * stream's handshake does it, to test operations attempted before that.
 */
class LateMockAsioStream : public Botan::TLS::Stream<TestStream, MockChannel> {
   public:
      template <typename... Args>
      explicit LateMockAsioStream(std::shared_ptr<Botan::TLS::Context> context, Args&&... args) :
            Stream(std::move(context), std::forward<Args>(args)...) {}

      void create_native_handle() { m_native_handle = std::make_unique<MockChannel>(m_core); }
};

template <class ChannelT>
class MockAsioStream : public Botan::TLS::Stream<TestStream, ChannelT> {
   public:
      template <typename... Args>
      explicit MockAsioStream(std::shared_ptr<Botan::TLS::Context> context, Args&&... args) :
            Botan::TLS::Stream<TestStream, ChannelT>(std::move(context), std::forward<Args>(args)...) {
         this->m_native_handle = std::make_unique<ChannelT>(this->m_core);
      }
};

template <class ChannelT>
class DeferredWriteAsioStream : public Botan::TLS::Stream<DeferredWriteStream, ChannelT> {
   public:
      template <typename ChannelFactory, typename... Args>
      explicit DeferredWriteAsioStream(std::shared_ptr<Botan::TLS::Context> context,
                                       const ChannelFactory& make_channel,
                                       Args&&... args) :
            Botan::TLS::Stream<DeferredWriteStream, ChannelT>(std::move(context), std::forward<Args>(args)...) {
         this->m_native_handle = make_channel(this->m_core);
      }

      bool writing() const { return this->write_in_progress(); }
};

// Channel factories for DeferredWriteAsioStream

auto emitting(const std::vector<uint8_t>& record, size_t replies = 1) {
   return [record, replies](const std::shared_ptr<Botan::TLS::Callbacks>& core) {
      return std::make_unique<EmittingMockChannel>(core, record, replies);
   };
}

template <typename ChannelT>
auto channel() {
   return [](const std::shared_ptr<Botan::TLS::Callbacks>& core) { return std::make_unique<ChannelT>(core); };
}

static_assert(std::is_move_constructible_v<Botan::TLS::Stream<TestStream>>);
static_assert(std::is_move_assignable_v<Botan::TLS::Stream<TestStream>>);

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

      // everything that was written to the given stream
      std::vector<uint8_t> received_by(TestStream& remote) {
         const auto s = remote.str();
         return std::vector<uint8_t>(s.begin(), s.end());
      }

      /**
       * Completes the mock handshake from the stream's input and hands out the
       * application data the mock channel delivers with it, leaving the stream
       * active and idle.
       */
      template <typename StreamT>
      void activate(StreamT& ssl) {
         ssl.handshake(Botan::TLS::Connection_Side::Client);
         uint8_t buf[TEST_DATA_SIZE];
         ssl.read_some(net::buffer(buf));
      }

      //! A buffer sequence too large to flatten; never dereferenced, flattening fails before anything is copied
      static std::array<net::const_buffer, 2> too_large_to_flatten() {
         return {net::const_buffer(TEST_DATA, std::numeric_limits<std::size_t>::max() / 2),
                 net::const_buffer(TEST_DATA, std::numeric_limits<std::size_t>::max() / 2)};
      }

      boost::string_view test_data() const {
         return boost::string_view(reinterpret_cast<const char*>(TEST_DATA), TEST_DATA_SIZE);
      }

      void test_sync_handshake(std::vector<Test::Result>& results) {
         net::io_context ioc;
         const auto ctx = get_context();
         AsioStream ssl(ctx, ioc, test_data());

         ssl.handshake(Botan::TLS::Connection_Side::Client);

         Test::Result result("sync TLS handshake");
         result.test_is_true("feeds data into channel until active", ssl.native_handle()->is_active());
         results.push_back(result);
      }

      void test_sync_handshake_error(std::vector<Test::Result>& results) {
         net::io_context ioc;
         // fail right away
         FailCount fc{0, net::error::no_recovery};
         TestStream remote{ioc};

         const auto ctx = get_context();
         AsioStream ssl(ctx, ioc, fc);
         ssl.next_layer().connect(remote);

         // mimic handshake initialization
         ssl.native_handle()->send(TEST_DATA);

         error_code ec;
         ssl.handshake(Botan::TLS::Connection_Side::Client, ec);

         Test::Result result("sync TLS handshake error");
         result.test_is_false("does not activate channel", ssl.native_handle()->is_active());
         result.test_is_true("propagates error code", ec == net::error::no_recovery);
         results.push_back(result);
      }

      void test_sync_handshake_cancellation(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         CancellingAsioStream ssl(ctx, ioc, test_data());
         ssl.next_layer().connect(remote);

         // mimic handshake initialization
         ssl.native_handle()->send(TEST_DATA);

         error_code ec;
         ssl.handshake(Botan::TLS::Connection_Side::Client, ec);

         Test::Result result("sync TLS handshake cancellation");
         result.test_is_false("does not activate channel", ssl.native_handle()->is_active());
         result.test_is_false("does not finish handshake", ssl.native_handle()->is_handshake_complete());
         result.test_is_true("cancelled handshake means EOF", ec == net::error::eof);
         results.push_back(result);
      }

      void test_sync_handshake_throw(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         ThrowingAsioStream ssl(ctx, ioc, test_data());
         ssl.next_layer().connect(remote);

         error_code ec;
         ssl.handshake(Botan::TLS::Connection_Side::Client, ec);

         Test::Result result("sync TLS handshake error");
         result.test_is_false("does not activate channel", ssl.native_handle()->is_active());
         result.test_is_true("propagates error code", ec == ThrowingMockChannel::expected_ec());
         results.push_back(result);
      }

      void test_async_handshake(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         AsioStream ssl(ctx, ioc, test_data());
         ssl.next_layer().connect(remote);

         // mimic handshake initialization
         ssl.native_handle()->send(TEST_DATA);

         Test::Result result("async TLS handshake");

         auto handler = [&](const error_code&) {
            result.test_is_true("reads from socket", ssl.next_layer().nread() > 0);
            result.test_is_true("writes from socket", ssl.next_layer().nwrite() > 0);
            result.test_is_true("feeds data into channel until active", ssl.native_handle()->is_active());
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

         const auto ctx = get_context();
         AsioStream ssl(ctx, ioc, fc);
         ssl.next_layer().connect(remote);

         // mimic handshake initialization
         ssl.native_handle()->send(TEST_DATA);

         Test::Result result("async TLS handshake error");

         auto handler = [&](const error_code& ec) {
            result.test_is_false("does not activate channel", ssl.native_handle()->is_active());
            result.test_is_true("propagates error code", ec == net::error::no_recovery);
         };

         ssl.async_handshake(Botan::TLS::Connection_Side::Client, handler);

         ioc.run();
         results.push_back(result);
      }

      void test_async_handshake_cancellation(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         CancellingAsioStream ssl(ctx, ioc, test_data());
         ssl.next_layer().connect(remote);

         // mimic handshake initialization
         ssl.native_handle()->send(TEST_DATA);

         Test::Result result("async TLS handshake cancellation");

         auto handler = [&](const error_code& ec) {
            result.test_is_false("does not activate channel", ssl.native_handle()->is_active());
            result.test_is_false("does not finish handshake", ssl.native_handle()->is_handshake_complete());
            result.test_is_true("cancelled handshake means EOF", ec == net::error::eof);
         };

         ssl.async_handshake(Botan::TLS::Connection_Side::Client, handler);

         ioc.run();
         results.push_back(result);
      }

      void test_async_handshake_throw(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         ThrowingAsioStream ssl(ctx, ioc, test_data());
         ssl.next_layer().connect(remote);

         Test::Result result("async TLS handshake throw");

         auto handler = [&](const error_code& ec) {
            result.test_is_false("does not activate channel", ssl.native_handle()->is_active());
            result.test_is_true("propagates error code", ec == ThrowingMockChannel::expected_ec());
         };

         ssl.async_handshake(Botan::TLS::Connection_Side::Client, handler);

         ioc.run();
         results.push_back(result);
      }

      void test_sync_read_some_success(std::vector<Test::Result>& results) {
         net::io_context ioc;

         const auto ctx = get_context();
         AsioStream ssl(ctx, ioc, test_data());

         const std::size_t buf_size = 128;
         uint8_t buf[buf_size];
         error_code ec;

         const auto bytes_transferred = net::read(ssl, net::mutable_buffer(buf, sizeof(buf)), ec);

         Test::Result result("sync read_some success");
         result.test_is_true("reads the correct data", contains(buf, TEST_DATA, buf_size));
         result.test_sz_eq("reads the correct amount of data", bytes_transferred, buf_size);
         result.test_is_true("does not report an error", !ec);

         results.push_back(result);
      }

      void test_sync_read_some_buffer_sequence(std::vector<Test::Result>& results) {
         net::io_context ioc;

         const auto ctx = get_context();
         AsioStream ssl(ctx, ioc, test_data());
         error_code ec;

         std::vector<net::mutable_buffer> data;
         uint8_t buf1[TEST_DATA_SIZE / 2];
         uint8_t buf2[TEST_DATA_SIZE / 2];
         data.emplace_back(net::mutable_buffer(buf1, TEST_DATA_SIZE / 2));
         data.emplace_back(net::mutable_buffer(buf2, TEST_DATA_SIZE / 2));

         const auto bytes_transferred = net::read(ssl, data, ec);

         Test::Result result("sync read_some buffer sequence");

         result.test_is_true("reads the correct data",
                             contains(buf1, TEST_DATA, TEST_DATA_SIZE / 2) &&
                                contains(buf2, TEST_DATA + TEST_DATA_SIZE / 2, TEST_DATA_SIZE / 2));
         result.test_sz_eq("reads the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
         result.test_is_true("does not report an error", !ec);

         results.push_back(result);
      }

      void test_sync_read_some_error(std::vector<Test::Result>& results) {
         net::io_context ioc;
         // fail right away
         FailCount fc{0, net::error::no_recovery};
         TestStream remote{ioc};

         const auto ctx = get_context();
         AsioStream ssl(ctx, ioc, fc);
         ssl.next_layer().connect(remote);

         uint8_t buf[128];
         error_code ec;

         const auto bytes_transferred = net::read(ssl, net::mutable_buffer(buf, sizeof(buf)), ec);

         Test::Result result("sync read_some error");
         result.test_sz_eq("didn't transfer anything", bytes_transferred, 0);
         result.test_is_true("propagates error code", ec == net::error::no_recovery);

         results.push_back(result);
      }

      void test_sync_read_some_throw(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         ThrowingAsioStream ssl(ctx, ioc, test_data());
         ssl.next_layer().connect(remote);

         uint8_t buf[128];
         error_code ec;

         const auto bytes_transferred = net::read(ssl, net::mutable_buffer(buf, sizeof(buf)), ec);

         Test::Result result("sync read_some throw");
         result.test_sz_eq("didn't transfer anything", bytes_transferred, 0);
         result.test_is_true("propagates error code", ec == ThrowingMockChannel::expected_ec());

         results.push_back(result);
      }

      void test_sync_read_zero_buffer(std::vector<Test::Result>& results) {
         net::io_context ioc;
         // any read from the next layer would fail right away
         FailCount fc{0, net::error::no_recovery};
         TestStream remote{ioc};

         const auto ctx = get_context();
         AsioStream ssl(ctx, ioc, fc);
         ssl.next_layer().connect(remote);
         // data waiting to be sent is not flushed by a zero-byte read either
         ssl.native_handle()->send(TEST_DATA);

         const std::size_t buf_size = 128;
         uint8_t buf[buf_size];
         error_code ec;

         const auto bytes_transferred = ssl.read_some(net::mutable_buffer(buf, std::size_t(0)), ec);

         Test::Result result("sync read_some into zero-size buffer");
         result.test_sz_eq("reads the correct amount of data", bytes_transferred, 0);
         result.test_is_true("does not report an error", !ec);
         result.test_sz_eq("does not read from the next layer", ssl.next_layer().nread(), 0);
         result.test_sz_eq("does not write to the next layer", ssl.next_layer().nwrite(), 0);

         results.push_back(result);
      }

      void test_sync_read_some_sends_emitted_data(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         // warning no_renegotiation
         const auto record = Botan::hex_decode("15030300020164");
         EmittingAsioStream ssl(ctx, record, ioc, test_data());
         ssl.next_layer().connect(remote);
         ssl.next_layer().append(test_data());
         ssl.next_layer().read_size(TEST_DATA_SIZE);

         uint8_t buf[TEST_DATA_SIZE];
         error_code ec;

         const auto bytes_transferred = net::read(ssl, net::mutable_buffer(buf, sizeof(buf)), ec);

         Test::Result result("sync read_some sends records emitted by the TLS layer");
         result.test_is_true("does not report an error", !ec);
         result.test_sz_eq("reads the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
         result.test_is_true("reads the correct data", contains(buf, TEST_DATA, TEST_DATA_SIZE));
         result.test_bin_eq("emitted record was sent", received_by(remote), record);

         results.push_back(result);
      }

      void test_sync_read_some_sends_alert(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         AlertingAsioStream ssl(ctx, ioc, test_data());
         ssl.next_layer().connect(remote);

         uint8_t buf[128];
         error_code ec;

         const auto bytes_transferred = net::read(ssl, net::mutable_buffer(buf, sizeof(buf)), ec);

         Test::Result result("sync read_some sends the alert generated for a processing error");
         result.test_sz_eq("didn't transfer anything", bytes_transferred, 0);
         result.test_is_true("propagates error code", ec == AlertingMockChannel::expected_ec());
         result.test_bin_eq(
            "alert was sent before reporting the error", received_by(remote), AlertingMockChannel::alert_record());

         results.push_back(result);
      }

      void test_sync_stale_error_code(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         AsioStream ssl(ctx, ioc, test_data());
         ssl.next_layer().connect(remote);

         Test::Result result("sync operations reset a stale error code");

         error_code ec = net::error::no_recovery;
         ssl.handshake(Botan::TLS::Connection_Side::Client, ec);
         result.test_is_true("handshake does not report an error", !ec);
         result.test_is_true("handshake feeds data into channel until active", ssl.native_handle()->is_active());

         ec = net::error::no_recovery;
         const auto written = ssl.write_some(net::const_buffer(TEST_DATA, TEST_DATA_SIZE), ec);
         result.test_is_true("write_some does not report an error", !ec);
         result.test_sz_eq("write_some writes the correct amount of data", written, TEST_DATA_SIZE);
         result.test_is_true("write_some writes the correct data", remote.str() == test_data());

         ec = net::error::no_recovery;
         uint8_t buf[TEST_DATA_SIZE];
         const auto read = ssl.read_some(net::mutable_buffer(buf, sizeof(buf)), ec);
         result.test_is_true("read_some does not report an error", !ec);
         result.test_sz_eq("read_some reads the correct amount of data", read, TEST_DATA_SIZE);

         ec = net::error::no_recovery;
         ssl.shutdown(ec);
         result.test_is_true("shutdown does not report an error", !ec);
         result.test_sz_eq("shutdown wrote the close_notify", remote.str().size(), TEST_DATA_SIZE + 7);

         results.push_back(result);
      }

      void test_move_assignment(std::vector<Test::Result>& results) {
         net::io_context ioc;

         const auto ctx = get_context();
         AsioStream from(ctx, ioc, test_data());
         AsioStream ssl(ctx, ioc);
         ssl = std::move(from);

         uint8_t buf[TEST_DATA_SIZE];
         error_code ec;

         const auto bytes_transferred = net::read(ssl, net::mutable_buffer(buf, sizeof(buf)), ec);

         Test::Result result("move assignment");
         result.test_is_true("does not report an error", !ec);
         result.test_sz_eq("reads the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
         result.test_is_true("reads the correct data", contains(buf, TEST_DATA, TEST_DATA_SIZE));

         results.push_back(result);
      }

      void test_callbacks_reuse(std::vector<Test::Result>& results) {
         net::io_context ioc;
         const auto ctx = get_context();
         const auto callbacks = std::make_shared<Botan::TLS::StreamCallbacks>();

         Test::Result result("StreamCallbacks instance is bound to one Stream at a time");

         auto first = std::make_unique<Botan::TLS::Stream<TestStream>>(ctx, callbacks, ioc);
         result.test_throws<Botan::Invalid_Argument>("rejects an instance in use by another stream", [&] {
            const Botan::TLS::Stream<TestStream> second(ctx, callbacks, ioc);
         });

         // A moved stream keeps its binding
         auto moved = std::make_unique<Botan::TLS::Stream<TestStream>>(std::move(*first));
         first.reset();
         result.test_throws<Botan::Invalid_Argument>("rejects an instance in use by a moved stream", [&] {
            const Botan::TLS::Stream<TestStream> second(ctx, callbacks, ioc);
         });

         moved.reset();
         result.test_no_throw("accepts the instance once the previous stream is gone",
                              [&] { const Botan::TLS::Stream<TestStream> third(ctx, callbacks, ioc); });

         results.push_back(result);
      }

      void test_null_arguments(std::vector<Test::Result>& results) {
         net::io_context ioc;
         const auto creds = std::make_shared<Botan::Credentials_Manager>();
         const auto rng = std::make_shared<Botan::Null_RNG>();
         const auto session_mgr = std::make_shared<Botan::TLS::Session_Manager_Noop>();
         const auto policy = std::make_shared<Botan::TLS::Default_Policy>();

         Test::Result result("null arguments are rejected");

         result.test_throws<Botan::Invalid_Argument>("Context rejects null credentials manager", [&] {
            const Botan::TLS::Context context(nullptr, rng, session_mgr, policy);
         });
         result.test_throws<Botan::Invalid_Argument>("Context rejects null RNG", [&] {
            const Botan::TLS::Context context(creds, nullptr, session_mgr, policy);
         });
         result.test_throws<Botan::Invalid_Argument>("Context rejects null session manager", [&] {
            const Botan::TLS::Context context(creds, rng, nullptr, policy);
         });
         result.test_throws<Botan::Invalid_Argument>("Context rejects null policy", [&] {
            const Botan::TLS::Context context(creds, rng, session_mgr, nullptr);
         });

         result.test_throws<Botan::Invalid_Argument>("Stream rejects null context", [&] {
            const Botan::TLS::Stream<TestStream> ssl(
               std::shared_ptr<Botan::TLS::Context>(), std::make_shared<Botan::TLS::StreamCallbacks>(), ioc);
         });
         result.test_throws<Botan::Invalid_Argument>("Stream rejects null callbacks", [&] {
            const Botan::TLS::Stream<TestStream> ssl(
               get_context(), std::shared_ptr<Botan::TLS::StreamCallbacks>(), ioc);
         });

         results.push_back(result);
      }

      void test_async_read_some_success(std::vector<Test::Result>& results) {
         net::io_context ioc;
         const TestStream remote{ioc};

         const auto ctx = get_context();
         AsioStream ssl(ctx, ioc, test_data());
         uint8_t data[TEST_DATA_SIZE]{};

         Test::Result result("async read_some success");

         auto read_handler = [&](const error_code& ec, std::size_t bytes_transferred) {
            result.test_is_true("reads the correct data", contains(data, TEST_DATA, TEST_DATA_SIZE));
            result.test_sz_eq("reads the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
            result.test_is_true("does not report an error", !ec);
         };

         const net::mutable_buffer buf{data, TEST_DATA_SIZE};
         net::async_read(ssl, buf, read_handler);

         ssl.next_layer().close_remote();
         ioc.run();
         results.push_back(result);
      }

      void test_async_read_some_buffer_sequence(std::vector<Test::Result>& results) {
         net::io_context ioc;
         const auto ctx = get_context();
         AsioStream ssl(ctx, ioc, test_data());

         std::vector<net::mutable_buffer> data;
         uint8_t buf1[TEST_DATA_SIZE / 2];
         uint8_t buf2[TEST_DATA_SIZE / 2];
         data.emplace_back(net::mutable_buffer(buf1, TEST_DATA_SIZE / 2));
         data.emplace_back(net::mutable_buffer(buf2, TEST_DATA_SIZE / 2));

         Test::Result result("async read_some buffer sequence");

         auto read_handler = [&](const error_code& ec, std::size_t bytes_transferred) {
            result.test_is_true("reads the correct data",
                                contains(buf1, TEST_DATA, TEST_DATA_SIZE / 2) &&
                                   contains(buf2, TEST_DATA + TEST_DATA_SIZE / 2, TEST_DATA_SIZE / 2));
            result.test_sz_eq("reads the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
            result.test_is_true("does not report an error", !ec);
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
         const auto ctx = get_context();
         AsioStream ssl(ctx, ioc, fc);
         uint8_t data[TEST_DATA_SIZE];

         Test::Result result("async read_some error");

         auto read_handler = [&](const error_code& ec, std::size_t bytes_transferred) {
            result.test_sz_eq("didn't transfer anything", bytes_transferred, 0);
            result.test_is_true("propagates error code", ec == net::error::no_recovery);
         };

         const net::mutable_buffer buf{data, TEST_DATA_SIZE};
         net::async_read(ssl, buf, read_handler);

         ssl.next_layer().close_remote();
         ioc.run();
         results.push_back(result);
      }

      void test_async_read_some_throw(std::vector<Test::Result>& results) {
         net::io_context ioc;
         const auto ctx = get_context();
         ThrowingAsioStream ssl(ctx, ioc, test_data());
         uint8_t data[TEST_DATA_SIZE];

         Test::Result result("async read_some throw");

         auto read_handler = [&](const error_code& ec, std::size_t bytes_transferred) {
            result.test_sz_eq("didn't transfer anything", bytes_transferred, 0);
            result.test_is_true("propagates error code", ec == ThrowingMockChannel::expected_ec());
         };

         const net::mutable_buffer buf{data, TEST_DATA_SIZE};
         net::async_read(ssl, buf, read_handler);

         ssl.next_layer().close_remote();
         ioc.run();
         results.push_back(result);
      }

      void test_async_read_some_sends_emitted_data(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         // warning no_renegotiation
         const auto record = Botan::hex_decode("15030300020164");
         EmittingAsioStream ssl(ctx, record, ioc, test_data());
         ssl.next_layer().connect(remote);
         ssl.next_layer().append(test_data());
         ssl.next_layer().read_size(TEST_DATA_SIZE);
         uint8_t data[TEST_DATA_SIZE]{};

         Test::Result result("async read_some sends records emitted by the TLS layer");

         auto read_handler = [&](const error_code& ec, std::size_t bytes_transferred) {
            result.test_is_true("does not report an error", !ec);
            result.test_sz_eq("reads the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
            result.test_is_true("reads the correct data", contains(data, TEST_DATA, TEST_DATA_SIZE));
            result.test_bin_eq("emitted record was sent", received_by(remote), record);
         };

         net::async_read(ssl, net::buffer(data), read_handler);

         ioc.run();
         results.push_back(result);
      }

      void test_async_read_some_sends_alert(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         AlertingAsioStream ssl(ctx, ioc, test_data());
         ssl.next_layer().connect(remote);
         uint8_t data[TEST_DATA_SIZE];

         Test::Result result("async read_some sends the alert generated for a processing error");

         auto read_handler = [&](const error_code& ec, std::size_t bytes_transferred) {
            result.test_sz_eq("didn't transfer anything", bytes_transferred, 0);
            result.test_is_true("propagates error code", ec == AlertingMockChannel::expected_ec());
            result.test_bin_eq(
               "alert was sent before reporting the error", received_by(remote), AlertingMockChannel::alert_record());
         };

         net::async_read(ssl, net::buffer(data), read_handler);

         ioc.run();
         results.push_back(result);
      }

      void test_async_read_write_overlap(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         // Large enough that appending it to the send buffer reallocates the buffer's storage
         const std::vector<uint8_t> record(4 * TEST_DATA_SIZE, 0x15);
         DeferredWriteAsioStream<EmittingMockChannel> ssl(ctx, emitting(record), ioc, test_data());
         ssl.next_layer().inner().connect(remote);
         ssl.next_layer().inner().append(test_data());
         ssl.next_layer().inner().read_size(TEST_DATA_SIZE);
         uint8_t data[TEST_DATA_SIZE]{};

         Test::Result result("async read and write outstanding at the same time");

         bool read_done = false;
         bool write_done = false;

         // The read is started first so that it processes the peer's data (and
         // the TLS layer appends to the send buffer) while the write's records
         // are still lent to the next layer.
         net::async_read(ssl, net::buffer(data), [&](const error_code& ec, std::size_t bytes_transferred) {
            read_done = true;
            result.test_is_true("read does not report an error", !ec);
            result.test_sz_eq("reads the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
            result.test_is_true("reads the correct data", contains(data, TEST_DATA, TEST_DATA_SIZE));
         });

         net::async_write(ssl,
                          net::const_buffer(TEST_DATA, TEST_DATA_SIZE),
                          [&](const error_code& ec, std::size_t bytes_transferred) {
                             write_done = true;
                             result.test_is_true("write does not report an error", !ec);
                             result.test_sz_eq("writes the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
                          });

         ioc.run();

         result.test_is_true("read completed", read_done);
         result.test_is_true("write completed", write_done);

         std::vector<uint8_t> expected(TEST_DATA, TEST_DATA + TEST_DATA_SIZE);
         expected.insert(expected.end(), record.begin(), record.end());
         result.test_bin_eq("records were written intact and in order", received_by(remote), expected);

         results.push_back(result);
      }

      void test_async_write_waits_for_read_flush(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         const auto record = Botan::hex_decode("15030300020164");
         DeferredWriteAsioStream<EmittingMockChannel> ssl(ctx, emitting(record), ioc, test_data());
         ssl.next_layer().inner().connect(remote);
         ssl.next_layer().inner().append(test_data());
         ssl.next_layer().inner().read_size(TEST_DATA_SIZE);
         uint8_t data[TEST_DATA_SIZE]{};

         Test::Result result("async write waits for a read operation's write to finish");

         bool read_done = false;
         bool write_done = false;

         net::async_read(ssl, net::buffer(data), [&](const error_code& ec, std::size_t bytes_transferred) {
            read_done = true;
            result.test_is_true("read does not report an error", !ec);
            result.test_sz_eq("reads the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
            result.test_is_true("reads the correct data", contains(data, TEST_DATA, TEST_DATA_SIZE));
         });

         // Runs once the read operation has started sending the emitted record
         net::post(ioc, [&] {
            result.test_is_true("[precondition] read operation is writing", ssl.writing());

            net::async_write(ssl,
                             net::const_buffer(TEST_DATA, TEST_DATA_SIZE),
                             [&](const error_code& ec, std::size_t bytes_transferred) {
                                write_done = true;
                                result.test_is_true("write does not report an error", !ec);
                                result.test_sz_eq(
                                   "writes the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
                             });
         });

         ioc.run();

         result.test_is_true("read completed", read_done);
         result.test_is_true("write completed", write_done);

         auto expected = record;
         expected.insert(expected.end(), TEST_DATA, TEST_DATA + TEST_DATA_SIZE);
         result.test_bin_eq("records were written in order", received_by(remote), expected);

         results.push_back(result);
      }

      void test_async_write_cancellation(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         const auto record = Botan::hex_decode("15030300020164");
         DeferredWriteAsioStream<EmittingMockChannel> ssl(ctx, emitting(record), ioc, test_data());
         ssl.next_layer().inner().connect(remote);
         ssl.next_layer().inner().append(test_data());
         ssl.next_layer().inner().read_size(TEST_DATA_SIZE);
         uint8_t data[TEST_DATA_SIZE]{};

         Test::Result result("async write cancelled while waiting for a read operation's write");

         bool read_done = false;
         bool write_done = false;
         net::cancellation_signal cancel;

         net::async_read(ssl, net::buffer(data), [&](const error_code& ec, std::size_t bytes_transferred) {
            read_done = true;
            result.test_is_true("read does not report an error", !ec);
            result.test_sz_eq("reads the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
         });

         // Runs once the read operation has started sending the emitted record
         net::post(ioc, [&] {
            result.test_is_true("[precondition] read operation is writing", ssl.writing());

            net::async_write(
               ssl,
               net::const_buffer(TEST_DATA, TEST_DATA_SIZE),
               net::bind_cancellation_slot(cancel.slot(), [&](const error_code& ec, std::size_t bytes_transferred) {
                  write_done = true;
                  result.test_is_true("write was cancelled", ec == net::error::operation_aborted);
                  result.test_sz_eq("nothing was written", bytes_transferred, 0);
               }));

            cancel.emit(net::cancellation_type::terminal);
         });

         ioc.run();

         result.test_is_true("read completed", read_done);
         result.test_is_true("write completed", write_done);
         result.test_bin_eq("application data was never encrypted", received_by(remote), record);

         results.push_back(result);
      }

      void test_async_read_waits_for_stalled_write(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         // The peer sends five requests that each provoke a reply, then application data
         const auto reply = Botan::hex_decode("15030300020164");
         DeferredWriteAsioStream<EmittingMockChannel> ssl(ctx, emitting(reply, 5), ioc, test_data());
         for(size_t i = 0; i < 5; ++i) {
            ssl.next_layer().inner().append(test_data());
         }
         ssl.next_layer().inner().connect(remote);
         ssl.next_layer().inner().read_size(TEST_DATA_SIZE);
         ssl.next_layer().hold_writes();
         uint8_t data[TEST_DATA_SIZE]{};

         Test::Result result("async read waits for a stalled write before consuming more input");

         bool read_done = false;
         bool write_done = false;

         net::async_write(ssl,
                          net::const_buffer(TEST_DATA, TEST_DATA_SIZE),
                          [&](const error_code& ec, std::size_t bytes_transferred) {
                             write_done = true;
                             result.test_is_true("write does not report an error", !ec);
                             result.test_sz_eq("writes the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
                          });

         net::async_read(ssl, net::buffer(data), [&](const error_code& ec, std::size_t bytes_transferred) {
            read_done = true;
            result.test_is_true("read does not report an error", !ec);
            result.test_sz_eq("reads the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
            result.test_is_true("reads the correct data", contains(data, TEST_DATA, TEST_DATA_SIZE));
         });

         // While the write is stalled, the read must not consume more input
         ioc.poll();
         result.test_is_true("[precondition] write is stalled", ssl.next_layer().write_pending());
         result.test_sz_eq("one request was processed", ssl.native_handle()->records_received(), 1);
         result.test_is_false("read did not complete", read_done);

         // Releasing the writes one by one lets the read make progress
         while(ssl.next_layer().write_pending()) {
            ssl.next_layer().complete_write();
            ioc.restart();
            ioc.poll();
         }

         result.test_is_true("read completed", read_done);
         result.test_is_true("write completed", write_done);
         result.test_sz_eq("all requests were processed", ssl.native_handle()->records_received(), 6);

         std::vector<uint8_t> expected(TEST_DATA, TEST_DATA + TEST_DATA_SIZE);
         for(size_t i = 0; i < 5; ++i) {
            expected.insert(expected.end(), reply.begin(), reply.end());
         }
         result.test_bin_eq("records were written in order", received_by(remote), expected);

         results.push_back(result);
      }

      void test_async_read_error_waits_for_stalled_write(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         DeferredWriteAsioStream<AlertingMockChannel> ssl(ctx, channel<AlertingMockChannel>(), ioc, test_data());
         ssl.next_layer().inner().connect(remote);
         ssl.next_layer().hold_writes();
         uint8_t data[TEST_DATA_SIZE]{};

         Test::Result result("async read reports a processing error only once its alert was sent");

         bool read_done = false;
         bool write_done = false;

         net::async_write(ssl,
                          net::const_buffer(TEST_DATA, TEST_DATA_SIZE),
                          [&](const error_code& ec, std::size_t bytes_transferred) {
                             write_done = true;
                             result.test_is_true("write does not report an error", !ec);
                             result.test_sz_eq("writes the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
                          });

         std::vector<uint8_t> expected(TEST_DATA, TEST_DATA + TEST_DATA_SIZE);
         const auto alert = AlertingMockChannel::alert_record();
         expected.insert(expected.end(), alert.begin(), alert.end());

         net::async_read(ssl, net::buffer(data), [&](const error_code& ec, std::size_t bytes_transferred) {
            read_done = true;
            result.test_sz_eq("didn't transfer anything", bytes_transferred, 0);
            result.test_is_true("propagates error code", ec == AlertingMockChannel::expected_ec());
            result.test_bin_eq("alert was sent before reporting the error", received_by(remote), expected);
         });

         ioc.poll();
         result.test_is_true("[precondition] write is stalled", ssl.next_layer().write_pending());
         result.test_is_false("read did not complete while its alert is queued", read_done);

         while(ssl.next_layer().write_pending()) {
            ssl.next_layer().complete_write();
            ioc.restart();
            ioc.poll();
         }

         result.test_is_true("read completed", read_done);
         result.test_is_true("write completed", write_done);

         results.push_back(result);
      }

      void test_async_shutdown_reports_write_error(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         const auto reply = Botan::hex_decode("15030300020164");
         DeferredWriteAsioStream<EmittingMockChannel> ssl(ctx, emitting(reply), ioc, test_data());
         ssl.next_layer().inner().connect(remote);
         ssl.next_layer().inner().append(test_data());
         ssl.next_layer().inner().read_size(TEST_DATA_SIZE);
         ssl.next_layer().hold_writes();
         uint8_t data[TEST_DATA_SIZE]{};

         Test::Result result("async shutdown reports the failure to send close_notify");

         bool read_done = false;
         bool shutdown_done = false;

         net::async_read(ssl, net::buffer(data), [&](const error_code& ec, std::size_t bytes_transferred) {
            read_done = true;
            result.test_is_true("read does not report an error", !ec);
            result.test_sz_eq("reads the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
         });

         // The read operation is now sending the emitted record
         ioc.poll();
         result.test_is_true("[precondition] read operation is writing", ssl.writing());

         ssl.async_shutdown([&](const error_code& ec) {
            shutdown_done = true;
            result.test_is_true("shutdown reports the error", ec == net::error::connection_reset);
         });

         // The read's write completes; the shutdown then sends close_notify, which fails
         ssl.next_layer().complete_write();
         ioc.restart();
         ioc.poll();
         result.test_is_true("[precondition] close_notify is being sent", ssl.next_layer().write_pending());

         ssl.next_layer().complete_write(net::error::connection_reset);
         ioc.restart();
         ioc.poll();

         result.test_is_true("read completed", read_done);
         result.test_is_true("shutdown completed", shutdown_done);
         result.test_bin_eq("close_notify did not reach the peer", received_by(remote), reply);

         results.push_back(result);
      }

      void test_async_read_reply_survives_failed_write(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         DeferredWriteAsioStream<ClosingMockChannel> ssl(ctx, channel<ClosingMockChannel>(), ioc, test_data());
         ssl.next_layer().inner().connect(remote);
         ssl.next_layer().hold_writes();
         uint8_t data[TEST_DATA_SIZE]{};

         Test::Result result("async read's close_notify reply survives a subsequent write that fails");

         bool read_done = false;
         bool second_write_done = false;

         // Once the first write completes, the session is closed and the second write fails to encrypt
         net::async_write(ssl, net::const_buffer(TEST_DATA, TEST_DATA_SIZE), [&](const error_code& ec, std::size_t) {
            result.test_is_true("first write does not report an error", !ec);

            net::async_write(ssl,
                             net::const_buffer(TEST_DATA, TEST_DATA_SIZE),
                             [&](const error_code& ec2, std::size_t bytes_transferred) {
                                second_write_done = true;
                                result.test_is_true("second write reports an error", ec2.failed());
                                result.test_sz_eq("second write wrote nothing", bytes_transferred, 0);
                             });
         });

         std::vector<uint8_t> expected(TEST_DATA, TEST_DATA + TEST_DATA_SIZE);
         const auto reply = MockChannel::close_notify_record();
         expected.insert(expected.end(), reply.begin(), reply.end());

         net::async_read(ssl, net::buffer(data), [&](const error_code& ec, std::size_t bytes_transferred) {
            read_done = true;
            result.test_is_true("read reports EOF", ec == net::error::eof);
            result.test_sz_eq("didn't transfer anything", bytes_transferred, 0);
            result.test_bin_eq("close_notify reply was sent before reporting EOF", received_by(remote), expected);
         });

         ioc.poll();
         result.test_is_true("[precondition] write is stalled", ssl.next_layer().write_pending());
         result.test_is_false("read did not complete while its reply is queued", read_done);

         while(ssl.next_layer().write_pending()) {
            ssl.next_layer().complete_write();
            ioc.restart();
            ioc.poll();
         }

         result.test_is_true("read completed", read_done);
         result.test_is_true("second write completed", second_write_done);

         results.push_back(result);
      }

      void test_async_read_reply_sent_by_shutdown(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         DeferredWriteAsioStream<ClosingMockChannel> ssl(ctx, channel<ClosingMockChannel>(), ioc, test_data());
         ssl.next_layer().inner().connect(remote);
         ssl.next_layer().hold_writes();
         uint8_t data[TEST_DATA_SIZE]{};

         Test::Result result("async read reports EOF only once its close_notify reply was written");

         bool read_done = false;
         bool shutdown_done = false;

         // Once the first write completes, the application shuts the (already closed) session down
         net::async_write(ssl, net::const_buffer(TEST_DATA, TEST_DATA_SIZE), [&](const error_code& ec, std::size_t) {
            result.test_is_true("write does not report an error", !ec);

            ssl.async_shutdown([&](const error_code& ec2) {
               shutdown_done = true;
               result.test_is_true("shutdown does not report an error", !ec2);
            });
         });

         std::vector<uint8_t> expected(TEST_DATA, TEST_DATA + TEST_DATA_SIZE);
         const auto reply = MockChannel::close_notify_record();
         expected.insert(expected.end(), reply.begin(), reply.end());

         net::async_read(ssl, net::buffer(data), [&](const error_code& ec, std::size_t bytes_transferred) {
            read_done = true;
            result.test_is_true("read reports EOF", ec == net::error::eof);
            result.test_sz_eq("didn't transfer anything", bytes_transferred, 0);
            result.test_bin_eq("close_notify reply was sent exactly once", received_by(remote), expected);
         });

         ioc.poll();
         result.test_is_true("[precondition] write is stalled", ssl.next_layer().write_pending());
         result.test_is_false("read did not complete while its reply is queued", read_done);

         while(ssl.next_layer().write_pending()) {
            ssl.next_layer().complete_write();
            ioc.restart();
            ioc.poll();
         }

         result.test_is_true("read completed", read_done);
         result.test_is_true("shutdown completed", shutdown_done);

         results.push_back(result);
      }

      void test_async_read_hands_out_data_before_sending_reply(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         DeferredWriteAsioStream<CoalescedMockChannel> ssl(ctx, channel<CoalescedMockChannel>(), ioc, test_data());
         ssl.next_layer().inner().connect(remote);
         uint8_t data[TEST_DATA_SIZE]{};

         Test::Result result("async read hands out application data before sending the reply generated alongside");

         bool read_done = false;

         net::async_read(ssl, net::buffer(data), [&](const error_code& ec, std::size_t bytes_transferred) {
            read_done = true;
            result.test_is_true("read does not report an error", !ec);
            result.test_sz_eq("reads the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
            result.test_is_true("reads the correct data", contains(data, TEST_DATA, TEST_DATA_SIZE));
            result.test_is_true("reply was not sent yet", remote.str().empty());
         });

         ioc.run();
         result.test_is_true("read completed", read_done);
         result.test_is_false("read did not write to the next layer", ssl.next_layer().write_pending());

         // The next read sends the reply, then reports the peer's close_notify
         bool next_read_done = false;
         ssl.async_read_some(net::buffer(data), [&](const error_code& ec, std::size_t) {
            next_read_done = true;
            result.test_is_true("next read reports EOF", ec == net::error::eof);
            result.test_bin_eq(
               "reply was sent before reporting EOF", received_by(remote), MockChannel::close_notify_record());
         });

         ioc.restart();
         ioc.run();
         result.test_is_true("next read completed", next_read_done);

         results.push_back(result);
      }

      void test_async_write_sends_reply_of_completed_read(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         DeferredWriteAsioStream<CoalescedMockChannel> ssl(ctx, channel<CoalescedMockChannel>(), ioc, test_data());
         ssl.next_layer().inner().connect(remote);
         ssl.next_layer().hold_writes();
         uint8_t data[TEST_DATA_SIZE]{};

         Test::Result result("async write sends the reply a completed read generated alongside application data");

         bool read_done = false;
         bool write_done = false;

         net::async_write(ssl,
                          net::const_buffer(TEST_DATA, TEST_DATA_SIZE),
                          [&](const error_code& ec, std::size_t bytes_transferred) {
                             write_done = true;
                             result.test_is_true("write does not report an error", !ec);
                             result.test_sz_eq("writes the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
                          });

         net::async_read(ssl, net::buffer(data), [&](const error_code& ec, std::size_t bytes_transferred) {
            read_done = true;
            result.test_is_true("read does not report an error", !ec);
            result.test_sz_eq("reads the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
            result.test_is_true("reads the correct data", contains(data, TEST_DATA, TEST_DATA_SIZE));
         });

         // The data is handed out right away; the stalled write will send the reply
         ioc.poll();
         result.test_is_true("[precondition] write is stalled", ssl.next_layer().write_pending());
         result.test_is_true("read completed without waiting for the write", read_done);

         while(ssl.next_layer().write_pending()) {
            ssl.next_layer().complete_write();
            ioc.restart();
            ioc.poll();
         }

         result.test_is_true("write completed", write_done);

         std::vector<uint8_t> expected(TEST_DATA, TEST_DATA + TEST_DATA_SIZE);
         const auto reply = MockChannel::close_notify_record();
         expected.insert(expected.end(), reply.begin(), reply.end());
         result.test_bin_eq("reply was sent by the write", received_by(remote), expected);

         results.push_back(result);
      }

      void test_async_read_waits_for_reply_of_earlier_read(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         DeferredWriteAsioStream<CoalescedMockChannel> ssl(ctx, channel<CoalescedMockChannel>(), ioc, test_data());
         ssl.next_layer().inner().connect(remote);
         ssl.next_layer().hold_writes();
         uint8_t data[TEST_DATA_SIZE]{};

         Test::Result result("async read waits for the reply an earlier read left to a write before reporting EOF");

         bool write_done = false;
         bool first_read_done = false;
         bool second_read_done = false;

         net::async_write(ssl, net::const_buffer(TEST_DATA, TEST_DATA_SIZE), [&](const error_code& ec, std::size_t) {
            write_done = true;
            result.test_is_true("write does not report an error", !ec);
         });

         // The first read hands out the data right away and leaves the reply to the stalled write
         net::async_read(ssl, net::buffer(data), [&](const error_code& ec, std::size_t bytes_transferred) {
            first_read_done = true;
            result.test_is_true("first read does not report an error", !ec);
            result.test_sz_eq("first read reads the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
         });

         ioc.poll();
         result.test_is_true("first read completed", first_read_done);

         // The write completes and takes the reply into flight
         ssl.next_layer().complete_write();
         ioc.restart();
         ioc.poll();
         result.test_is_true("[precondition] reply is in flight", ssl.next_layer().write_pending());

         std::vector<uint8_t> expected(TEST_DATA, TEST_DATA + TEST_DATA_SIZE);
         const auto reply = MockChannel::close_notify_record();
         expected.insert(expected.end(), reply.begin(), reply.end());

         ssl.async_read_some(net::buffer(data), [&](const error_code& ec, std::size_t bytes_transferred) {
            second_read_done = true;
            result.test_is_true("second read reports EOF", ec == net::error::eof);
            result.test_sz_eq("second read didn't transfer anything", bytes_transferred, 0);
            result.test_bin_eq("reply was written before reporting EOF", received_by(remote), expected);
         });

         ioc.restart();
         ioc.poll();
         result.test_is_false("second read did not complete while the reply is in flight", second_read_done);

         ssl.next_layer().complete_write();
         ioc.restart();
         ioc.poll();

         result.test_is_true("write completed", write_done);
         result.test_is_true("second read completed", second_read_done);

         results.push_back(result);
      }

      void test_async_read_retries_reply_left_by_earlier_read(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         DeferredWriteAsioStream<CoalescedMockChannel> ssl(ctx, channel<CoalescedMockChannel>(), ioc, test_data());
         ssl.next_layer().inner().connect(remote);
         ssl.next_layer().hold_writes();
         uint8_t data[TEST_DATA_SIZE]{};

         Test::Result result("async read retries the reply an earlier read left behind until it is written");

         bool read_done = false;

         net::async_read(ssl, net::buffer(data), [&](const error_code& ec, std::size_t bytes_transferred) {
            read_done = true;
            result.test_is_true("read does not report an error", !ec);
            result.test_sz_eq("reads the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
            result.test_is_true("reads the correct data", contains(data, TEST_DATA, TEST_DATA_SIZE));
         });

         ioc.poll();
         result.test_is_true("read completed", read_done);
         result.test_is_false("read did not write to the next layer", ssl.next_layer().write_pending());

         // The next read sends the reply; it fails, and the reply remains queued
         bool next_read_done = false;
         ssl.async_read_some(net::buffer(data), [&](const error_code& ec, std::size_t bytes_transferred) {
            next_read_done = true;
            result.test_is_true("next read reports the failed write", ec == net::error::connection_reset);
            result.test_sz_eq("next read didn't transfer anything", bytes_transferred, 0);
         });

         ioc.restart();
         ioc.poll();
         result.test_is_true("[precondition] reply is being sent", ssl.next_layer().write_pending());
         ssl.next_layer().complete_write(net::error::connection_reset);
         ioc.restart();
         ioc.poll();
         result.test_is_true("next read completed", next_read_done);

         // Once the next layer accepts it, the reply goes out and the peer's close_notify is reported
         bool last_read_done = false;
         ssl.async_read_some(net::buffer(data), [&](const error_code& ec, std::size_t) {
            last_read_done = true;
            result.test_is_true("read after that reports EOF", ec == net::error::eof);
         });

         ioc.restart();
         ioc.poll();
         result.test_is_true("[precondition] reply is being sent again", ssl.next_layer().write_pending());
         ssl.next_layer().complete_write();
         ioc.restart();
         ioc.poll();
         result.test_is_true("last read completed", last_read_done);
         result.test_bin_eq("reply was written once", received_by(remote), MockChannel::close_notify_record());

         results.push_back(result);
      }

      void test_sync_read_hands_out_data_before_sending_reply(std::vector<Test::Result>& results) {
         net::io_context ioc;
         // the first operation (the read) succeeds, every operation after it fails
         FailCount fc{2, net::error::connection_reset};
         TestStream remote{ioc};

         const auto ctx = get_context();
         CoalescedAsioStream ssl(ctx, ioc, fc, test_data());
         ssl.next_layer().connect(remote);

         uint8_t buf[TEST_DATA_SIZE];
         error_code ec;

         const auto bytes_transferred = ssl.read_some(net::mutable_buffer(buf, sizeof(buf)), ec);

         Test::Result result("sync read_some hands out application data before sending the reply generated alongside");
         result.test_is_true("does not report an error", !ec);
         result.test_sz_eq("reads the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
         result.test_is_true("reads the correct data", contains(buf, TEST_DATA, TEST_DATA_SIZE));
         result.test_sz_eq("reply was not sent yet", ssl.next_layer().nwrite(), 0);

         // The next read sends the reply, which fails
         const auto next = ssl.read_some(net::mutable_buffer(buf, sizeof(buf)), ec);
         result.test_is_true("next read reports the failed write", ec == net::error::connection_reset);
         result.test_sz_eq("next read didn't transfer anything", next, 0);

         results.push_back(result);
      }

      void test_async_write_retries_remainder_of_failed_write(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         DeferredWriteAsioStream<MockChannel> ssl(ctx, channel<MockChannel>(), ioc, test_data());
         ssl.next_layer().inner().connect(remote);
         ssl.next_layer().hold_writes();

         Test::Result result("async write retries the records a failed write did not get through");

         bool first_write_done = false;
         bool second_write_done = false;

         net::async_write(ssl,
                          net::const_buffer(TEST_DATA, TEST_DATA_SIZE),
                          [&](const error_code& ec, std::size_t bytes_transferred) {
                             first_write_done = true;
                             result.test_is_true("first write reports the error", ec == net::error::connection_reset);
                             result.test_sz_eq("first write processed its data", bytes_transferred, TEST_DATA_SIZE);
                          });

         // The next layer accepts part of the records, then fails
         result.test_is_true("[precondition] write is stalled", ssl.next_layer().write_pending());
         ssl.next_layer().complete_write({}, TEST_DATA_SIZE / 3);
         ioc.poll();
         result.test_is_true("[precondition] the rest is being written", ssl.next_layer().write_pending());
         ssl.next_layer().complete_write(net::error::connection_reset);
         ioc.restart();
         ioc.poll();
         result.test_is_true("first write completed", first_write_done);
         result.test_sz_eq("part of the records was written", received_by(remote).size(), TEST_DATA_SIZE / 3);

         // The second write sends the rest first, then its own records
         net::async_write(ssl,
                          net::const_buffer(TEST_DATA, TEST_DATA_SIZE),
                          [&](const error_code& ec, std::size_t bytes_transferred) {
                             second_write_done = true;
                             result.test_is_true("second write does not report an error", !ec);
                             result.test_sz_eq("second write processed its data", bytes_transferred, TEST_DATA_SIZE);
                          });

         while(ssl.next_layer().write_pending()) {
            ssl.next_layer().complete_write();
            ioc.restart();
            ioc.poll();
         }
         result.test_is_true("second write completed", second_write_done);

         std::vector<uint8_t> expected(TEST_DATA, TEST_DATA + TEST_DATA_SIZE);
         expected.insert(expected.end(), TEST_DATA, TEST_DATA + TEST_DATA_SIZE);
         result.test_bin_eq("records were written once and in order", received_by(remote), expected);

         results.push_back(result);
      }

      void test_sync_read_sends_remainder_of_failed_write(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         DeferredWriteAsioStream<MockChannel> ssl(ctx, channel<MockChannel>(), ioc, test_data());
         ssl.next_layer().inner().connect(remote);
         ssl.next_layer().hold_writes();
         uint8_t data[TEST_DATA_SIZE]{};

         Test::Result result("sync read_some sends the records a failed async write did not get through");

         bool write_done = false;

         net::async_write(ssl,
                          net::const_buffer(TEST_DATA, TEST_DATA_SIZE),
                          [&](const error_code& ec, std::size_t bytes_transferred) {
                             write_done = true;
                             result.test_is_true("write reports the error", ec == net::error::connection_reset);
                             result.test_sz_eq("write processed its data", bytes_transferred, TEST_DATA_SIZE);
                          });

         // The next layer accepts part of the records, then fails
         result.test_is_true("[precondition] write is stalled", ssl.next_layer().write_pending());
         ssl.next_layer().complete_write({}, TEST_DATA_SIZE / 3);
         ioc.poll();
         result.test_is_true("[precondition] the rest is being written", ssl.next_layer().write_pending());
         ssl.next_layer().complete_write(net::error::connection_reset);
         ioc.restart();
         ioc.poll();
         result.test_is_true("write completed", write_done);

         // The read sends the rest before consuming input
         error_code ec;
         const auto bytes_transferred = ssl.read_some(net::buffer(data), ec);
         result.test_is_true("read does not report an error", !ec);
         result.test_sz_eq("reads the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
         result.test_is_true("reads the correct data", contains(data, TEST_DATA, TEST_DATA_SIZE));
         result.test_bin_eq("records were written once and in order",
                            received_by(remote),
                            std::vector<uint8_t>(TEST_DATA, TEST_DATA + TEST_DATA_SIZE));

         results.push_back(result);
      }

      /**
       * Drives concurrent read and write operations with random transport
       * events (stalled, partial, failed and cancelled writes, input in random
       * chunks) and checks the invariants of the output queue: the transport
       * receives the emitted records in order and without duplicates, a write
       * completes only once its records are written, and the write flag is
       * clear while no operation is outstanding.
       */
      Test::Result random_interleaving(uint32_t seed) {
         Test::Result result("randomized interleaving of reads, writes and transport events (seed " +
                             std::to_string(seed) + ")");
         std::mt19937 rng(seed);

         net::io_context ioc;
         TestStream remote{ioc};
         const auto ctx = get_context();
         DeferredWriteAsioStream<NumberedMockChannel> ssl(
            ctx,
            [&rng](const std::shared_ptr<Botan::TLS::Callbacks>& core) {
               return std::make_unique<NumberedMockChannel>(core, rng);
            },
            ioc);
         ssl.next_layer().inner().connect(remote);
         ssl.next_layer().hold_writes();
         const auto& channel = *ssl.native_handle();

         uint8_t read_buffer[64];
         const std::vector<uint8_t> plaintext(32, 'x');
         net::cancellation_signal read_cancel;
         net::cancellation_signal write_cancel;
         bool read_outstanding = false;
         bool write_outstanding = false;
         size_t reads = 0;
         size_t writes = 0;

         const auto acceptable = [](const error_code& ec) {
            return !ec || ec == net::error::operation_aborted || ec == net::error::connection_reset;
         };

         const auto check_invariants = [&](const std::string& when) {
            const auto received = received_by(remote);
            const auto& emitted = channel.emitted();
            if(received.size() > emitted.size() || !std::equal(received.begin(), received.end(), emitted.begin())) {
               result.test_failure("transport did not receive a prefix of the emitted records " + when);
            }
            if(!read_outstanding && !write_outstanding) {
               if(ssl.writing()) {
                  result.test_failure("write flag is set while idle " + when);
               }
               if(ssl.next_layer().write_pending()) {
                  result.test_failure("a transport write is pending while idle " + when);
               }
            }
         };

         // Written by the peer (unlike append(), this wakes up a pending read)
         const auto feed_input = [&] {
            const std::string chunk(1 + rng() % 100, 'i');
            error_code feed_ec;
            remote.write_some(net::buffer(chunk), feed_ec);
            if(feed_ec) {
               result.test_failure("feeding input failed: " + feed_ec.message());
            }
         };

         const size_t steps = 400;
         for(size_t step = 0; step < steps; ++step) {
            const std::string when = "after step " + std::to_string(step);

            switch(rng() % 8) {
               case 0:
               case 1:
                  if(!read_outstanding) {
                     read_outstanding = true;
                     ++reads;
                     ssl.async_read_some(
                        net::buffer(read_buffer),
                        net::bind_cancellation_slot(read_cancel.slot(), [&, when](const error_code& ec, std::size_t n) {
                           read_outstanding = false;
                           if(!acceptable(ec)) {
                              result.test_failure("read reports an unexpected error " + when + ": " + ec.message());
                           }
                           if(!ec && n == 0) {
                              result.test_failure("read completes without data or error " + when);
                           }
                        }));
                  }
                  break;
               case 2:
               case 3:
                  if(!write_outstanding) {
                     write_outstanding = true;
                     ++writes;
                     ssl.async_write_some(
                        net::buffer(plaintext),
                        net::bind_cancellation_slot(
                           write_cancel.slot(), [&, when](const error_code& ec, std::size_t n) {
                              write_outstanding = false;
                              if(!acceptable(ec)) {
                                 result.test_failure("write reports an unexpected error " + when + ": " + ec.message());
                              }
                              if(!ec && n != plaintext.size()) {
                                 result.test_failure("write completes without processing its data " + when);
                              }
                              if(!ec && received_by(remote).size() < channel.last_send_end()) {
                                 result.test_failure("write completes before its records are written " + when);
                              }
                           }));
                  }
                  break;
               case 4:
                  feed_input();
                  break;
               case 5:
                  if(ssl.next_layer().write_pending()) {
                     switch(rng() % 4) {
                        case 0:
                           ssl.next_layer().complete_write(net::error::connection_reset);
                           break;
                        case 1:
                           ssl.next_layer().complete_write({}, 1 + rng() % 16);
                           break;
                        default:
                           ssl.next_layer().complete_write();
                           break;
                     }
                  }
                  break;
               case 6:
                  if(rng() % 2 == 0) {
                     read_cancel.emit(net::cancellation_type::terminal);
                  } else {
                     write_cancel.emit(net::cancellation_type::terminal);
                  }
                  break;
               default:
                  break;
            }

            ioc.restart();
            ioc.poll();
            check_invariants(when);
         }

         // Let the outstanding operations finish: the transport accepts everything, input keeps coming
         for(size_t i = 0; i < 100 && (read_outstanding || write_outstanding || ssl.next_layer().write_pending());
             ++i) {
            if(ssl.next_layer().write_pending()) {
               ssl.next_layer().complete_write();
            }
            if(read_outstanding) {
               feed_input();
            }
            ioc.restart();
            ioc.poll();
            check_invariants("while finishing");
         }

         result.test_is_false("all reads completed", read_outstanding);
         result.test_is_false("all writes completed", write_outstanding);
         result.test_is_true("[precondition] reads and writes were started", reads > 10 && writes > 10);

         // Whatever a failed write left behind goes out with a final one
         error_code ec;
         ssl.write_some(net::buffer(plaintext), ec);
         result.test_is_true("final write does not report an error", !ec);
         result.test_is_false("write flag is clear at the end", ssl.writing());
         result.test_bin_eq("transport received exactly the emitted records", received_by(remote), channel.emitted());

         return result;
      }

      void test_random_interleaving(std::vector<Test::Result>& results) {
         for(uint32_t seed = 1; seed <= 8; ++seed) {
            results.push_back(random_interleaving(seed));
         }
      }

      void test_operations_before_handshake(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         LateMockAsioStream ssl(ctx, ioc, test_data());
         ssl.next_layer().connect(remote);
         uint8_t buf[TEST_DATA_SIZE];
         error_code ec;

         Test::Result result("operations before the handshake are refused without breaking the stream");

         const auto read = ssl.read_some(net::buffer(buf), ec);
         result.test_is_true("read_some is refused", ec == Botan::ErrorType::InvalidObjectState);
         result.test_sz_eq("read_some didn't transfer anything", read, 0);

         const auto written = ssl.write_some(net::const_buffer(TEST_DATA, TEST_DATA_SIZE), ec);
         result.test_is_true("write_some is refused", ec == Botan::ErrorType::InvalidObjectState);
         result.test_sz_eq("write_some didn't transfer anything", written, 0);

         ssl.shutdown(ec);
         result.test_is_true("shutdown is refused", ec == Botan::ErrorType::InvalidObjectState);

         result.test_sz_eq("nothing was read from the next layer", ssl.next_layer().nread(), 0);
         result.test_sz_eq("nothing was written to the next layer", ssl.next_layer().nwrite(), 0);

         bool read_done = false;
         ssl.async_read_some(net::buffer(buf), [&](const error_code& read_ec, std::size_t bytes_transferred) {
            read_done = true;
            result.test_is_true("async_read_some is refused", read_ec == Botan::ErrorType::InvalidObjectState);
            result.test_sz_eq("async_read_some didn't transfer anything", bytes_transferred, 0);
         });

         bool write_done = false;
         ssl.async_write_some(net::const_buffer(TEST_DATA, TEST_DATA_SIZE),
                              [&](const error_code& write_ec, std::size_t bytes_transferred) {
                                 write_done = true;
                                 result.test_is_true("async_write_some is refused",
                                                     write_ec == Botan::ErrorType::InvalidObjectState);
                                 result.test_sz_eq("async_write_some didn't transfer anything", bytes_transferred, 0);
                              });

         bool shutdown_done = false;
         ssl.async_shutdown([&](const error_code& shutdown_ec) {
            shutdown_done = true;
            result.test_is_true("async_shutdown is refused", shutdown_ec == Botan::ErrorType::InvalidObjectState);
         });

         ioc.run();
         result.test_is_true("async_read_some completed", read_done);
         result.test_is_true("async_write_some completed", write_done);
         result.test_is_true("async_shutdown completed", shutdown_done);
         result.test_is_true("still nothing was written to the next layer", remote.str().empty());

         // None of that left anything behind: the handshake works and finds the input intact
         ssl.create_native_handle();
         ssl.handshake(Botan::TLS::Connection_Side::Client, ec);
         result.test_is_true("handshake does not report an error", !ec);
         result.test_is_true("handshake feeds data into channel until active", ssl.native_handle()->is_active());

         const auto bytes_transferred = ssl.read_some(net::buffer(buf), ec);
         result.test_is_true("read_some does not report an error afterwards", !ec);
         result.test_sz_eq("read_some reads the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
         result.test_is_true("read_some reads the correct data", contains(buf, TEST_DATA, TEST_DATA_SIZE));

         results.push_back(result);
      }

      void test_sync_write_some_partial_failure(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         PartialSendAsioStream ssl(ctx, ioc, test_data());
         ssl.next_layer().connect(remote);
         ssl.handshake(Botan::TLS::Connection_Side::Client);
         error_code ec;

         Test::Result result(
            "sync write_some discards the records of a partially failed send and refuses further output");
         result.test_is_true("[precondition] connection is active", ssl.native_handle()->is_active());

         const auto bytes_transferred = ssl.write_some(net::const_buffer(TEST_DATA, TEST_DATA_SIZE), ec);
         result.test_is_true("reports the error", ec == Botan::ErrorType::InternalError);
         result.test_sz_eq("didn't transfer anything", bytes_transferred, 0);
         result.test_is_true("nothing was written", remote.str().empty());

         const auto again = ssl.write_some(net::const_buffer(TEST_DATA, TEST_DATA_SIZE), ec);
         result.test_is_true("another write reports the error again", ec == Botan::ErrorType::InternalError);
         result.test_sz_eq("another write didn't transfer anything", again, 0);

         const auto large = ssl.write_some(too_large_to_flatten(), ec);
         result.test_is_true("a write too large to flatten reports the error again",
                             ec == Botan::ErrorType::InternalError);
         result.test_sz_eq("a write too large to flatten didn't transfer anything", large, 0);

         ssl.shutdown(ec);
         result.test_is_true("shutdown reports the error again", ec == Botan::ErrorType::InternalError);
         result.test_is_true("still nothing was written", remote.str().empty());

         results.push_back(result);
      }

      void test_sync_write_some_before_handshake(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         InactiveSendAsioStream ssl(ctx, ioc, test_data());
         ssl.next_layer().connect(remote);
         error_code ec;

         Test::Result result("sync write_some refused before the handshake does not break the stream");

         const auto refused = ssl.write_some(net::const_buffer(TEST_DATA, TEST_DATA_SIZE), ec);
         result.test_is_true("write before the handshake is refused", ec == Botan::ErrorType::InvalidObjectState);
         result.test_sz_eq("write before the handshake didn't transfer anything", refused, 0);

         ssl.handshake(Botan::TLS::Connection_Side::Client, ec);
         result.test_is_true("handshake does not report an error", !ec);

         const auto bytes_transferred = ssl.write_some(net::const_buffer(TEST_DATA, TEST_DATA_SIZE), ec);
         result.test_is_true("write after the handshake does not report an error", !ec);
         result.test_sz_eq("write after the handshake transfers the data", bytes_transferred, TEST_DATA_SIZE);
         result.test_bin_eq(
            "the data was written", received_by(remote), std::vector<uint8_t>(TEST_DATA, TEST_DATA + TEST_DATA_SIZE));

         results.push_back(result);
      }

      void test_async_write_partial_failure(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         PartialSendAsioStream ssl(ctx, ioc, test_data());
         ssl.next_layer().connect(remote);
         ssl.handshake(Botan::TLS::Connection_Side::Client);

         Test::Result result("async write discards the records of a partially failed send and refuses further output");
         result.test_is_true("[precondition] connection is active", ssl.native_handle()->is_active());

         bool write_done = false;
         bool shutdown_done = false;

         net::async_write(ssl,
                          net::const_buffer(TEST_DATA, TEST_DATA_SIZE),
                          [&](const error_code& ec, std::size_t bytes_transferred) {
                             write_done = true;
                             result.test_is_true("reports the error", ec == Botan::ErrorType::InternalError);
                             result.test_sz_eq("didn't transfer anything", bytes_transferred, 0);
                             result.test_is_true("nothing was written", remote.str().empty());

                             ssl.async_shutdown([&](const error_code& ec2) {
                                shutdown_done = true;
                                result.test_is_true("shutdown reports the error again",
                                                    ec2 == Botan::ErrorType::InternalError);
                                result.test_is_true("still nothing was written", remote.str().empty());
                             });
                          });

         ioc.run();
         result.test_is_true("write completed", write_done);
         result.test_is_true("shutdown completed", shutdown_done);

         results.push_back(result);
      }

      void test_cancellation_after_completion(std::vector<Test::Result>& results) {
         net::io_context ioc;
         net::cancellation_signal read_signal;
         net::cancellation_signal write_signal;
         uint8_t data[TEST_DATA_SIZE]{};

         Test::Result result("cancellation emitted after the operation completed and the stream is gone");

         bool read_done = false;
         bool write_done = false;

         {
            TestStream remote{ioc};
            const auto ctx = get_context();
            const auto record = Botan::hex_decode("15030300020164");
            DeferredWriteAsioStream<EmittingMockChannel> ssl(ctx, emitting(record), ioc, test_data());
            ssl.next_layer().inner().connect(remote);
            ssl.next_layer().inner().append(test_data());
            ssl.next_layer().inner().read_size(TEST_DATA_SIZE);

            // A read whose last step is a read on the next layer
            net::async_read(ssl,
                            net::buffer(data),
                            net::bind_cancellation_slot(read_signal.slot(), [&](const error_code& ec, std::size_t) {
                               read_done = true;
                               result.test_is_true("read does not report an error", !ec);
                            }));

            // A write that first waits on the timer for the read's write to finish
            net::post(ioc, [&] {
               net::async_write(
                  ssl,
                  net::const_buffer(TEST_DATA, TEST_DATA_SIZE),
                  net::bind_cancellation_slot(write_signal.slot(), [&](const error_code& ec, std::size_t) {
                     write_done = true;
                     result.test_is_true("write does not report an error", !ec);
                  }));
            });

            ioc.run();
            result.test_is_true("read completed", read_done);
            result.test_is_true("write completed", write_done);
         }

         // Both operations are done and the stream was destroyed; a late cancellation must not reach anything
         read_signal.emit(net::cancellation_type::terminal);
         write_signal.emit(net::cancellation_type::terminal);
         result.test_success("late cancellation is ignored");

         results.push_back(result);
      }

      void test_sync_read_sends_reply_left_by_async_read(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         DeferredWriteAsioStream<CoalescedMockChannel> ssl(ctx, channel<CoalescedMockChannel>(), ioc, test_data());
         ssl.next_layer().inner().connect(remote);
         ssl.next_layer().hold_writes();
         uint8_t data[TEST_DATA_SIZE]{};

         Test::Result result("sync read_some sends the reply an async read left behind");

         bool read_done = false;

         net::async_read(ssl, net::buffer(data), [&](const error_code& ec, std::size_t bytes_transferred) {
            read_done = true;
            result.test_is_true("async read does not report an error", !ec);
            result.test_sz_eq("async read reads the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
         });

         ioc.poll();
         result.test_is_true("async read completed", read_done);
         result.test_is_false("async read did not write to the next layer", ssl.next_layer().write_pending());
         result.test_is_true("nothing was written yet", remote.str().empty());

         // The sync read sends the queued reply, then reports the peer's close_notify
         error_code ec;
         const auto next = ssl.read_some(net::buffer(data), ec);
         result.test_is_true("sync read reports EOF", ec == net::error::eof);
         result.test_sz_eq("sync read didn't transfer anything", next, 0);
         result.test_bin_eq("reply was written", received_by(remote), MockChannel::close_notify_record());

         results.push_back(result);
      }

      void test_async_read_cancelled_while_sending_reply(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         DeferredWriteAsioStream<ClosingMockChannel> ssl(ctx, channel<ClosingMockChannel>(), ioc, test_data());
         ssl.next_layer().inner().connect(remote);
         ssl.next_layer().hold_writes();
         uint8_t data[TEST_DATA_SIZE]{};
         net::cancellation_signal cancel;

         Test::Result result("async read cancelled while sending its close_notify reply");

         bool read_done = false;

         ssl.async_read_some(
            net::buffer(data),
            net::bind_cancellation_slot(cancel.slot(), [&](const error_code& ec, std::size_t bytes_transferred) {
               read_done = true;
               result.test_is_true("read was cancelled", ec == net::error::operation_aborted);
               result.test_sz_eq("didn't transfer anything", bytes_transferred, 0);
            }));

         ioc.poll();
         result.test_is_true("[precondition] reply is being sent", ssl.next_layer().write_pending());

         cancel.emit(net::cancellation_type::terminal);
         ioc.restart();
         ioc.poll();
         result.test_is_true("read completed", read_done);

         // The reply stays queued: the next read sends it and then reports the peer's close_notify
         bool next_read_done = false;
         ssl.async_read_some(net::buffer(data), [&](const error_code& ec, std::size_t) {
            next_read_done = true;
            result.test_is_true("next read reports EOF", ec == net::error::eof);
         });

         ioc.restart();
         ioc.poll();
         result.test_is_true("[precondition] reply is being sent again", ssl.next_layer().write_pending());
         ssl.next_layer().complete_write();
         ioc.restart();
         ioc.poll();
         result.test_is_true("next read completed", next_read_done);
         result.test_bin_eq("reply was written once", received_by(remote), MockChannel::close_notify_record());

         results.push_back(result);
      }

      void test_async_write_cancelled_while_sending_read_reply(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         DeferredWriteAsioStream<ClosingMockChannel> ssl(ctx, channel<ClosingMockChannel>(), ioc, test_data());
         ssl.next_layer().inner().connect(remote);
         ssl.next_layer().hold_writes();
         uint8_t data[TEST_DATA_SIZE]{};
         net::cancellation_signal cancel;

         Test::Result result("async write cancelled while sending a read's close_notify reply");

         bool write_done = false;
         bool read_done = false;

         net::async_write(
            ssl,
            net::const_buffer(TEST_DATA, TEST_DATA_SIZE),
            net::bind_cancellation_slot(cancel.slot(), [&](const error_code& ec, std::size_t bytes_transferred) {
               write_done = true;
               result.test_is_true("write was cancelled", ec == net::error::operation_aborted);
               result.test_sz_eq("write processed its data", bytes_transferred, TEST_DATA_SIZE);
            }));

         ssl.async_read_some(net::buffer(data), [&](const error_code& ec, std::size_t bytes_transferred) {
            read_done = true;
            result.test_is_true("read reports EOF", ec == net::error::eof);
            result.test_sz_eq("read didn't transfer anything", bytes_transferred, 0);
         });

         ioc.poll();

         // The write's own data goes out, then the write sends the reply the read generated
         ssl.next_layer().complete_write();
         ioc.restart();
         ioc.poll();
         result.test_is_true("[precondition] write is sending the reply", ssl.next_layer().write_pending());
         result.test_is_false("write did not complete yet", write_done);

         cancel.emit(net::cancellation_type::terminal);
         ioc.restart();
         ioc.poll();
         result.test_is_true("write completed", write_done);

         // The read sends the reply itself before reporting EOF
         result.test_is_true("[precondition] read is sending the reply", ssl.next_layer().write_pending());
         result.test_is_false("read did not complete yet", read_done);
         ssl.next_layer().complete_write();
         ioc.restart();
         ioc.poll();
         result.test_is_true("read completed", read_done);

         std::vector<uint8_t> expected(TEST_DATA, TEST_DATA + TEST_DATA_SIZE);
         const auto reply = MockChannel::close_notify_record();
         expected.insert(expected.end(), reply.begin(), reply.end());
         result.test_bin_eq("records were written once and in order", received_by(remote), expected);

         results.push_back(result);
      }

      void test_sync_operations_while_async_write_in_flight(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         DeferredWriteAsioStream<CoalescedMockChannel> ssl(ctx, channel<CoalescedMockChannel>(), ioc, test_data());
         ssl.next_layer().inner().connect(remote);
         ssl.next_layer().hold_writes();
         uint8_t data[TEST_DATA_SIZE]{};

         Test::Result result("sync operations while an async write is in flight");

         bool write_done = false;

         net::async_write(ssl,
                          net::const_buffer(TEST_DATA, TEST_DATA_SIZE),
                          [&](const error_code& ec, std::size_t bytes_transferred) {
                             write_done = true;
                             result.test_is_true("write does not report an error", !ec);
                             result.test_sz_eq("writes the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
                          });
         result.test_is_true("[precondition] write is stalled", ssl.next_layer().write_pending());

         error_code ec;
         ssl.shutdown(ec);
         result.test_is_true("shutdown is refused", ec == net::error::already_started);

         const auto written = ssl.write_some(net::const_buffer(TEST_DATA, TEST_DATA_SIZE), ec);
         result.test_is_true("write_some is refused", ec == net::error::already_started);
         result.test_sz_eq("write_some didn't transfer anything", written, 0);

         const auto refused = ssl.read_some(net::buffer(data), ec);
         result.test_is_true("read_some is refused", ec == net::error::already_started);
         result.test_sz_eq("read_some didn't transfer anything", refused, 0);

         while(ssl.next_layer().write_pending()) {
            ssl.next_layer().complete_write();
            ioc.restart();
            ioc.poll();
         }
         result.test_is_true("write completed", write_done);

         // With the write done, the sync read works again; its reply is left to the next read
         const auto read = ssl.read_some(net::buffer(data), ec);
         result.test_is_true("read_some does not report an error afterwards", !ec);
         result.test_sz_eq("read_some reads the correct amount of data", read, TEST_DATA_SIZE);
         result.test_is_true("read_some reads the correct data", contains(data, TEST_DATA, TEST_DATA_SIZE));

         const auto next = ssl.read_some(net::buffer(data), ec);
         result.test_is_true("next read_some reports EOF", ec == net::error::eof);
         result.test_sz_eq("next read_some didn't transfer anything", next, 0);

         std::vector<uint8_t> expected(TEST_DATA, TEST_DATA + TEST_DATA_SIZE);
         const auto reply = MockChannel::close_notify_record();
         expected.insert(expected.end(), reply.begin(), reply.end());
         result.test_bin_eq("the reply was sent after the write", received_by(remote), expected);

         results.push_back(result);
      }

      void test_sync_read_after_output_failure(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         MockAsioStream<PartialSendClosingMockChannel> ssl(ctx, ioc, test_data());
         ssl.next_layer().connect(remote);
         activate(ssl);
         // the next record makes the channel answer with a close_notify
         ssl.next_layer().append(test_data());
         uint8_t buf[TEST_DATA_SIZE];
         error_code ec;

         Test::Result result("sync read_some discards the reply after an output failure");

         ssl.write_some(net::const_buffer(TEST_DATA, TEST_DATA_SIZE), ec);
         result.test_is_true("[precondition] write fails", ec == Botan::ErrorType::InternalError);

         const auto bytes_transferred = ssl.read_some(net::buffer(buf), ec);
         result.test_is_true("read reports the close_notify", ec == net::error::eof);
         result.test_sz_eq("read didn't transfer anything", bytes_transferred, 0);
         result.test_is_true("nothing was written", remote.str().empty());

         results.push_back(result);
      }

      void test_async_read_after_output_failure(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         MockAsioStream<PartialSendClosingMockChannel> ssl(ctx, ioc, test_data());
         ssl.next_layer().connect(remote);
         activate(ssl);
         // the next record makes the channel answer with a close_notify
         ssl.next_layer().append(test_data());
         uint8_t buf[TEST_DATA_SIZE];
         error_code ec;

         Test::Result result("async read_some discards the reply after an output failure");

         ssl.write_some(net::const_buffer(TEST_DATA, TEST_DATA_SIZE), ec);
         result.test_is_true("[precondition] write fails", ec == Botan::ErrorType::InternalError);

         bool read_done = false;
         ssl.async_read_some(net::buffer(buf), [&](const error_code& read_ec, std::size_t bytes_transferred) {
            read_done = true;
            result.test_is_true("read reports the close_notify", read_ec == net::error::eof);
            result.test_sz_eq("read didn't transfer anything", bytes_transferred, 0);
            result.test_is_true("nothing was written", remote.str().empty());
         });

         ioc.run();
         result.test_is_true("read completed", read_done);

         results.push_back(result);
      }

      void test_write_after_failed_read_is_refused(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         MockAsioStream<FailingReceiveMockChannel> ssl(ctx, ioc, test_data());
         ssl.next_layer().connect(remote);
         activate(ssl);
         ssl.next_layer().append(test_data());
         uint8_t buf[TEST_DATA_SIZE];
         error_code ec;

         Test::Result result("output is refused after the TLS implementation failed on received data");

         const auto bytes_transferred = ssl.read_some(net::buffer(buf), ec);
         result.test_is_true("read reports the error", ec == Botan::TLS::Alert::UnexpectedMessage);
         result.test_sz_eq("read didn't transfer anything", bytes_transferred, 0);
         result.test_is_true("[precondition] connection is still active", ssl.native_handle()->is_active());

         const auto written = ssl.write_some(net::const_buffer(TEST_DATA, TEST_DATA_SIZE), ec);
         result.test_is_true("write reports the error again", ec == Botan::TLS::Alert::UnexpectedMessage);
         result.test_sz_eq("write didn't transfer anything", written, 0);
         result.test_is_true("nothing was written", remote.str().empty());

         results.push_back(result);
      }

      void test_sync_write_zero_buffer(std::vector<Test::Result>& results) {
         net::io_context ioc;
         // any write to the next layer would fail right away
         FailCount fc{0, net::error::no_recovery};
         TestStream remote{ioc};

         const auto ctx = get_context();
         AsioStream ssl(ctx, ioc, fc);
         ssl.next_layer().connect(remote);
         // data waiting to be sent is not flushed by a zero-byte write either
         ssl.native_handle()->send(TEST_DATA);
         error_code ec;

         const auto bytes_transferred = ssl.write_some(net::const_buffer(), ec);

         Test::Result result("sync write_some from zero-size buffer");
         result.test_sz_eq("writes the correct amount of data", bytes_transferred, 0);
         result.test_is_true("does not report an error", !ec);
         result.test_sz_eq("does not write to the next layer", ssl.next_layer().nwrite(), 0);

         results.push_back(result);
      }

      void test_async_write_zero_buffer(std::vector<Test::Result>& results) {
         net::io_context ioc;
         // any write to the next layer would fail right away
         FailCount fc{0, net::error::no_recovery};
         TestStream remote{ioc};

         const auto ctx = get_context();
         AsioStream ssl(ctx, ioc, fc);
         ssl.next_layer().connect(remote);
         // data waiting to be sent is not flushed by a zero-byte write either
         ssl.native_handle()->send(TEST_DATA);

         Test::Result result("async write_some from zero-size buffer");
         bool write_done = false;

         ssl.async_write_some(net::const_buffer(), [&](const error_code& ec, std::size_t bytes_transferred) {
            write_done = true;
            result.test_sz_eq("writes the correct amount of data", bytes_transferred, 0);
            result.test_is_true("does not report an error", !ec);
            result.test_is_true("nothing was written", remote.str().empty());
         });

         ioc.run();
         result.test_is_true("write completed", write_done);

         results.push_back(result);
      }

      void test_sync_write_some_flatten_failure(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         AsioStream ssl(ctx, ioc, test_data());
         ssl.next_layer().connect(remote);
         ssl.handshake(Botan::TLS::Connection_Side::Client);
         error_code ec;

         Test::Result result("sync write_some of a buffer sequence too large to flatten does not break the stream");
         result.test_is_true("[precondition] connection is active", ssl.native_handle()->is_active());

         const auto refused = ssl.write_some(too_large_to_flatten(), ec);
         result.test_is_true("write reports the allocation failure", ec.failed());
         result.test_sz_eq("write didn't transfer anything", refused, 0);
         result.test_is_true("nothing was written", remote.str().empty());

         const auto bytes_transferred = ssl.write_some(net::const_buffer(TEST_DATA, TEST_DATA_SIZE), ec);
         result.test_is_true("next write does not report an error", !ec);
         result.test_sz_eq("next write transfers the data", bytes_transferred, TEST_DATA_SIZE);
         result.test_bin_eq(
            "the data was written", received_by(remote), std::vector<uint8_t>(TEST_DATA, TEST_DATA + TEST_DATA_SIZE));

         results.push_back(result);
      }

      void test_swallowed_alert_emit_failure(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         MockAsioStream<SwallowingMockChannel> ssl(ctx, ioc, test_data());
         ssl.next_layer().connect(remote);
         activate(ssl);
         // the channel answers the next record with an alert it cannot buffer
         ssl.next_layer().append(test_data());
         uint8_t buf[TEST_DATA_SIZE];
         error_code ec;

         Test::Result result("output is refused after the TLS implementation swallowed a failure to emit an alert");

         const auto bytes_transferred = ssl.read_some(net::buffer(buf), ec);
         result.test_is_true("read reports the failure", ec.failed());
         result.test_sz_eq("read didn't transfer anything", bytes_transferred, 0);
         result.test_is_true("[precondition] connection is still active", ssl.native_handle()->is_active());
         const auto read_ec = ec;

         const auto written = ssl.write_some(net::const_buffer(TEST_DATA, TEST_DATA_SIZE), ec);
         result.test_is_true("write reports the failure again", ec == read_ec);
         result.test_sz_eq("write didn't transfer anything", written, 0);
         result.test_is_true("nothing was written", remote.str().empty());

         results.push_back(result);
      }

      void test_sync_shutdown_swallowed_emit_failure(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         MockAsioStream<SwallowingMockChannel> ssl(ctx, ioc, test_data());
         ssl.next_layer().connect(remote);
         activate(ssl);
         error_code ec;

         Test::Result result("sync shutdown reports a swallowed failure to emit the close_notify");

         ssl.shutdown(ec);
         result.test_is_true("shutdown reports the failure", ec.failed());
         result.test_is_true("nothing was written", remote.str().empty());
         result.test_is_false("[precondition] connection is inactive after close", ssl.native_handle()->is_active());
         const auto first_ec = ec;

         ssl.shutdown(ec);
         result.test_is_true("another shutdown reports the failure again", ec == first_ec);
         result.test_is_true("still nothing was written", remote.str().empty());

         results.push_back(result);
      }

      void test_async_read_zero_buffer(std::vector<Test::Result>& results) {
         net::io_context ioc;
         // any read from or write to the next layer would fail right away
         FailCount fc{0, net::error::no_recovery};
         TestStream remote{ioc};

         const auto ctx = get_context();
         AsioStream ssl(ctx, ioc, fc);
         ssl.next_layer().connect(remote);
         // data waiting to be sent is not flushed by a zero-byte read either
         ssl.native_handle()->send(TEST_DATA);
         uint8_t data[TEST_DATA_SIZE];

         Test::Result result("async read_some into zero-size buffer");

         auto read_handler = [&](const error_code& ec, std::size_t bytes_transferred) {
            result.test_sz_eq("reads the correct amount of data", bytes_transferred, 0);
            result.test_is_true("does not report an error", !ec);
            result.test_sz_eq("does not write to the next layer", ssl.next_layer().nwrite(), 0);
         };

         ssl.async_read_some(net::mutable_buffer(data, std::size_t(0)), read_handler);

         ioc.run();
         results.push_back(result);
      }

      void test_sync_write_some_success(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         AsioStream ssl(ctx, ioc);
         ssl.next_layer().connect(remote);
         error_code ec;

         const auto bytes_transferred = net::write(ssl, net::const_buffer(TEST_DATA, TEST_DATA_SIZE), ec);

         Test::Result result("sync write_some success");
         result.test_is_true("writes the correct data", remote.str() == test_data());
         result.test_sz_eq("writes the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
         result.test_is_true("does not report an error", !ec);

         results.push_back(result);
      }

      void test_sync_no_handshake(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         Botan::TLS::Stream<TestStream> ssl(ctx, ioc);  // Note that we're not using MockChannel here
         ssl.next_layer().connect(remote);
         error_code ec;

         net::write(ssl, net::const_buffer(TEST_DATA, TEST_DATA_SIZE), ec);

         Test::Result result("sync write_some without handshake fails gracefully");
         result.test_is_true("reports an error", ec.failed());

         results.push_back(result);
      }

      void test_sync_write_some_buffer_sequence(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         AsioStream ssl(ctx, ioc);
         ssl.next_layer().connect(remote);
         error_code ec;

         // this should be Botan::TLS::MAX_PLAINTEXT_SIZE + 1024 + 1
         std::array<uint8_t, 17 * 1024 + 1> random_data{};
         random_data.fill('4');  // chosen by fair dice roll
         random_data.back() = '5';

         std::vector<net::const_buffer> data;
         data.emplace_back(net::const_buffer(random_data.data(), 1));
         for(std::size_t i = 1; i < random_data.size(); i += 1024) {
            data.emplace_back(net::const_buffer(random_data.data() + i, 1024));
         }

         const auto bytes_transferred = net::write(ssl, data, ec);

         Test::Result result("sync write_some buffer sequence");

         result.test_is_true("[precondition] MAX_PLAINTEXT_SIZE is still smaller than random_data.size()",
                             Botan::TLS::MAX_PLAINTEXT_SIZE < random_data.size());

         result.test_is_true("writes the correct data",
                             contains(remote.buffer().data().data(), random_data.data(), random_data.size()));
         result.test_sz_eq("writes the correct amount of data", bytes_transferred, random_data.size());
         result.test_sz_eq("correct number of writes", ssl.next_layer().nwrite(), 2);
         result.test_is_true("does not report an error", !ec);

         results.push_back(result);
      }

      void test_sync_write_some_error(std::vector<Test::Result>& results) {
         net::io_context ioc;
         // fail right away
         FailCount fc{0, net::error::no_recovery};
         TestStream remote{ioc};

         const auto ctx = get_context();
         AsioStream ssl(ctx, ioc, fc);
         ssl.next_layer().connect(remote);

         error_code ec;

         const auto bytes_transferred = net::write(ssl, net::const_buffer(TEST_DATA, TEST_DATA_SIZE), ec);

         Test::Result result("sync write_some error");
         result.test_sz_eq("committed the data to the core", bytes_transferred, TEST_DATA_SIZE);
         result.test_is_true("propagates error code", ec == net::error::no_recovery);

         results.push_back(result);
      }

      void test_sync_write_some_throw(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         ThrowingAsioStream ssl(ctx, ioc);
         ssl.next_layer().connect(remote);
         error_code ec;

         const auto bytes_transferred = net::write(ssl, net::const_buffer(TEST_DATA, TEST_DATA_SIZE), ec);

         Test::Result result("sync write_some throw");
         result.test_sz_eq("didn't transfer anything", bytes_transferred, 0);
         result.test_is_true("propagates error code", ec == ThrowingMockChannel::expected_ec());

         results.push_back(result);
      }

      void test_async_write_some_success(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         AsioStream ssl(ctx, ioc);
         ssl.next_layer().connect(remote);

         Test::Result result("async write_some success");

         auto write_handler = [&](const error_code& ec, std::size_t bytes_transferred) {
            result.test_is_true("writes the correct data", remote.str() == test_data());
            result.test_sz_eq("writes the correct amount of data", bytes_transferred, TEST_DATA_SIZE);
            result.test_is_true("does not report an error", !ec);
         };

         net::async_write(ssl, net::const_buffer(TEST_DATA, TEST_DATA_SIZE), write_handler);

         ioc.run();
         results.push_back(result);
      }

      void test_async_write_some_buffer_sequence(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         AsioStream ssl(ctx, ioc);
         ssl.next_layer().connect(remote);

         // this should be Botan::TLS::MAX_PLAINTEXT_SIZE + 1024 + 1
         std::array<uint8_t, 17 * 1024 + 1> random_data{};
         random_data.fill('4');  // chosen by fair dice roll
         random_data.back() = '5';

         std::vector<net::const_buffer> src;
         src.emplace_back(net::const_buffer(random_data.data(), 1));
         for(std::size_t i = 1; i < random_data.size(); i += 1024) {
            src.emplace_back(net::const_buffer(random_data.data() + i, 1024));
         }

         Test::Result result("async write_some buffer sequence");

         result.test_is_true("[precondition] MAX_PLAINTEXT_SIZE is still smaller than random_data.size()",
                             Botan::TLS::MAX_PLAINTEXT_SIZE < random_data.size());

         auto write_handler = [&](const error_code& ec, std::size_t bytes_transferred) {
            result.test_is_true("writes the correct data",
                                contains(remote.buffer().data().data(), random_data.data(), random_data.size()));
            result.test_sz_eq("writes the correct amount of data", bytes_transferred, random_data.size());
            result.test_sz_eq("correct number of writes", ssl.next_layer().nwrite(), 2);
            result.test_is_true("does not report an error", !ec);
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

         const auto ctx = get_context();
         AsioStream ssl(ctx, ioc, fc);
         ssl.next_layer().connect(remote);

         Test::Result result("async write_some error");

         auto write_handler = [&](const error_code& ec, std::size_t bytes_transferred) {
            result.test_sz_eq("committed some bytes to the core", bytes_transferred, TEST_DATA_SIZE);
            result.test_is_true("propagates error code", ec == net::error::no_recovery);
         };

         net::async_write(ssl, net::const_buffer(TEST_DATA, TEST_DATA_SIZE), write_handler);

         ioc.run();
         results.push_back(result);
      }

      void test_async_write_throw(std::vector<Test::Result>& results) {
         net::io_context ioc;
         TestStream remote{ioc};

         const auto ctx = get_context();
         ThrowingAsioStream ssl(ctx, ioc);
         ssl.next_layer().connect(remote);

         Test::Result result("async write_some throw");

         auto write_handler = [&](const error_code& ec, std::size_t bytes_transferred) {
            result.test_sz_eq("didn't transfer anything", bytes_transferred, 0);
            result.test_is_true("propagates error code", ec == ThrowingMockChannel::expected_ec());
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
         test_sync_read_some_sends_emitted_data(results);
         test_sync_read_some_sends_alert(results);
         test_sync_stale_error_code(results);
         test_move_assignment(results);
         test_callbacks_reuse(results);
         test_null_arguments(results);

         test_async_read_some_success(results);
         test_async_read_some_buffer_sequence(results);
         test_async_read_some_error(results);
         test_async_read_some_throw(results);
         test_async_read_some_sends_emitted_data(results);
         test_async_read_some_sends_alert(results);
         test_async_read_write_overlap(results);
         test_async_write_waits_for_read_flush(results);
         test_async_write_cancellation(results);
         test_async_read_waits_for_stalled_write(results);
         test_async_read_error_waits_for_stalled_write(results);
         test_async_shutdown_reports_write_error(results);
         test_async_read_reply_survives_failed_write(results);
         test_async_read_reply_sent_by_shutdown(results);
         test_async_read_hands_out_data_before_sending_reply(results);
         test_async_write_sends_reply_of_completed_read(results);
         test_async_read_waits_for_reply_of_earlier_read(results);
         test_async_read_retries_reply_left_by_earlier_read(results);
         test_sync_read_hands_out_data_before_sending_reply(results);
         test_async_write_retries_remainder_of_failed_write(results);
         test_sync_read_sends_remainder_of_failed_write(results);
         test_operations_before_handshake(results);
         test_random_interleaving(results);
         test_sync_write_some_partial_failure(results);
         test_sync_write_some_before_handshake(results);
         test_async_write_partial_failure(results);
         test_cancellation_after_completion(results);
         test_sync_read_sends_reply_left_by_async_read(results);
         test_async_read_cancelled_while_sending_reply(results);
         test_async_write_cancelled_while_sending_read_reply(results);
         test_sync_operations_while_async_write_in_flight(results);
         test_sync_read_after_output_failure(results);
         test_async_read_after_output_failure(results);
         test_write_after_failed_read_is_refused(results);
         test_sync_write_some_flatten_failure(results);
         test_swallowed_alert_emit_failure(results);
         test_sync_shutdown_swallowed_emit_failure(results);
         test_async_read_zero_buffer(results);

         test_sync_write_some_success(results);
         test_sync_write_some_buffer_sequence(results);
         test_sync_write_some_error(results);
         test_sync_write_some_throw(results);
         test_sync_write_zero_buffer(results);

         test_async_write_some_success(results);
         test_async_write_some_buffer_sequence(results);
         test_async_write_some_error(results);
         test_async_write_throw(results);
         test_async_write_zero_buffer(results);

         return results;
      }
};

BOTAN_REGISTER_TEST("tls", "tls_asio_stream", Asio_Stream_Tests);

}  // namespace

}  // namespace Botan_Tests

   #endif
#endif  // BOTAN_HAS_TLS && BOTAN_HAS_TLS_ASIO_STREAM
