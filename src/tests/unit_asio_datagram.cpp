/*
* TLS ASIO Datagram Unit Tests
* (C) 2026 The Botan Authors
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

// Shared fixtures include live DTLS 1.2 peers using an auto-seeded RNG.
#if defined(BOTAN_HAS_TLS_12) && defined(BOTAN_HAS_AUTO_SEEDING_RNG) && defined(BOTAN_HAS_TLS_ASIO_STREAM)
   #include <botan/asio_compat.h>
   #if defined(BOTAN_FOUND_COMPATIBLE_BOOST_ASIO_DATAGRAM_VERSION)
      #include "test_asio_datagram_helpers.h"
      #include <boost/asio/bind_cancellation_slot.hpp>
      #include <boost/asio/bind_executor.hpp>
      #include <boost/asio/strand.hpp>
      #if defined(BOOST_ASIO_HAS_CO_AWAIT)
         #include <boost/asio/co_spawn.hpp>
         #include <boost/asio/redirect_error.hpp>
         #include <boost/asio/use_awaitable.hpp>
      #endif
      #include <array>
      #include <atomic>
      #include <iterator>
      #include <thread>

namespace Botan_Tests::Asio_Datagram_Test {

namespace {

struct AllocationCounts {
      std::atomic<size_t> allocations = 0;
      std::atomic<size_t> outstanding = 0;
};

template <typename T>
class CountingAllocator {
   public:
      using value_type = T;

      explicit CountingAllocator(std::shared_ptr<AllocationCounts> counts) : m_counts(std::move(counts)) {}

      template <typename U>
      explicit CountingAllocator(const CountingAllocator<U>& other) : m_counts(other.m_counts) {}

      T* allocate(size_t n) {
         auto* memory = std::allocator<T>{}.allocate(n);
         ++m_counts->allocations;
         ++m_counts->outstanding;
         return memory;
      }

      void deallocate(T* memory, size_t n) {
         --m_counts->outstanding;
         std::allocator<T>{}.deallocate(memory, n);
      }

      bool operator==(const CountingAllocator& other) const { return m_counts == other.m_counts; }

   private:
      template <typename U>
      friend class CountingAllocator;
      std::shared_ptr<AllocationCounts> m_counts;
};

class AllocatedCompletion {
   public:
      using allocator_type = CountingAllocator<uint8_t>;

      AllocatedCompletion(allocator_type allocator, std::function<void(error_code, size_t)> handler) :
            m_allocator(std::move(allocator)), m_handler(std::move(handler)) {}

      allocator_type get_allocator() const noexcept { return m_allocator; }

      void operator()(error_code ec, size_t n) { m_handler(ec, n); }

   private:
      allocator_type m_allocator;
      std::function<void(error_code, size_t)> m_handler;
};

class MockDatagramLayer {
   public:
      using executor_type = net::io_context::executor_type;
      using lowest_layer_type = MockDatagramLayer;

      explicit MockDatagramLayer(net::io_context& io) : m_io(io) {}

      executor_type get_executor() noexcept { return m_io.get_executor(); }

      MockDatagramLayer& lowest_layer() { return *this; }

      const MockDatagramLayer& lowest_layer() const { return *this; }

      void cancel(error_code& ec) { ec.clear(); }

      size_t send(const net::const_buffer& buffer, [[maybe_unused]] int flags, error_code& ec) {
         ec.clear();
         m_sent.emplace_back(static_cast<const uint8_t*>(buffer.data()),
                             static_cast<const uint8_t*>(buffer.data()) + buffer.size());
         return buffer.size();
      }

      template <typename Handler>
      void async_send(const net::const_buffer& buffer, Handler&& handler) {
         m_custom_send_allocator = std::is_same_v<net::associated_allocator_t<Handler>, CountingAllocator<uint8_t>>;
         error_code ec;
         const auto sent = send(buffer, 0, ec);
         // Dispatch directly so the wrapper must honor the user's associated executor.
         net::post(m_io, [handler = std::forward<Handler>(handler), ec, sent]() mutable { handler(ec, sent); });
      }

      size_t receive(const net::mutable_buffer& buffer, [[maybe_unused]] int flags, error_code& ec) {
         ++m_receive_calls;
         if(m_incoming.empty()) {
            ec = net::error::would_block;
            return 0;
         }

         ec.clear();
         const auto& msg = m_incoming.front();
         const auto copied = net::buffer_copy(buffer, net::buffer(msg));
         m_incoming.pop_front();
         return copied;
      }

      template <typename Handler>
      void async_receive(const net::mutable_buffer& buffer, Handler&& handler) {
         m_custom_receive_allocator = std::is_same_v<net::associated_allocator_t<Handler>, CountingAllocator<uint8_t>>;
         error_code ec;
         const auto received = receive(buffer, 0, ec);
         net::post(m_io, [handler = std::forward<Handler>(handler), ec, received]() mutable { handler(ec, received); });
      }

      void push_incoming(std::vector<uint8_t> msg) { m_incoming.emplace_back(std::move(msg)); }

      const std::vector<std::vector<uint8_t>>& sent() const { return m_sent; }

      size_t receive_calls() const { return m_receive_calls; }

      bool custom_send_allocator() const { return m_custom_send_allocator; }

      bool custom_receive_allocator() const { return m_custom_receive_allocator; }

   private:
      net::io_context& m_io;
      std::deque<std::vector<uint8_t>> m_incoming;
      std::vector<std::vector<uint8_t>> m_sent;
      size_t m_receive_calls = 0;
      bool m_custom_send_allocator = false;
      bool m_custom_receive_allocator = false;
};

class MockChannel {
   public:
      explicit MockChannel(std::shared_ptr<Botan::TLS::Callbacks> callbacks) : m_callbacks(std::move(callbacks)) {}

      size_t received_data(std::span<const uint8_t> data) {
         if(m_alert_on_receive) {
            m_callbacks->tls_alert(
               Botan::TLS::Alert(*m_alert_on_receive, *m_alert_on_receive != Botan::TLS::AlertType::CloseNotify));
            return 0;
         }
         if(m_respond_to_received_data) {
            m_callbacks->tls_emit_data(vec("response"));
         }
         if(m_received_record_size > 0) {
            for(size_t offset = 0; offset < data.size(); offset += m_received_record_size) {
               m_callbacks->tls_record_received(
                  0, data.subspan(offset, std::min(m_received_record_size, data.size() - offset)));
            }
         } else {
            m_callbacks->tls_record_received(0, data);
         }
         return 0;
      }

      void send(std::span<const uint8_t> data) {
         if(!data.empty()) {
            m_callbacks->tls_emit_data(data);
         }
      }

      void close() {
         m_closed = true;
         m_callbacks->tls_alert(Botan::TLS::AlertType::CloseNotify);
      }

      bool is_handshake_complete() const { return m_active; }

      bool is_active() const { return m_active && !m_closed; }

      std::optional<std::chrono::milliseconds> next_retransmission_timeout() const {
         return m_active ? std::nullopt : std::optional(std::chrono::milliseconds(0));
      }

      bool is_closed() const { return m_closed; }

      bool is_closed_for_reading() const { return m_closed; }

      bool is_closed_for_writing() const { return m_closed; }

      bool timeout_check() {
         ++m_timeout_checks;
         m_callbacks->tls_emit_data(vec("tick"));
         return true;
      }

      size_t timeout_checks() const { return m_timeout_checks; }

      void set_active(bool active) { m_active = active; }

      void respond_to_received_data(bool respond) { m_respond_to_received_data = respond; }

      void alert_on_receive(Botan::TLS::AlertType alert) { m_alert_on_receive = alert; }

      void received_record_size(size_t size) { m_received_record_size = size; }

   private:
      std::shared_ptr<Botan::TLS::Callbacks> m_callbacks;
      bool m_active = true;
      bool m_closed = false;
      bool m_respond_to_received_data = false;
      size_t m_timeout_checks = 0;
      std::optional<Botan::TLS::AlertType> m_alert_on_receive;
      size_t m_received_record_size = 0;
};

class TestDatagram final : public Botan::TLS::Datagram<MockDatagramLayer, MockChannel> {
   public:
      explicit TestDatagram(std::shared_ptr<Botan::TLS::Context> context,
                            net::io_context& io,
                            Botan::TLS::DatagramOptions options = {}) :
            Datagram(std::move(context), std::make_shared<Botan::TLS::DatagramCallbacks>(), options, io) {
         set_native_handle(std::make_unique<MockChannel>(callbacks()));
      }

      void inject(std::string_view msg) { callbacks()->tls_record_received(0, vec(msg)); }

      size_t flush(error_code& ec) { return send(net::const_buffer{}, ec); }

      void start_timer() { start_deferred_operations(); }

      void defer(uint64_t delay_ms, std::function<void()> op) {
         callbacks()->tls_register_deferred_operation(delay_ms, std::move(op));
      }
};

class ControlledTestDatagram final : public Botan::TLS::Datagram<ControlledDatagramLayer, MockChannel> {
   public:
      ControlledTestDatagram(std::shared_ptr<Botan::TLS::Context> context, ControlledDatagramLayer layer) :
            Datagram(std::move(context),
                     std::make_shared<Botan::TLS::DatagramCallbacks>(),
                     Botan::TLS::DatagramOptions{},
                     std::move(layer)) {
         set_native_handle(std::make_unique<MockChannel>(callbacks()));
      }

      void defer(uint64_t delay_ms, std::function<void()> op) {
         callbacks()->tls_register_deferred_operation(delay_ms, std::move(op));
      }
};

Test::Result test_send_boundaries() {
   Test::Result result("DTLS ASIO datagram send boundaries");
   net::io_context io;
   TestDatagram datagram(get_context(), io);
   datagram.native_handle()->send(vec("one"));
   datagram.native_handle()->send(vec("two"));
   result.test_is_true("const wrapper exposes the same native channel",
                       std::as_const(datagram).native_handle() == datagram.native_handle());

   error_code ec;
   datagram.flush(ec);

   result.test_is_true("flush succeeds", !ec);
   result.test_sz_eq("two datagrams sent", datagram.next_layer().sent().size(), 2);
   result.test_bin_eq("first datagram", datagram.next_layer().sent()[0], vec("one"));
   result.test_bin_eq("second datagram", datagram.next_layer().sent()[1], vec("two"));
   return result;
}

Test::Result test_receive_queue() {
   Test::Result result("DTLS ASIO datagram receive queue");
   net::io_context io;
   TestDatagram datagram(get_context(), io);
   datagram.inject("one");
   datagram.inject("two");

   std::array<uint8_t, 8> buffer{};
   error_code ec;
   const auto first = datagram.receive(net::buffer(buffer), ec);
   result.test_is_true("first receive succeeds", !ec);
   result.test_sz_eq("first receive size", first, 3);
   result.test_bin_eq("first receive data", std::vector<uint8_t>(buffer.begin(), buffer.begin() + first), vec("one"));

   const auto second = datagram.receive(net::buffer(buffer), ec);
   result.test_is_true("second receive succeeds", !ec);
   result.test_sz_eq("second receive size", second, 3);
   result.test_bin_eq("second receive data", std::vector<uint8_t>(buffer.begin(), buffer.begin() + second), vec("two"));
   return result;
}

Test::Result test_sync_receive_flush() {
   Test::Result result("DTLS ASIO datagram receive flushes protocol response");
   net::io_context io;
   TestDatagram datagram(get_context(), io);
   datagram.native_handle()->respond_to_received_data(true);
   datagram.next_layer().push_incoming(vec("request"));

   std::array<uint8_t, 16> buffer{};
   error_code ec;
   const auto transferred = datagram.receive(net::buffer(buffer), ec);

   result.test_is_true("receive succeeds", !ec);
   result.test_sz_eq("receive size", transferred, 7);
   result.test_sz_eq("protocol response was sent", datagram.next_layer().sent().size(), 1);
   result.test_bin_eq("protocol response contents", datagram.next_layer().sent().front(), vec("response"));
   return result;
}

Test::Result test_error_code_reuse() {
   Test::Result result("DTLS ASIO datagram error code reuse");
   net::io_context io;
   TestDatagram datagram(get_context(), io);
   datagram.inject("kept");
   std::array<uint8_t, 4> buffer{};
   error_code ec;
   result.test_sz_eq("small buffer returns no data", datagram.receive(net::buffer(buffer.data(), 1), ec), 0);
   result.test_is_true("small buffer is reported", ec == net::error::message_size);
   result.test_sz_eq("larger retry returns retained record", datagram.receive(net::buffer(buffer), ec), 4);
   result.test_is_true("successful retry clears error", !ec);
   result.test_bin_eq("record was preserved", buffer, vec("kept"));
   ec = net::error::message_size;
   result.test_sz_eq("send succeeds with stale error", datagram.send(net::buffer(buffer), ec), buffer.size());
   result.test_is_true("send clears error", !ec);
   ec = net::error::message_size;
   datagram.handshake(Botan::TLS::Connection_Side::Client, ec);
   result.test_is_true("handshake clears error", !ec);
   ec = net::error::message_size;
   datagram.set_verify_callback(accept_all, ec);
   result.test_is_true("verification setter clears error", !ec);
   ec = net::error::message_size;
   datagram.shutdown(ec);
   result.test_is_true("shutdown clears error", !ec);
   ec = net::error::message_size;
   datagram.cancel(ec);
   result.test_is_true("cancel clears error", !ec);
   return result;
}

Test::Result test_associated_executor() {
   Test::Result result("DTLS ASIO datagram associated executor");
   for(size_t operation = 0; operation != 5; ++operation) {
      net::io_context io;
      const auto strand = net::make_strand(io);
      TestDatagram datagram(get_context(), io);
      std::array<uint8_t, 16> buffer{};
      size_t completions = 0;
      auto complete = [&](const error_code& ec) {
         ++completions;
         result.test_is_true("completion uses associated strand", strand.running_in_this_thread());
         result.test_is_true("operation succeeds", !ec);
      };
      if(operation == 0 || operation == 1) {
         if(operation == 0) {
            datagram.inject("queued");
         } else {
            datagram.next_layer().push_incoming(vec("queued"));
         }
         datagram.async_receive(net::buffer(buffer), net::bind_executor(strand, [&](const error_code& ec, size_t n) {
                                   complete(ec);
                                   result.test_sz_eq("receive size", n, 6);
                                   result.test_bin_eq("receive data",
                                                      std::vector<uint8_t>(buffer.begin(), buffer.begin() + n),
                                                      vec("queued"));
                                }));
      } else if(operation == 2) {
         datagram.async_send(net::buffer(buffer), net::bind_executor(strand, [&](const error_code& ec, size_t n) {
                                complete(ec);
                                result.test_sz_eq("send size", n, buffer.size());
                             }));
      } else if(operation == 3) {
         datagram.async_handshake(Botan::TLS::Connection_Side::Client, net::bind_executor(strand, complete));
      } else {
         datagram.async_shutdown(net::bind_executor(strand, complete));
      }
      result.test_sz_eq("completion is not inline", completions, 0);
      io.run();
      result.test_sz_eq("completion called exactly once", completions, 1);
   }
   return result;
}

Test::Result test_separate_completion_executor() {
   Test::Result result("DTLS ASIO datagram separate completion executor");
   net::io_context transport_io;
   net::io_context completion_io;
   TestDatagram datagram(get_context(), transport_io);
   std::array<uint8_t, 4> buffer{};
   size_t completions = 0;
   datagram.async_send(net::buffer(buffer),
                       net::bind_executor(completion_io.get_executor(),
                                          [&, lifetime = std::make_unique<int>(42)](const error_code& ec, size_t n) {
                                             ++completions;
                                             result.test_is_true("operation succeeds", !ec);
                                             result.test_sz_eq("send size", n, buffer.size());
                                             result.test_is_true("move-only handler remains intact", *lifetime == 42);
                                          }));
   completion_io.poll();
   result.test_is_true("pending operation keeps completion executor alive", !completion_io.stopped());
   transport_io.run();
   result.test_sz_eq("transport does not invoke user completion", completions, 0);
   completion_io.run();
   result.test_sz_eq("completion executor invokes handler once", completions, 1);
   return result;
}

Test::Result test_cached_receive_errors() {
   Test::Result result("DTLS ASIO datagram cached terminal receive errors");
   for(const auto alert : {Botan::TLS::AlertType::CloseNotify, Botan::TLS::AlertType::HandshakeFailure}) {
      net::io_context io;
      TestDatagram datagram(get_context(), io);
      datagram.native_handle()->alert_on_receive(alert);
      datagram.next_layer().push_incoming(vec("alert"));
      std::array<uint8_t, 16> buffer{};
      error_code ec;
      datagram.receive(net::buffer(buffer), ec);
      const error_code expected =
         alert == Botan::TLS::AlertType::CloseNotify ? error_code(net::error::eof) : Botan::TLS::make_error_code(alert);
      result.test_is_true("first receive reports terminal state", ec == expected);
      const auto reads = datagram.next_layer().receive_calls();
      datagram.receive(net::buffer(buffer), ec);
      result.test_is_true("subsequent receive retains terminal state", ec == expected);
      result.test_sz_eq("terminal receive does not read transport again", datagram.next_layer().receive_calls(), reads);
   }
   return result;
}

Test::Result test_recoverable_receive_errors() {
   Test::Result result("DTLS ASIO datagram recoverable receive errors preserve deferred work");
   for(const bool overflow : {false, true}) {
      net::io_context io;
      Botan::TLS::DatagramOptions options;
      options.receive_queue_limit = 1;
      TestDatagram datagram(get_context(), io, options);
      if(overflow) {
         datagram.native_handle()->received_record_size(2);
      }
      datagram.next_layer().push_incoming(vec("data"));
      size_t deferred_calls = 0;
      datagram.defer(50, [&] { ++deferred_calls; });
      std::array<uint8_t, 8> buffer{};
      error_code receive_ec;
      datagram.async_receive(net::buffer(buffer.data(), overflow ? buffer.size() : 1), [&](error_code ec, size_t n) {
         receive_ec = ec;
         result.test_sz_eq("recoverable error reports no plaintext", n, 0);
      });
      io.run();
      const error_code expected = overflow ? Botan::TLS::make_error_code(Botan::TLS::DatagramReceiveQueueOverflow)
                                           : error_code(net::error::message_size);
      result.test_is_true("recoverable error is reported", receive_ec == expected);
      result.test_sz_eq("deferred operation still executes", deferred_calls, 1);
      error_code ec;
      result.test_sz_eq("retained record can be retried", datagram.receive(net::buffer(buffer), ec), overflow ? 2 : 4);
      result.test_is_true("retry succeeds", !ec);
   }
   return result;
}

Test::Result test_receive_cancellation() {
   Test::Result result("DTLS ASIO datagram receive slot cancellation and reuse");
   net::io_context io;
   net::cancellation_signal signal;
   for(size_t iteration = 0; iteration != 2; ++iteration) {
      io.restart();
      auto control = std::make_shared<ControlledDatagramLayer::Control>();
      auto [layer, peer] = ControlledDatagramLayer::make_pair(io, control);
      ControlledTestDatagram datagram(get_context(), std::move(layer));
      std::array<uint8_t, 16> buffer{};
      const auto counts = std::make_shared<AllocationCounts>();
      size_t completions = 0;
      error_code receive_ec;
      datagram.async_receive(
         net::buffer(buffer),
         net::bind_cancellation_slot(
            signal.slot(), AllocatedCompletion(CountingAllocator<uint8_t>(counts), [&](error_code ec, size_t n) {
               ++completions;
               receive_ec = ec;
               result.test_sz_eq("cancelled receive reports no plaintext", n, 0);
               result.test_sz_eq("cancelled operation storage released before completion", counts->outstanding, 0);
            })));
      signal.emit(net::cancellation_type::partial);
      signal.emit(net::cancellation_type::total);
      io.poll();
      result.test_sz_eq("unsupported cancellation types leave receive pending", completions, 0);
      signal.emit(net::cancellation_type::terminal);
      result.test_sz_eq("cancellation completion is not inline", completions, 0);
      io.run();
      result.test_is_true("terminal cancellation is reported", receive_ec == net::error::operation_aborted);
      result.test_sz_eq("receive completes exactly once", completions, 1);
      result.test_is_true("slot is cleared for reuse", !signal.slot().has_handler());
   }
   return result;
}

Test::Result test_receive_cancel_between_callbacks() {
   Test::Result result("DTLS ASIO datagram slot cancellation between transport completions");
   net::io_context io;
   TestDatagram datagram(get_context(), io);
   datagram.next_layer().push_incoming(vec("pending"));
   std::array<uint8_t, 16> buffer{};
   net::cancellation_signal signal;
   size_t completions = 0;
   error_code receive_ec;
   datagram.async_receive(net::buffer(buffer), net::bind_cancellation_slot(signal.slot(), [&](error_code ec, size_t n) {
                             ++completions;
                             receive_ec = ec;
                             result.test_sz_eq("cancelled completion reports no plaintext", n, 0);
                          }));
   signal.emit(net::cancellation_type::terminal);
   io.run();
   result.test_is_true("queued transport completion observes slot cancellation",
                       receive_ec == net::error::operation_aborted);
   result.test_sz_eq("queued operation completes exactly once", completions, 1);
   return result;
}

Test::Result test_receive_cancel_with_send() {
   Test::Result result("DTLS ASIO datagram receive cancellation preserves overlapping send");
   for(const bool flush_response : {false, true}) {
      net::io_context io;
      auto control = std::make_shared<ControlledDatagramLayer::Control>();
      control->hold_next_send = ControlledDatagramLayer::Direction::ClientToServer;
      auto [layer, peer] = ControlledDatagramLayer::make_pair(io, control);
      ControlledTestDatagram datagram(get_context(), std::move(layer));
      datagram.native_handle()->respond_to_received_data(flush_response);
      const auto payload = vec("held");
      std::array<uint8_t, 16> buffer{};
      size_t sends = 0;
      size_t receives = 0;
      error_code send_ec;
      error_code receive_ec;
      net::cancellation_signal signal;
      datagram.async_send(net::buffer(payload), [&](error_code ec, size_t n) {
         ++sends;
         send_ec = ec;
         result.test_sz_eq("overlapping send retains size", n, payload.size());
      });
      datagram.async_receive(net::buffer(buffer),
                             net::bind_cancellation_slot(signal.slot(), [&](error_code ec, size_t n) {
                                ++receives;
                                receive_ec = ec;
                                result.test_sz_eq("cancelled receive returns no plaintext", n, 0);
                             }));
      if(flush_response) {
         error_code ec;
         peer.send(net::buffer(payload), 0, ec);
         result.test_is_true("protocol response input delivered", !ec);
      }
      io.poll();  // The receive is either idle or waiting behind the held send's flush.
      signal.emit(net::cancellation_type::terminal);
      io.poll();
      result.test_is_true("receive cancellation completes before held send",
                          receive_ec == net::error::operation_aborted);
      result.test_sz_eq("receive completes once", receives, 1);
      result.test_sz_eq("held send remains pending", sends, 0);
      result.test_sz_eq("unrelated send was not cancelled", control->aborted_sends, 0);
      datagram.next_layer().release_held_send();
      io.run();
      result.test_is_true("overlapping send succeeds", !send_ec);
      result.test_sz_eq("send completes once", sends, 1);
   }
   return result;
}

Test::Result test_send_and_shutdown_cancellation() {
   Test::Result result("DTLS ASIO datagram send and shutdown slot cancellation");
   for(const bool shutdown : {false, true}) {
      net::io_context io;
      auto control = std::make_shared<ControlledDatagramLayer::Control>();
      control->hold_next_send = ControlledDatagramLayer::Direction::ClientToServer;
      auto [layer, peer] = ControlledDatagramLayer::make_pair(io, control);
      ControlledTestDatagram datagram(get_context(), std::move(layer));
      const auto payload = vec("held");
      std::array<uint8_t, 16> buffer{};
      net::cancellation_signal signal;
      size_t completions = 0;
      size_t receives = 0;
      error_code operation_ec;
      error_code receive_ec;
      if(shutdown) {
         datagram.native_handle()->send(payload);
         datagram.async_shutdown(net::bind_cancellation_slot(signal.slot(), [&](error_code ec) {
            ++completions;
            operation_ec = ec;
         }));
      } else {
         datagram.async_send(net::buffer(payload),
                             net::bind_cancellation_slot(signal.slot(), [&](error_code ec, size_t n) {
                                ++completions;
                                operation_ec = ec;
                                result.test_sz_eq("cancelled send reports no plaintext", n, 0);
                             }));
         datagram.async_receive(net::buffer(buffer), [&](error_code ec, size_t n) {
            ++receives;
            receive_ec = ec;
            result.test_sz_eq("unrelated receive retains plaintext", n, payload.size());
         });
      }
      signal.emit(net::cancellation_type::terminal);
      if(!shutdown) {
         error_code ec;
         peer.send(net::buffer(payload), 0, ec);
         result.test_is_true("unrelated input delivered", !ec);
      }
      io.run();
      result.test_is_true("slot cancellation is reported", operation_ec == net::error::operation_aborted);
      result.test_sz_eq("cancelled operation completes once", completions, 1);
      result.test_sz_eq("held native send cancelled once", control->aborted_sends, 1);
      result.test_is_true("completed operation clears slot", !signal.slot().has_handler());
      if(!shutdown) {
         result.test_is_true("unrelated receive succeeds", !receive_ec);
         result.test_sz_eq("unrelated receive completes once", receives, 1);
      }
   }
   return result;
}

Test::Result test_handshake_cancellation() {
   Test::Result result("DTLS ASIO datagram handshake slot cancellation stops deferred work");
   for(const bool held_send : {false, true}) {
      net::io_context io;
      auto control = std::make_shared<ControlledDatagramLayer::Control>();
      if(held_send) {
         control->hold_next_send = ControlledDatagramLayer::Direction::ClientToServer;
      }
      auto [layer, peer] = ControlledDatagramLayer::make_pair(io, control);
      ControlledTestDatagram datagram(get_context(), std::move(layer));
      datagram.native_handle()->set_active(false);
      size_t deferred_calls = 0;
      datagram.defer(50, [&] { ++deferred_calls; });
      if(held_send) {
         datagram.native_handle()->send(vec("hello"));
      }
      net::cancellation_signal signal;
      size_t completions = 0;
      error_code handshake_ec;
      datagram.async_handshake(Botan::TLS::Connection_Side::Client,
                               net::bind_cancellation_slot(signal.slot(), [&](error_code ec) {
                                  ++completions;
                                  handshake_ec = ec;
                               }));
      signal.emit(net::cancellation_type::terminal);
      io.run();
      result.test_is_true("handshake cancellation is reported", handshake_ec == net::error::operation_aborted);
      result.test_sz_eq("handshake completes once", completions, 1);
      result.test_sz_eq("no deferred operation ran", deferred_calls, 0);
      result.test_sz_eq("held handshake send cancelled once", control->aborted_sends, held_send ? 1 : 0);
   }
   return result;
}

      #if defined(BOOST_ASIO_HAS_CO_AWAIT)
constexpr auto receive_in_coroutine =
   [](std::shared_ptr<ControlledTestDatagram> datagram) -> net::awaitable<std::pair<error_code, size_t>> {
   std::array<uint8_t, 16> buffer{};
   error_code receive_ec;
   const auto n =
      co_await datagram->async_receive(net::buffer(buffer), net::redirect_error(net::use_awaitable, receive_ec));
   co_return std::make_pair(receive_ec, n);
};

Test::Result test_coroutine_cancellation() {
   Test::Result result("DTLS ASIO datagram coroutine cancellation");
   net::io_context io;
   auto control = std::make_shared<ControlledDatagramLayer::Control>();
   auto [layer, peer] = ControlledDatagramLayer::make_pair(io, control);
   auto datagram = std::make_shared<ControlledTestDatagram>(get_context(), std::move(layer));
   net::cancellation_signal signal;
   error_code receive_ec;
   size_t completions = 0;
   net::co_spawn(io,
                 receive_in_coroutine(std::move(datagram)),
                 net::bind_cancellation_slot(
                    signal.slot(), [&](const std::exception_ptr& error, const std::pair<error_code, size_t>& received) {
                       ++completions;
                       receive_ec = received.first;
                       result.test_is_true("coroutine handles cancellation via error code", !error);
                       result.test_sz_eq("cancelled coroutine receives no plaintext", received.second, 0);
                    }));
   io.poll();
   signal.emit(net::cancellation_type::terminal);
   io.run();
   result.test_is_true("coroutine cancellation reaches receive", receive_ec == net::error::operation_aborted);
   result.test_sz_eq("coroutine completes once", completions, 1);
   return result;
}
      #endif

Test::Result test_send_allocator() {
   Test::Result result("DTLS ASIO datagram associated allocator");
   net::io_context transport_io;
   net::io_context completion_io;
   TestDatagram datagram(get_context(), transport_io);
   std::array<uint8_t, 4> buffer{};
   const auto counts = std::make_shared<AllocationCounts>();
   size_t completions = 0;
   datagram.async_send(
      net::buffer(buffer),
      net::bind_executor(completion_io.get_executor(),
                         AllocatedCompletion(CountingAllocator<uint8_t>(counts), [&](error_code ec, size_t n) {
                            ++completions;
                            result.test_is_true("send succeeds", !ec);
                            result.test_sz_eq("send size", n, buffer.size());
                            result.test_sz_eq(
                               "operation storage is released before completion", counts->outstanding, 0);
                         })));
   std::thread completion_thread([&] { completion_io.run(); });
   transport_io.run();
   completion_thread.join();
   result.test_is_true("associated allocator is used", counts->allocations > 0);
   result.test_is_true("send transport receives associated allocator", datagram.next_layer().custom_send_allocator());
   result.test_sz_eq("handler invoked exactly once", completions, 1);
   result.test_sz_eq("all allocations released", counts->outstanding, 0);
   return result;
}

Test::Result test_receive_allocator() {
   Test::Result result("DTLS ASIO datagram receive associated allocator");
   net::io_context io;
   TestDatagram datagram(get_context(), io);
   datagram.next_layer().push_incoming(vec("data"));
   std::array<uint8_t, 16> buffer{};
   const auto counts = std::make_shared<AllocationCounts>();
   size_t completions = 0;
   datagram.async_receive(net::buffer(buffer),
                          AllocatedCompletion(CountingAllocator<uint8_t>(counts), [&](error_code ec, size_t n) {
                             ++completions;
                             result.test_is_true("receive succeeds", !ec);
                             result.test_sz_eq("received record size", n, 4);
                             result.test_sz_eq("receive storage released before completion", counts->outstanding, 0);
                          }));
   result.test_is_true("pending receive uses associated allocator", counts->outstanding > 0);
   io.run();
   result.test_sz_eq("receive handler invoked exactly once", completions, 1);
   result.test_is_true("receive transport receives associated allocator",
                       datagram.next_layer().custom_receive_allocator());
   result.test_sz_eq("all receive allocations released", counts->outstanding, 0);
   return result;
}

Test::Result test_callback_ownership() {
   Test::Result result("DTLS ASIO datagram callback ownership and options");
   net::io_context io;
   const auto context = get_context();
   const auto callbacks = std::make_shared<Botan::TLS::DatagramCallbacks>();
   const Botan::TLS::Datagram<MockDatagramLayer, MockChannel> first(
      context, callbacks, Botan::TLS::DatagramOptions{}, io);
   result.test_throws("callbacks cannot belong to two wrappers", [&] {
      const Botan::TLS::Datagram<MockDatagramLayer, MockChannel> second(
         context, callbacks, Botan::TLS::DatagramOptions{}, io);
   });
   for(const bool empty_queue : {false, true}) {
      Botan::TLS::DatagramOptions options;
      if(empty_queue) {
         options.receive_queue_limit = 0;
      } else {
         options.encrypted_receive_buffer_size = 0;
      }
      result.test_throws("zero receive limits are rejected", [&] { const TestDatagram invalid(context, io, options); });
   }
   return result;
}

Test::Result test_async_receive_flush() {
   Test::Result result("DTLS ASIO datagram async receive flushes protocol response");
   net::io_context io;
   TestDatagram datagram(get_context(), io);
   datagram.native_handle()->respond_to_received_data(true);
   datagram.next_layer().push_incoming(vec("request"));

   std::array<uint8_t, 16> buffer{};
   bool called = false;
   datagram.async_receive(net::buffer(buffer), [&](const error_code& ec, size_t transferred) {
      called = true;
      result.test_is_true("async receive succeeds", !ec);
      result.test_sz_eq("async receive size", transferred, 7);
   });

   io.run();
   result.test_is_true("handler called", called);
   result.test_sz_eq("protocol response was sent", datagram.next_layer().sent().size(), 1);
   result.test_bin_eq("protocol response contents", datagram.next_layer().sent().front(), vec("response"));
   return result;
}

Test::Result test_queue_overflow() {
   Test::Result result("DTLS ASIO datagram queue overflow");
   Botan::TLS::DatagramOptions options;
   options.receive_queue_limit = 1;
   net::io_context io;
   TestDatagram datagram(get_context(), io, options);
   datagram.inject("kept");
   datagram.inject("dropped");

   std::array<uint8_t, 16> buffer{};
   error_code ec;
   const auto transferred = datagram.receive(net::buffer(buffer), ec);
   result.test_sz_eq("no data returned with overflow", transferred, 0);
   result.test_is_true("overflow is reported", ec == Botan::TLS::DatagramReceiveQueueOverflow);
   result.test_sz_eq("retained record is readable after overflow", datagram.receive(net::buffer(buffer), ec), 4);
   result.test_is_true("overflow is reported only once", !ec);
   return result;
}

Test::Result test_deferred_callbacks() {
   Test::Result result("DTLS ASIO datagram deferred operations");
   net::io_context io;
   TestDatagram datagram(get_context(), io);
   size_t calls = 0;
   datagram.defer(2, [&] {
      ++calls;
      datagram.native_handle()->send(vec("tick"));
      datagram.defer(2, [&] { ++calls; });
   });
   datagram.start_timer();
   io.run();
   result.test_sz_eq("nested operations execute exactly once", calls, 2);
   result.test_sz_eq("timeout_check is never polled", datagram.native_handle()->timeout_checks(), 0);
   result.test_is_true("retransmit data was sent", !datagram.next_layer().sent().empty());
   return result;
}

Test::Result test_deferred_lifetime() {
   Test::Result result("DTLS ASIO datagram deferred operation lifetime");
   net::io_context io;
   size_t calls = 0;
   {
      TestDatagram datagram(get_context(), io);
      datagram.defer(0, [&] { ++calls; });
      datagram.start_timer();
   }
   io.run();
   result.test_sz_eq("destroyed wrapper does not invoke operation", calls, 0);
   return result;
}

Test::Result test_cancel_between_callbacks() {
   Test::Result result("DTLS ASIO datagram cancel between transport completions");
   net::io_context io;
   auto control = std::make_shared<ControlledDatagramLayer::Control>();
   auto [layer, peer] = ControlledDatagramLayer::make_pair(io, control);
   ControlledTestDatagram datagram(get_context(), std::move(layer));
   std::array<uint8_t, 32> buffer{};
   size_t completions = 0;
   error_code receive_ec;
   datagram.async_receive(net::buffer(buffer), [&](error_code ec, size_t n) {
      receive_ec = ec;
      result.test_sz_eq("canceled operation reports no plaintext", n, 0);
      ++completions;
   });
   const auto packet = vec("already completed transport read");
   error_code ec;
   peer.send(net::buffer(packet), 0, ec);
   result.test_is_true("transport read was delivered", !ec);
   // The transport completion is queued, so canceling the socket alone would miss it.
   datagram.cancel(ec);
   io.run();
   result.test_sz_eq("composed receive completes exactly once", completions, 1);
   result.test_is_true("composed cancellation is reported", receive_ec == net::error::operation_aborted);
   return result;
}

Test::Result test_reference_transport_move() {
   Test::Result result("DTLS ASIO datagram reference transport follows move");
   net::io_context io;
   MockDatagramLayer layer(io);
   Botan::TLS::Datagram<MockDatagramLayer&, MockChannel> original(get_context(), layer);
   Botan::TLS::Datagram<MockDatagramLayer&, MockChannel> moved(std::move(original));
   result.test_is_true("reference transport is preserved", &moved.next_layer() == &layer);
   return result;
}

Test::Result test_deferred_move() {
   Test::Result result("DTLS ASIO datagram deferred operation follows move");
   net::io_context io;
   TestDatagram original(get_context(), io);
   size_t calls = 0;
   original.defer(2, [&] { ++calls; });
   original.start_timer();
   // Background protocol work mutates the moved wrapper through its deferred state.
   // NOLINTNEXTLINE(misc-const-correctness)
   Botan::TLS::Datagram<MockDatagramLayer, MockChannel> moved(std::move(original));
   io.run();
   result.test_sz_eq("operation follows moved wrapper", calls, 1);
   return result;
}

Test::Result test_deferred_after_handshake() {
   Test::Result result("DTLS ASIO datagram deferred operation after handshake completion");
   net::io_context io;
   TestDatagram datagram(get_context(), io);
   bool handshake_done = false;
   size_t calls = 0;
   datagram.defer(2, [&] {
      result.test_is_true("handshake completed before retained operation", handshake_done);
      ++calls;
      datagram.native_handle()->send(vec("final flight"));
   });
   datagram.async_handshake(Botan::TLS::Connection_Side::Client, [&](error_code ec) {
      result.test_is_true("mock handshake succeeds", !ec);
      handshake_done = true;
   });
   io.run();
   result.test_sz_eq("retained operation executes once", calls, 1);
   result.test_sz_eq("retained flight is sent", datagram.next_layer().sent().size(), 1);
   return result;
}

class Asio_Datagram_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results {
            test_send_boundaries(), test_receive_queue(), test_sync_receive_flush(), test_error_code_reuse(),
               test_associated_executor(), test_separate_completion_executor(), test_cached_receive_errors(),
               test_recoverable_receive_errors(), test_receive_cancellation(), test_receive_cancel_between_callbacks(),
               test_receive_cancel_with_send(), test_send_and_shutdown_cancellation(), test_handshake_cancellation(),
      #if defined(BOOST_ASIO_HAS_CO_AWAIT)
               test_coroutine_cancellation(),
      #endif
               test_send_allocator(), test_receive_allocator(), test_callback_ownership(), test_async_receive_flush(),
               test_queue_overflow(), test_deferred_callbacks(), test_deferred_lifetime(),
               test_cancel_between_callbacks(), test_reference_transport_move(), test_deferred_move(),
               test_deferred_after_handshake(),
         };
         auto integration = run_asio_datagram_integration_tests();
         results.insert(
            results.end(), std::make_move_iterator(integration.begin()), std::make_move_iterator(integration.end()));
         return results;
      }
};

}  // namespace

BOTAN_REGISTER_TEST("tls", "tls_asio_datagram", Asio_Datagram_Tests);

}  // namespace Botan_Tests::Asio_Datagram_Test

   #endif
#endif  // BOTAN_HAS_TLS_12 && BOTAN_HAS_AUTO_SEEDING_RNG && BOTAN_HAS_TLS_ASIO_STREAM
