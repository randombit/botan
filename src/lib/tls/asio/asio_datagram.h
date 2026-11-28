/*
* DTLS ASIO Datagram
* (C) 2026 The Botan Authors
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ASIO_DATAGRAM_H_
#define BOTAN_ASIO_DATAGRAM_H_

#include <botan/asio_compat.h>
#if !defined(BOTAN_FOUND_COMPATIBLE_BOOST_ASIO_DATAGRAM_VERSION)
   #error Available boost headers are too old for the boost asio datagram wrapper.
#else

   #include <botan/asio_context.h>
   #include <botan/asio_error.h>

   #include <botan/tls_callbacks.h>
   #include <botan/tls_channel.h>
   #include <botan/tls_client.h>
   #include <botan/tls_magic.h>
   #include <botan/tls_server.h>

   #include <boost/asio/associated_allocator.hpp>
   #include <boost/asio/associated_cancellation_slot.hpp>
   #include <boost/asio/associated_executor.hpp>
   #include <boost/asio/async_result.hpp>
   #include <boost/asio/bind_cancellation_slot.hpp>
   #include <boost/asio/buffer.hpp>
   #include <boost/asio/cancellation_signal.hpp>
   #include <boost/asio/detail/throw_error.hpp>
   #include <boost/asio/error.hpp>
   #include <boost/asio/executor_work_guard.hpp>
   #include <boost/asio/post.hpp>
   #include <boost/asio/steady_timer.hpp>

   #include <algorithm>
   #include <chrono>
   #include <deque>
   #include <functional>
   #include <map>
   #include <memory>
   #include <optional>
   #include <span>
   #include <string>
   #include <string_view>
   #include <thread>
   #include <tuple>
   #include <type_traits>
   #include <utility>
   #include <vector>

namespace Botan::TLS {

template <class DL, class C>
class Datagram;

struct DatagramOptions final {
      /// Maximum number of queued plaintext application records. New records are dropped on overflow.
      size_t receive_queue_limit = 64;
      /// Capacity of the encrypted receive buffer, not the outgoing DTLS MTU.
      size_t encrypted_receive_buffer_size = MAX_CIPHERTEXT_SIZE;
};

/** Callbacks for exactly one Datagram instance. They must not be reused for another wrapper. */
class DatagramCallbacks : public Callbacks {
   public:
      DatagramCallbacks() = default;

      void tls_emit_data(std::span<const uint8_t> data) final { m_send_queue.emplace_back(data.begin(), data.end()); }

      void tls_record_received(uint64_t /*record_number*/, std::span<const uint8_t> data) final {
         if(data.empty()) {
            return;
         }
         if(m_receive_queue.size() >= m_options.receive_queue_limit) {
            m_receive_overflow = true;
            return;
         }

         m_receive_queue.emplace_back(data.begin(), data.end());
      }

      bool tls_peer_closed_connection() final { return true; }

      std::string tls_peer_network_identity() override {
         return m_peer_network_identity ? m_peer_network_identity() : std::string();
      }

      void tls_register_deferred_operation(uint64_t delay_ms, std::function<void()> op) final {
         if(m_register_deferred_operation) {
            m_register_deferred_operation(delay_ms, std::move(op));
         }
      }

      void tls_alert(TLS::Alert alert) final {
         if(alert.is_fatal() || alert.type() == TLS::AlertType::CloseNotify) {
            m_alert_from_peer = alert;
         }
      }

      void tls_verify_cert_chain(const std::vector<X509_Certificate>& cert_chain,
                                 const std::vector<std::optional<OCSP::Response>>& ocsp_responses,
                                 const std::vector<Certificate_Store*>& trusted_roots,
                                 Usage_Type usage,
                                 std::string_view hostname,
                                 const TLS::Policy& policy) override {
         auto ctx = m_context.lock();

         if(ctx && ctx->has_verify_callback()) {
            ctx->get_verify_callback()(cert_chain, ocsp_responses, trusted_roots, usage, hostname, policy);
         } else {
            Callbacks::tls_verify_cert_chain(cert_chain, ocsp_responses, trusted_roots, usage, hostname, policy);
         }
      }

      std::string tls_server_choose_app_protocol(const std::vector<std::string>& client_protos) override {
         if(client_protos.empty()) {
            return "";
         }

         auto ctx = m_context.lock();
         if(!ctx || ctx->m_app_protocols.empty()) {
            return "";
         }

         for(const auto& server_proto : ctx->m_app_protocols) {
            for(const auto& client_proto : client_protos) {
               if(server_proto == client_proto) {
                  return server_proto;
               }
            }
         }

         throw TLS_Exception(
            AlertType::NoApplicationProtocol,
            "Rejecting ALPN request: no overlap between client-offered and server-configured application protocols");
      }

   private:
      template <class DL, class C>
      friend class Datagram;

      void set_context(std::weak_ptr<Botan::TLS::Context> context) { m_context = std::move(context); }

      bool has_send_data() const { return !m_send_queue.empty(); }

      bool has_received_data() const { return !m_receive_queue.empty(); }

      std::optional<Alert> alert_from_peer() const { return m_alert_from_peer; }

      bool shutdown_received() const {
         return m_alert_from_peer && m_alert_from_peer->type() == AlertType::CloseNotify;
      }

      boost::asio::const_buffer next_send_datagram() const {
         if(m_send_queue.empty()) {
            throw Invalid_State("ASIO DTLS send queue unexpectedly empty");
         }
         return boost::asio::buffer(m_send_queue.front());
      }

      void consume_send_datagram() {
         if(m_send_queue.empty()) {
            throw Invalid_State("ASIO DTLS send queue unexpectedly empty");
         }
         m_send_queue.pop_front();
      }

      boost::system::error_code receive_overflow_error() {
         if(m_receive_overflow) {
            m_receive_overflow = false;
            return DatagramReceiveQueueOverflow;
         }
         return {};
      }

      template <typename MutableBufferSequence>
      size_t copy_received_datagram(const MutableBufferSequence& buffers, boost::system::error_code& ec) {
         if(auto overflow = receive_overflow_error()) {
            ec = overflow;
            return 0;
         }

         if(m_receive_queue.empty()) {
            return 0;
         }

         const auto& msg = m_receive_queue.front();
         if(boost::asio::buffer_size(buffers) < msg.size()) {
            ec = boost::asio::error::message_size;
            return 0;
         }

         const auto copied = boost::asio::buffer_copy(buffers, boost::asio::buffer(msg));
         m_receive_queue.pop_front();
         return copied;
      }

      DatagramOptions m_options;
      std::optional<Alert> m_alert_from_peer;
      std::deque<std::vector<uint8_t>> m_receive_queue;
      std::deque<std::vector<uint8_t>> m_send_queue;
      bool m_receive_overflow = false;
      bool m_attached = false;
      std::weak_ptr<TLS::Context> m_context;
      std::function<std::string()> m_peer_network_identity;
      std::function<void(uint64_t, std::function<void()>)> m_register_deferred_operation;
};

namespace detail {

template <typename T>
concept datagram_completion_token = boost::asio::completion_token_for<T, void(boost::system::error_code)>;

template <typename T>
concept datagram_size_completion_token = boost::asio::completion_token_for<T, void(boost::system::error_code, size_t)>;

// Internal callbacks run on the transport executor. Only the final completion is
// delivered on the user's associated executor, with its associated allocator.
template <typename Handler, typename Allocator>
class DatagramAllocatedHandler {
   public:
      using allocator_type = Allocator;

      DatagramAllocatedHandler(Handler handler, Allocator allocator) :
            m_handler(std::move(handler)), m_allocator(std::move(allocator)) {}

      allocator_type get_allocator() const noexcept { return m_allocator; }

      template <typename... Args>
      void operator()(Args&&... args) {
         std::move(m_handler)(std::forward<Args>(args)...);
      }

   private:
      Handler m_handler;
      Allocator m_allocator;
};

template <typename Handler, typename... Args>
class DatagramCompletion {
   public:
      using allocator_type = boost::asio::associated_allocator_t<Handler>;

      explicit DatagramCompletion(Handler handler, Args... args) :
            m_handler(std::move(handler)), m_args(std::move(args)...) {}

      allocator_type get_allocator() const noexcept { return boost::asio::get_associated_allocator(m_handler); }

      void operator()() { std::apply(std::move(m_handler), std::move(m_args)); }

   private:
      Handler m_handler;
      std::tuple<Args...> m_args;
};

template <typename Handler, typename Executor>
class DatagramAsyncBase {
   public:
      DatagramAsyncBase(Handler handler, const Executor& executor) :
            m_handler(std::move(handler)),
            m_cancellation_slot(boost::asio::get_associated_cancellation_slot(m_handler)),
            m_transport_work(boost::asio::make_work_guard(executor)),
            m_completion_work(boost::asio::make_work_guard(boost::asio::get_associated_executor(m_handler, executor))) {
      }

      ~DatagramAsyncBase() { disconnect_cancellation(); }

      DatagramAsyncBase(const DatagramAsyncBase&) = delete;
      DatagramAsyncBase& operator=(const DatagramAsyncBase&) = delete;
      DatagramAsyncBase(DatagramAsyncBase&&) = delete;
      DatagramAsyncBase& operator=(DatagramAsyncBase&&) = delete;

   protected:
      auto get_allocator() const { return boost::asio::get_associated_allocator(m_handler); }

      Executor transport_executor() const { return m_transport_work.get_executor(); }

      template <typename Operation>
      void connect_cancellation(const std::shared_ptr<Operation>& operation) {
         if(m_cancellation_slot.is_connected()) {
            m_cancellation_slot.assign([weak = std::weak_ptr(operation)](boost::asio::cancellation_type_t type) {
               if((type & boost::asio::cancellation_type::terminal) != boost::asio::cancellation_type::none) {
                  if(auto op = weak.lock()) {
                     op->cancel();
                  }
               }
            });
            m_cancellation_connected = true;
         }
      }

      void request_cancellation() {
         m_cancelled = true;
         m_transport_cancellation.emit(boost::asio::cancellation_type::terminal);
      }

      bool cancelled() const { return m_cancelled; }

      void check_operation_cancellation(boost::system::error_code& ec) const {
         if(m_cancelled) {
            ec = boost::asio::error::operation_aborted;
         }
      }

      template <typename Callback>
      auto transport_handler(Callback callback) {
         return boost::asio::bind_cancellation_slot(m_transport_cancellation.slot(),
                                                    DatagramAllocatedHandler(std::move(callback), get_allocator()));
      }

      template <typename... Args>
      void complete(Args... args) {
         disconnect_cancellation();
         const auto executor = m_completion_work.get_executor();
         const auto allocator = boost::asio::get_associated_allocator(m_handler);
         // Release the composed operation's state on the serialized transport
         // executor before a different executor can invoke the user handler.
         auto deliver = [executor,
                         completion = DatagramCompletion<Handler, Args...>(std::move(m_handler), std::move(args)...),
                         work = std::move(m_completion_work)]() mutable {
            boost::asio::post(executor, std::move(completion));
            work.reset();
         };
         boost::asio::post(m_transport_work.get_executor(), DatagramAllocatedHandler(std::move(deliver), allocator));
         m_transport_work.reset();
      }

   private:
      void disconnect_cancellation() {
         if(m_cancellation_connected) {
            m_cancellation_slot.clear();
            m_cancellation_connected = false;
         }
      }

      Handler m_handler;
      boost::asio::associated_cancellation_slot_t<Handler> m_cancellation_slot;
      boost::asio::cancellation_signal m_transport_cancellation;
      bool m_cancellation_connected = false;
      bool m_cancelled = false;
      boost::asio::executor_work_guard<Executor> m_transport_work;
      boost::asio::executor_work_guard<boost::asio::associated_executor_t<Handler, Executor>> m_completion_work;
};

template <typename Operation, typename Handler, typename... Args>
auto make_datagram_operation(Handler&& handler, Args&&... args) {
   const auto allocator = boost::asio::get_associated_allocator(handler);
   return std::allocate_shared<Operation>(allocator, std::forward<Handler>(handler), std::forward<Args>(args)...);
}

}  // namespace detail

/**
 * DTLS over a connected datagram transport. All access must be serialized with
 * the transport's executor (for example by using an Asio strand).
 * Custom transports must provide lowest_layer().cancel(error_code&) and either a
 * remote_endpoint() or a custom Callbacks::tls_peer_network_identity() implementation.
 *
 * The wrapper and application buffers must outlive pending user operations. Moving
 * with pending user operations is unsupported. Associated cancellation slots support
 * terminal cancellation only. Call cancel() to stop remaining I/O and protocol work,
 * then wait for outstanding completions before destroying the wrapper.
 */
template <class DatagramLayer, class ChannelT = Channel>
class Datagram {
   private:
      class EncryptedFlush {
         public:
            EncryptedFlush() = default;
            virtual ~EncryptedFlush() = default;
            EncryptedFlush(const EncryptedFlush&) = delete;
            EncryptedFlush& operator=(const EncryptedFlush&) = delete;
            EncryptedFlush(EncryptedFlush&&) = delete;
            EncryptedFlush& operator=(EncryptedFlush&&) = delete;
            virtual void post_resume() = 0;
      };

      class DeferredState {
         public:
            explicit DeferredState(Datagram& datagram) : m_owner(&datagram), m_timer(datagram.get_executor()) {}

         private:
            friend class Datagram;
            Datagram* m_owner;
            boost::asio::steady_timer m_timer;
            std::multimap<uint64_t, std::function<void()>> m_operations;
            uint64_t m_generation = 0;
            bool m_asynchronous = false;
      };

      using default_completion_token =
         boost::asio::default_completion_token_t<typename std::remove_reference_t<DatagramLayer>::executor_type>;

   public:
      template <typename... Args>
      explicit Datagram(std::shared_ptr<Context> context,
                        std::shared_ptr<DatagramCallbacks> callbacks,
                        DatagramOptions options,
                        Args&&... args) :
            m_context(std::move(context)),
            m_next_layer(std::forward<Args>(args)...),
            m_core(std::move(callbacks)),
            m_options(options),
            m_deferred_state(std::make_shared<DeferredState>(*this)),
            m_input_buffer_space(m_options.encrypted_receive_buffer_size),
            m_input_buffer(m_input_buffer_space.data(), m_input_buffer_space.size()) {
         if(!m_context || !m_core) {
            throw Invalid_Argument("ASIO DTLS requires a context and callbacks");
         }
         if(m_options.receive_queue_limit == 0 || m_options.encrypted_receive_buffer_size == 0) {
            throw Invalid_Argument("ASIO DTLS receive limits must be nonzero");
         }
         if(m_core->m_attached) {
            throw Invalid_Argument("ASIO DTLS callbacks already belong to a wrapper");
         }
         m_core->m_options = m_options;
         m_core->set_context(m_context);
         const auto weak_state = std::weak_ptr(m_deferred_state);
         m_core->m_register_deferred_operation = [weak_state](uint64_t delay_ms, std::function<void()> op) {
            if(auto state = weak_state.lock(); state && state->m_owner) {
               const auto now = state->m_owner->m_core->tls_current_monotonic_clock_ms();
               state->m_operations.emplace(now + delay_ms, std::move(op));
               state->m_owner->schedule_deferred_timer();
            }
         };
         m_core->m_peer_network_identity = [weak_state]() -> std::string {
            if(auto state = weak_state.lock(); state && state->m_owner) {
               const auto& layer = state->m_owner->next_layer();
               if constexpr(requires { layer.remote_endpoint(); }) {
                  const auto peer = layer.remote_endpoint();
                  return peer.address().to_string() + ":" + std::to_string(peer.port());
               } else if constexpr(requires { layer.lowest_layer().remote_endpoint(); }) {
                  const auto peer = layer.lowest_layer().remote_endpoint();
                  return peer.address().to_string() + ":" + std::to_string(peer.port());
               } else {
                  return {};
               }
            }
            return {};
         };
         m_core->m_attached = true;
      }

      template <typename... Args>
      explicit Datagram(std::shared_ptr<Context> context, Args&&... args) :
            Datagram(std::move(context),
                     std::make_shared<DatagramCallbacks>(),
                     DatagramOptions{},
                     std::forward<Args>(args)...) {}

      template <typename Arg>
      explicit Datagram(Arg&& arg,
                        std::shared_ptr<Context> context,
                        std::shared_ptr<DatagramCallbacks> callbacks = std::make_shared<DatagramCallbacks>(),
                        DatagramOptions options = {}) :
            Datagram(std::move(context), std::move(callbacks), options, std::forward<Arg>(arg)) {}

   #if defined(BOTAN_HAS_DEFAULT_TLS_CONTEXT)
      template <typename... Args>
      explicit Datagram(Server_Information server_info, Args&&... args) :
            Datagram(std::make_shared<Context>(std::move(server_info)), std::forward<Args>(args)...) {}
   #endif

      virtual ~Datagram() {
         if(m_deferred_state) {
            stop_deferred_operations();
            m_deferred_state->m_owner = nullptr;
         }
      }

      // Moving requires that no user operations are pending.
      Datagram(Datagram&& other) noexcept(std::is_nothrow_move_constructible_v<DatagramLayer> &&
                                          std::is_nothrow_move_constructible_v<decltype(m_flush_waiters)>) :
            m_context(std::move(other.m_context)),
            m_next_layer(std::forward<DatagramLayer>(other.m_next_layer)),
            m_core(std::move(other.m_core)),
            m_options(other.m_options),
            m_native_handle(std::move(other.m_native_handle)),
            m_ec_from_last_read(other.m_ec_from_last_read),
            m_ec_from_deferred_operation(other.m_ec_from_deferred_operation),
            m_cancel_generation(other.m_cancel_generation),
            m_deferred_state(std::move(other.m_deferred_state)),
            m_flush_in_progress(other.m_flush_in_progress),
            m_flush_waiters(std::move(other.m_flush_waiters)),
            m_input_buffer_space(std::move(other.m_input_buffer_space)),
            m_input_buffer(m_input_buffer_space.data(), m_input_buffer_space.size()) {
         m_deferred_state->m_owner = this;
      }

      Datagram& operator=(Datagram&& other) = delete;

      Datagram(const Datagram& other) = delete;
      Datagram& operator=(const Datagram& other) = delete;

      using next_layer_type = std::remove_reference_t<DatagramLayer>;

      const next_layer_type& next_layer() const { return m_next_layer; }

      next_layer_type& next_layer() { return m_next_layer; }

      using lowest_layer_type = typename next_layer_type::lowest_layer_type;

      lowest_layer_type& lowest_layer() { return m_next_layer.lowest_layer(); }

      const lowest_layer_type& lowest_layer() const { return m_next_layer.lowest_layer(); }

      using executor_type = typename next_layer_type::executor_type;

      executor_type get_executor() noexcept { return m_next_layer.get_executor(); }

      using native_handle_type = std::add_pointer_t<ChannelT>;

      native_handle_type native_handle() {
         if(m_native_handle == nullptr) {
            throw Botan::Invalid_State("ASIO DTLS native handle unexpectedly null");
         }
         return m_native_handle.get();
      }

      const ChannelT* native_handle() const {
         if(m_native_handle == nullptr) {
            throw Botan::Invalid_State("ASIO DTLS native handle unexpectedly null");
         }
         return m_native_handle.get();
      }

      void set_verify_callback(Context::Verify_Callback callback) {
         m_context->set_verify_callback(std::move(callback));
      }

      void set_verify_callback(Context::Verify_Callback callback, boost::system::error_code& ec) {
         ec.clear();
         try_with_error_code([&] { m_context->set_verify_callback(std::move(callback)); }, ec);
      }

      /** Cancel pending operations and stop DTLS retransmissions. */
      void cancel(boost::system::error_code& ec) {
         ec.clear();
         ++m_cancel_generation;
         stop_deferred_operations();
         lowest_layer().cancel(ec);
      }

      void cancel() {
         boost::system::error_code ec;
         cancel(ec);
         boost::asio::detail::throw_error(ec, "cancel");
      }

      void handshake(Connection_Side side) {
         boost::system::error_code ec;
         handshake(side, ec);
         boost::asio::detail::throw_error(ec, "handshake");
      }

      void handshake(Connection_Side side, boost::system::error_code& ec) {
         ec.clear();
         setup_native_handle(side, ec);
         if(ec) {
            return;
         }

         while(!ec) {
            run_deferred_operations(ec);
            send_pending_encrypted_data(ec);

            if(native_handle()->is_handshake_complete()) {
               return;
            }

            handle_tls_protocol_errors(ec);

            const auto read = receive_encrypted_datagram(ec);
            if(!ec) {
               process_encrypted_data(boost::asio::const_buffer(input_buffer().data(), read));
            }

            run_deferred_operations(ec);
            send_pending_encrypted_data(ec);
         }
      }

      template <detail::datagram_completion_token CompletionToken = default_completion_token>
      // Asio's async_initiate requires the completion token as an lvalue.
      // NOLINTNEXTLINE(*-missing-std-forward)
      auto async_handshake(Connection_Side side, CompletionToken&& completion_token = default_completion_token{}) {
         return boost::asio::async_initiate<CompletionToken, void(boost::system::error_code)>(
            [this](auto&& completion_handler, Connection_Side connection_side) {
               using handler_t = std::decay_t<decltype(completion_handler)>;
               auto op = detail::make_datagram_operation<AsyncHandshakeOp<handler_t>>(
                  std::forward<handler_t>(completion_handler), *this, connection_side);
               op->start();
            },
            completion_token,
            side);
      }

      void shutdown(boost::system::error_code& ec) {
         ec.clear();
         try_with_error_code([&] { native_handle()->close(); }, ec);
         send_pending_encrypted_data(ec);
         stop_deferred_operations();
      }

      void shutdown() {
         boost::system::error_code ec;
         shutdown(ec);
         boost::asio::detail::throw_error(ec, "shutdown");
      }

      template <detail::datagram_completion_token CompletionToken = default_completion_token>
      // NOLINTNEXTLINE(*-missing-std-forward)
      auto async_shutdown(CompletionToken&& completion_token = default_completion_token{}) {
         return boost::asio::async_initiate<CompletionToken, void(boost::system::error_code)>(
            [this](auto&& completion_handler) {
               using handler_t = std::decay_t<decltype(completion_handler)>;
               boost::system::error_code ec;
               try_with_error_code([&] { native_handle()->close(); }, ec);
               stop_deferred_operations();
               auto op = detail::make_datagram_operation<AsyncFlushOp<handler_t>>(
                  std::forward<handler_t>(completion_handler), *this, ec);
               op->start();
            },
            completion_token);
      }

      template <typename ConstBufferSequence>
      size_t send(const ConstBufferSequence& buffers, boost::system::error_code& ec) {
         ec.clear();
         const auto plain_size = boost::asio::buffer_size(buffers);
         if(plain_size > MAX_PLAINTEXT_SIZE) {
            ec = boost::asio::error::message_size;
            return 0;
         }

         tls_encrypt(buffers, ec);
         send_pending_encrypted_data(ec);
         return !ec ? plain_size : 0;
      }

      template <typename ConstBufferSequence>
      size_t send(const ConstBufferSequence& buffers) {
         boost::system::error_code ec;
         const auto n = send(buffers, ec);
         boost::asio::detail::throw_error(ec, "send");
         return n;
      }

      template <typename ConstBufferSequence,
                detail::datagram_size_completion_token CompletionToken = default_completion_token>
      auto async_send(const ConstBufferSequence& buffers,
                      // NOLINTNEXTLINE(*-missing-std-forward)
                      CompletionToken&& completion_token = default_completion_token{}) {
         return boost::asio::async_initiate<CompletionToken, void(boost::system::error_code, size_t)>(
            [this](auto&& completion_handler, const auto& bufs) {
               using handler_t = std::decay_t<decltype(completion_handler)>;
               boost::system::error_code ec;
               const auto plain_size = boost::asio::buffer_size(bufs);
               if(plain_size > MAX_PLAINTEXT_SIZE) {
                  ec = boost::asio::error::message_size;
               } else {
                  tls_encrypt(bufs, ec);
               }
               auto op = detail::make_datagram_operation<AsyncFlushOp<handler_t, true>>(
                  std::forward<handler_t>(completion_handler), *this, ec, plain_size);
               op->start();
            },
            completion_token,
            buffers);
      }

      template <typename MutableBufferSequence>
      size_t receive(const MutableBufferSequence& buffers, boost::system::error_code& ec) {
         ec.clear();
         if(auto n = m_core->copy_received_datagram(buffers, ec); ec || n > 0) {
            return n;
         }

         handle_tls_protocol_errors(ec);

         while(!ec) {
            const auto read = receive_encrypted_datagram(ec);
            if(ec) {
               return 0;
            }

            process_encrypted_data(boost::asio::const_buffer(input_buffer().data(), read));
            send_pending_encrypted_data(ec);
            if(ec) {
               return 0;
            }

            if(auto n = m_core->copy_received_datagram(buffers, ec); ec || n > 0) {
               return n;
            }

            handle_tls_protocol_errors(ec);
         }

         return 0;
      }

      template <typename MutableBufferSequence>
      size_t receive(const MutableBufferSequence& buffers) {
         boost::system::error_code ec;
         const auto n = receive(buffers, ec);
         boost::asio::detail::throw_error(ec, "receive");
         return n;
      }

      template <typename MutableBufferSequence,
                detail::datagram_size_completion_token CompletionToken = default_completion_token>
      auto async_receive(const MutableBufferSequence& buffers,
                         // NOLINTNEXTLINE(*-missing-std-forward)
                         CompletionToken&& completion_token = default_completion_token{}) {
         return boost::asio::async_initiate<CompletionToken, void(boost::system::error_code, size_t)>(
            [this](auto&& completion_handler, const auto& bufs) {
               using handler_t = std::decay_t<decltype(completion_handler)>;
               auto op = detail::make_datagram_operation<AsyncReceiveOp<handler_t, MutableBufferSequence>>(
                  std::forward<handler_t>(completion_handler), *this, bufs);
               op->start();
            },
            completion_token,
            buffers);
      }

      bool shutdown_received() const { return m_core->shutdown_received(); }

   protected:
      std::shared_ptr<DatagramCallbacks> callbacks() { return m_core; }

      void set_native_handle(std::unique_ptr<ChannelT> handle)
         requires(!std::is_same_v<ChannelT, Channel>)
      {
         if(!handle || m_native_handle) {
            throw Invalid_State("ASIO DTLS custom native handle must be set exactly once");
         }
         m_native_handle = std::move(handle);
      }

   private:
      const boost::asio::mutable_buffer& input_buffer() { return m_input_buffer; }

      bool has_data_to_send() const { return m_core->has_send_data(); }

      bool has_received_data() const { return m_core->has_received_data(); }

      void setup_native_handle(Connection_Side side, boost::system::error_code& ec) {
         if constexpr(std::is_same_v<ChannelT, Channel>) {
            if(m_native_handle != nullptr) {
               throw Botan::Invalid_State("ASIO DTLS native handle unexpectedly set");
            }

            try_with_error_code(
               [&] {
                  if(!m_context->m_policy->allow_dtls12()) {
                     throw TLS_Exception(AlertType::ProtocolVersion, "Configured TLS policy does not allow DTLS 1.2");
                  }

                  if(side == Connection_Side::Client) {
                     m_native_handle = std::make_unique<Client>(m_core,
                                                                m_context->m_session_manager,
                                                                m_context->m_credentials_manager,
                                                                m_context->m_policy,
                                                                m_context->m_rng,
                                                                m_context->m_server_info,
                                                                Protocol_Version::latest_dtls_version(),
                                                                m_context->m_app_protocols);
                  } else {
                     m_native_handle = std::make_unique<Server>(m_core,
                                                                m_context->m_session_manager,
                                                                m_context->m_credentials_manager,
                                                                m_context->m_policy,
                                                                m_context->m_rng,
                                                                true /* DTLS */);
                  }
               },
               ec);
         }
      }

      size_t send_pending_encrypted_data(boost::system::error_code& ec) {
         size_t sent = 0;
         while(!ec && has_data_to_send()) {
            sent += m_next_layer.send(m_core->next_send_datagram(), 0, ec);
            if(!ec) {
               m_core->consume_send_datagram();
            }
         }
         return sent;
      }

      size_t receive_encrypted_datagram(boost::system::error_code& ec) {
         check_cancellation(ec, m_cancel_generation);
         if(ec) {
            return 0;
         }
         // Synchronous UDP reads must not block past a retransmission deadline.
         if constexpr(requires {
                         lowest_layer().non_blocking();
                         lowest_layer().non_blocking(true, ec);
                      }) {
            if(lowest_layer().non_blocking()) {
               run_deferred_operations(ec);
               send_pending_encrypted_data(ec);
               return ec ? 0 : m_next_layer.receive(input_buffer(), 0, ec);
            }
            if(m_deferred_state->m_operations.empty()) {
               return m_next_layer.receive(input_buffer(), 0, ec);
            }
            lowest_layer().non_blocking(true, ec);
            size_t received = 0;
            while(!ec) {
               run_deferred_operations(ec);
               send_pending_encrypted_data(ec);
               if(ec) {
                  break;
               }
               if(m_deferred_state->m_operations.empty()) {
                  // With no remaining deadline, an idle application receive can block normally.
                  lowest_layer().non_blocking(false, ec);
                  received = ec ? 0 : m_next_layer.receive(input_buffer(), 0, ec);
                  break;
               }
               received = m_next_layer.receive(input_buffer(), 0, ec);
               if(ec != boost::asio::error::would_block && ec != boost::asio::error::try_again) {
                  break;
               }
               ec.clear();
               std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            boost::system::error_code restore_ec;
            lowest_layer().non_blocking(false, restore_ec);
            if(!ec) {
               ec = restore_ec;
            }
            return received;
         } else {
            run_deferred_operations(ec);
            send_pending_encrypted_data(ec);
            return ec ? 0 : m_next_layer.receive(input_buffer(), 0, ec);
         }
      }

      template <typename ConstBufferSequence>
      void tls_encrypt(const ConstBufferSequence& buffers, boost::system::error_code& ec) {
         std::vector<uint8_t> copy_buffer;
         auto unpack = [&copy_buffer](const auto& bufs) -> std::span<const uint8_t> {
            const auto buffers_in_sequence =
               std::distance(boost::asio::buffer_sequence_begin(bufs), boost::asio::buffer_sequence_end(bufs));

            if(buffers_in_sequence == 0) {
               return {};
            } else if(buffers_in_sequence == 1) {
               const boost::asio::const_buffer buf = *boost::asio::buffer_sequence_begin(bufs);
               return {static_cast<const uint8_t*>(buf.data()), buf.size()};
            } else {
               copy_buffer.resize(boost::asio::buffer_size(bufs));
               boost::asio::buffer_copy(boost::asio::buffer(copy_buffer), bufs);
               return copy_buffer;
            }
         };

         try_with_error_code([&] { native_handle()->send(unpack(buffers)); }, ec);
      }

      void process_encrypted_data(const boost::asio::const_buffer& read_buffer) {
         try_with_error_code(
            [&] {
               native_handle()->received_data({static_cast<const uint8_t*>(read_buffer.data()), read_buffer.size()});
            },
            m_ec_from_last_read);
      }

      void handle_tls_protocol_errors(boost::system::error_code& ec) {
         if(m_ec_from_deferred_operation) {
            ec = m_ec_from_deferred_operation;
         } else if(ec) {
            return;
         } else if(m_ec_from_last_read) {
            ec = m_ec_from_last_read;
         } else if(auto alert = m_core->alert_from_peer()) {
            if(alert->type() == AlertType::CloseNotify) {
               ec = boost::asio::error::eof;
            } else {
               ec = alert->type();
            }
         }
      }

      template <typename Fun>
      void try_with_error_code(Fun&& f, boost::system::error_code& ec) {
         try {
            std::forward<Fun>(f)();
         } catch(const TLS_Exception& e) {
            if(e.type() == AlertType::None) {
               ec = boost::asio::error::timed_out;
            } else {
               ec = e.type();
            }
         } catch(const Exception& e) {
            ec = e.error_type();
         } catch(const std::exception&) {
            ec = ErrorType::Unknown;
         }
      }

      void check_cancellation(boost::system::error_code& ec, uint64_t generation) const {
         if(m_ec_from_deferred_operation) {
            ec = m_ec_from_deferred_operation;
         } else if(generation != m_cancel_generation) {
            ec = boost::asio::error::operation_aborted;
         }
      }

   protected:
      void start_deferred_operations() {
         m_deferred_state->m_asynchronous = true;
         schedule_deferred_timer();
      }

   private:
      void stop_deferred_operations() {
         ++m_deferred_state->m_generation;
         m_deferred_state->m_operations.clear();
         try {
            m_deferred_state->m_timer.cancel();
         } catch(const boost::system::system_error&) {
            // Cancellation is best effort; generation/lifetime checks still invalidate the handler.
         }
      }

      void run_deferred_operations(boost::system::error_code& ec) {
         auto& operations = m_deferred_state->m_operations;
         while(!ec && !operations.empty() && operations.begin()->first <= m_core->tls_current_monotonic_clock_ms()) {
            auto node = operations.extract(operations.begin());
            try_with_error_code(node.mapped(), ec);
         }
      }

      void fail_deferred_operation(boost::system::error_code ec) {
         if(!ec || m_ec_from_deferred_operation) {
            return;
         }
         m_ec_from_deferred_operation = ec;
         stop_deferred_operations();
         // Wake pending receives so their completion reports the original timer error.
         boost::system::error_code ignored;
         lowest_layer().cancel(ignored);
      }

      void schedule_deferred_timer() {
         auto& timer_state = *m_deferred_state;
         if(!timer_state.m_asynchronous || timer_state.m_operations.empty()) {
            return;
         }
         const auto now = m_core->tls_current_monotonic_clock_ms();
         const auto deadline = timer_state.m_operations.begin()->first;
         timer_state.m_timer.expires_after(std::chrono::milliseconds(deadline > now ? deadline - now : 0));
         const auto generation = ++timer_state.m_generation;
         timer_state.m_timer.async_wait([weak_state = std::weak_ptr(m_deferred_state),
                                         generation](boost::system::error_code ec) {
            const auto state = weak_state.lock();
            if(ec || !state || !state->m_owner || generation != state->m_generation) {
               return;
            }
            auto& datagram = *state->m_owner;
            datagram.run_deferred_operations(ec);
            if(ec) {
               datagram.fail_deferred_operation(ec);
               return;
            }
            datagram.async_flush([weak_state,
                                  cancel_generation = datagram.m_cancel_generation](boost::system::error_code send_ec) {
               if(const auto live_state = weak_state.lock();
                  live_state && live_state->m_owner && cancel_generation == live_state->m_owner->m_cancel_generation) {
                  live_state->m_owner->fail_deferred_operation(send_ec);
               }
            });
            datagram.schedule_deferred_timer();
         });
      }

      template <typename Handler>
      void async_flush(Handler handler) {
         auto op = detail::make_datagram_operation<AsyncEncryptedFlushOp<Handler>>(std::move(handler), *this);
         op->start();
      }

      // Each flush owns its handler associations and cancellation. Requests wait
      // for exclusive access to the encrypted queue, rather than sharing a send
      // whose cancellation would affect unrelated operations.
      template <typename Handler>
      class AsyncEncryptedFlushOp final : public EncryptedFlush,
                                          public detail::DatagramAsyncBase<Handler, executor_type>,
                                          public std::enable_shared_from_this<AsyncEncryptedFlushOp<Handler>> {
         public:
            AsyncEncryptedFlushOp(Handler handler, Datagram& datagram) :
                  detail::DatagramAsyncBase<Handler, executor_type>(std::move(handler), datagram.get_executor()),
                  m_state(datagram.m_deferred_state),
                  m_generation(datagram.m_cancel_generation) {}

            void start() {
               this->connect_cancellation(this->shared_from_this());
               auto* datagram = owner();
               if(datagram == nullptr) {
                  finish(boost::asio::error::operation_aborted);
                  return;
               }
               if(datagram->m_flush_in_progress) {
                  datagram->m_flush_waiters.push_back(this->shared_from_this());
               } else {
                  datagram->m_flush_in_progress = true;
                  resume();
               }
            }

            void post_resume() override {
               auto self = this->shared_from_this();
               boost::asio::post(this->transport_executor(),
                                 detail::DatagramAllocatedHandler([self] { self->resume(); }, this->get_allocator()));
            }

            void cancel() {
               this->request_cancellation();
               if(m_phase == Phase::Waiting) {
                  if(auto* datagram = owner(); datagram != nullptr) {
                     auto& waiters = datagram->m_flush_waiters;
                     const auto it = std::find_if(
                        waiters.begin(), waiters.end(), [this](const auto& waiter) { return waiter.get() == this; });
                     if(it != waiters.end()) {
                        waiters.erase(it);
                        finish(boost::asio::error::operation_aborted);
                     }
                  }
                  // A request already posted for resumption observes cancellation there.
               }
            }

         private:
            enum class Phase : uint8_t { Waiting, Sending, Complete };

            Datagram* owner() const {
               const auto state = m_state.lock();
               return state ? state->m_owner : nullptr;
            }

            void resume() {
               m_phase = Phase::Sending;
               auto* datagram = owner();
               if(datagram == nullptr) {
                  finish(boost::asio::error::operation_aborted);
                  return;
               }
               boost::system::error_code ec;
               datagram->check_cancellation(ec, m_generation);
               this->check_operation_cancellation(ec);
               if(ec || !datagram->has_data_to_send()) {
                  finish(ec);
                  return;
               }

               // The copy survives destruction or movement of a wrapper while
               // a background retransmission is pending. Its storage also uses
               // the initiating handler's allocator.
               auto allocator = this->get_allocator();
               using byte_allocator =
                  typename std::allocator_traits<decltype(allocator)>::template rebind_alloc<uint8_t>;
               using buffer_type = std::vector<uint8_t, byte_allocator>;
               const auto data = datagram->m_core->next_send_datagram();
               const auto* begin = static_cast<const uint8_t*>(data.data());
               auto buffer =
                  std::allocate_shared<buffer_type>(allocator, begin, begin + data.size(), byte_allocator(allocator));
               auto self = this->shared_from_this();
               datagram->m_next_layer.async_send(
                  boost::asio::buffer(*buffer),
                  this->transport_handler([self, buffer](boost::system::error_code send_ec, size_t) {
                     auto* live_datagram = self->owner();
                     if(live_datagram) {
                        if(!send_ec) {
                           live_datagram->m_core->consume_send_datagram();
                        }
                        live_datagram->check_cancellation(send_ec, self->m_generation);
                     } else {
                        send_ec = boost::asio::error::operation_aborted;
                     }
                     self->check_operation_cancellation(send_ec);
                     if(send_ec) {
                        self->finish(send_ec);
                     } else {
                        self->resume();
                     }
                  }));
            }

            void finish(boost::system::error_code ec) {
               detail::DatagramAsyncBase<Handler, executor_type>::complete(ec);
               if(std::exchange(m_phase, Phase::Complete) == Phase::Sending) {
                  if(auto* datagram = owner(); datagram != nullptr) {
                     datagram->m_flush_in_progress = false;
                     if(!datagram->m_flush_waiters.empty()) {
                        auto next = std::move(datagram->m_flush_waiters.front());
                        datagram->m_flush_waiters.pop_front();
                        datagram->m_flush_in_progress = true;
                        next->post_resume();
                     }
                  }
               }
            }

            std::weak_ptr<DeferredState> m_state;
            uint64_t m_generation;
            Phase m_phase = Phase::Waiting;
      };

      template <typename Handler, bool WithSize = false>
      class AsyncFlushOp : public detail::DatagramAsyncBase<Handler, executor_type>,
                           public std::enable_shared_from_this<AsyncFlushOp<Handler, WithSize>> {
         public:
            AsyncFlushOp(Handler handler,
                         Datagram& datagram,
                         boost::system::error_code ec = {},
                         size_t plain_size = 0) :
                  detail::DatagramAsyncBase<Handler, executor_type>(std::move(handler), datagram.get_executor()),
                  m_datagram(datagram),
                  m_plain_size(plain_size),
                  m_ec(ec),
                  m_generation(datagram.m_cancel_generation) {}

            void start() {
               this->connect_cancellation(this->shared_from_this());
               if constexpr(WithSize) {
                  m_datagram.start_deferred_operations();
               }
               flush_or_finish(m_ec);
            }

            void cancel() { this->request_cancellation(); }

         private:
            void flush_or_finish(boost::system::error_code ec) {
               m_datagram.check_cancellation(ec, m_generation);
               this->check_operation_cancellation(ec);
               if(ec || !m_datagram.has_data_to_send()) {
                  if constexpr(WithSize) {
                     this->complete(ec, ec ? size_t(0) : m_plain_size);
                  } else {
                     this->complete(ec);
                  }
                  return;
               }

               auto self = this->shared_from_this();
               m_datagram.async_flush(this->transport_handler(
                  [self](boost::system::error_code send_ec) { self->flush_or_finish(send_ec); }));
            }

            Datagram& m_datagram;
            size_t m_plain_size;
            boost::system::error_code m_ec;
            uint64_t m_generation;
      };

      template <typename Handler, typename MutableBufferSequence>
      class AsyncReceiveOp : public detail::DatagramAsyncBase<Handler, executor_type>,
                             public std::enable_shared_from_this<AsyncReceiveOp<Handler, MutableBufferSequence>> {
         public:
            AsyncReceiveOp(Handler handler, Datagram& datagram, MutableBufferSequence buffers) :
                  detail::DatagramAsyncBase<Handler, executor_type>(std::move(handler), datagram.get_executor()),
                  m_datagram(datagram),
                  m_buffers(std::move(buffers)),
                  m_generation(datagram.m_cancel_generation) {}

            void start() {
               boost::system::error_code ec;
               this->connect_cancellation(this->shared_from_this());
               m_datagram.check_cancellation(ec, m_generation);
               this->check_operation_cancellation(ec);
               const auto copied = ec ? 0 : m_datagram.m_core->copy_received_datagram(m_buffers, ec);
               if(copied == 0) {
                  m_datagram.handle_tls_protocol_errors(ec);
               }
               if(ec || copied > 0) {
                  m_ec = ec;
                  m_copied = copied;
                  finish();
                  return;
               }

               m_datagram.start_deferred_operations();

               read_more();
            }

            void cancel() { this->request_cancellation(); }

            void read_more() {
               m_datagram.check_cancellation(m_ec, m_generation);
               this->check_operation_cancellation(m_ec);
               if(m_ec) {
                  m_flush_allowed = false;
                  flush_or_finish();
                  return;
               }
               auto self = this->shared_from_this();
               m_datagram.m_next_layer.async_receive(
                  m_datagram.input_buffer(),
                  this->transport_handler([self](boost::system::error_code ec, size_t transferred) {
                     self->m_datagram.check_cancellation(ec, self->m_generation);
                     self->check_operation_cancellation(ec);
                     self->m_flush_allowed = !ec;
                     if(!ec) {
                        self->m_datagram.process_encrypted_data(
                           boost::asio::const_buffer(self->m_datagram.input_buffer().data(), transferred));
                     }

                     self->m_ec = ec;
                     self->m_copied = self->m_datagram.m_core->copy_received_datagram(self->m_buffers, self->m_ec);
                     self->m_datagram.handle_tls_protocol_errors(self->m_ec);
                     self->flush_or_finish();
                  }));
            }

            void flush_or_finish() {
               m_datagram.check_cancellation(m_ec, m_generation);
               this->check_operation_cancellation(m_ec);
               if(this->cancelled() || m_generation != m_datagram.m_cancel_generation) {
                  m_flush_allowed = false;
                  m_copied = 0;
               }
               if(m_flush_allowed && m_datagram.has_data_to_send()) {
                  auto self = this->shared_from_this();
                  m_datagram.async_flush(this->transport_handler([self](boost::system::error_code ec) {
                     if(ec) {
                        self->m_flush_allowed = false;
                        if(!self->m_ec) {
                           self->m_ec = ec;
                        }
                     }
                     self->flush_or_finish();
                  }));
                  return;
               }

               if(m_ec || m_copied > 0) {
                  finish();
               } else {
                  read_more();
               }
            }

         private:
            void finish() {
               const bool retryable = m_ec == boost::asio::error::message_size || m_ec == DatagramReceiveQueueOverflow;
               if(m_ec && !retryable && !this->cancelled()) {
                  m_datagram.stop_deferred_operations();
               }
               this->complete(m_ec, m_copied);
            }

            Datagram& m_datagram;
            MutableBufferSequence m_buffers;
            uint64_t m_generation;
            boost::system::error_code m_ec;
            size_t m_copied = 0;
            bool m_flush_allowed = true;
      };

      template <typename Handler>
      class AsyncHandshakeOp : public detail::DatagramAsyncBase<Handler, executor_type>,
                               public std::enable_shared_from_this<AsyncHandshakeOp<Handler>> {
         public:
            AsyncHandshakeOp(Handler handler, Datagram& datagram, Connection_Side side) :
                  detail::DatagramAsyncBase<Handler, executor_type>(std::move(handler), datagram.get_executor()),
                  m_datagram(datagram),
                  m_side(side),
                  m_generation(datagram.m_cancel_generation) {}

            void start() {
               this->connect_cancellation(this->shared_from_this());
               m_datagram.setup_native_handle(m_side, m_ec);
               if(m_ec) {
                  complete(m_ec);
                  return;
               }
               m_datagram.start_deferred_operations();
               flush_or_read();
            }

            void cancel() {
               this->request_cancellation();
               // Handshake I/O cannot overlap another user operation. Also stop
               // protocol-owned retransmissions that may currently own the send queue.
               boost::system::error_code ignored;
               m_datagram.cancel(ignored);
            }

            void flush_or_read() {
               m_datagram.check_cancellation(m_ec, m_generation);
               this->check_operation_cancellation(m_ec);
               if(m_ec) {
                  complete(m_ec);
                  return;
               }

               if(m_datagram.has_data_to_send()) {
                  auto self = this->shared_from_this();
                  m_datagram.async_flush(this->transport_handler([self](boost::system::error_code ec) {
                     self->m_ec = ec;
                     self->flush_or_read();
                  }));
                  return;
               }

               if(m_datagram.native_handle()->is_handshake_complete()) {
                  complete({});
                  return;
               }

               m_datagram.handle_tls_protocol_errors(m_ec);
               if(m_ec) {
                  complete(m_ec);
                  return;
               }

               auto self = this->shared_from_this();
               m_datagram.m_next_layer.async_receive(
                  m_datagram.input_buffer(),
                  this->transport_handler([self](boost::system::error_code ec, size_t transferred) {
                     self->m_datagram.check_cancellation(ec, self->m_generation);
                     self->check_operation_cancellation(ec);
                     if(!ec) {
                        self->m_datagram.process_encrypted_data(
                           boost::asio::const_buffer(self->m_datagram.input_buffer().data(), transferred));
                     }
                     self->m_ec = ec;
                     self->flush_or_read();
                  }));
            }

            void complete(boost::system::error_code ec) {
               if(ec) {
                  m_datagram.stop_deferred_operations();
               }
               detail::DatagramAsyncBase<Handler, executor_type>::complete(ec);
            }

         private:
            Datagram& m_datagram;
            Connection_Side m_side;
            uint64_t m_generation;
            boost::system::error_code m_ec;
      };

      std::shared_ptr<Context> m_context;
      DatagramLayer m_next_layer;
      std::shared_ptr<DatagramCallbacks> m_core;
      DatagramOptions m_options;
      std::unique_ptr<ChannelT> m_native_handle;
      boost::system::error_code m_ec_from_last_read;
      boost::system::error_code m_ec_from_deferred_operation;
      uint64_t m_cancel_generation = 0;
      std::shared_ptr<DeferredState> m_deferred_state;
      bool m_flush_in_progress = false;
      std::deque<std::shared_ptr<EncryptedFlush>> m_flush_waiters;
      std::vector<uint8_t> m_input_buffer_space;
      const boost::asio::mutable_buffer m_input_buffer;
};

template <typename T>
Datagram(Server_Information, T) -> Datagram<T>;
template <typename T>
Datagram(std::shared_ptr<Context>, std::shared_ptr<DatagramCallbacks>, DatagramOptions, T) -> Datagram<T>;
template <typename T>
Datagram(std::shared_ptr<Context>, T) -> Datagram<T>;
template <typename T>
Datagram(T, std::shared_ptr<Context>) -> Datagram<T>;

}  // namespace Botan::TLS

#endif
#endif  // BOTAN_ASIO_DATAGRAM_H_
