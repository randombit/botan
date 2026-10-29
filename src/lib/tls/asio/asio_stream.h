/*
* TLS ASIO Stream
* (C) 2018-2021 Jack Lloyd
*     2018-2021 Hannes Rantzsch, Tim Oesterreich, Rene Meusel
*     2023      Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ASIO_STREAM_H_
#define BOTAN_ASIO_STREAM_H_

#include <botan/asio_compat.h>
#if !defined(BOTAN_FOUND_COMPATIBLE_BOOST_ASIO_VERSION)
   #error Available boost headers are too old for the boost asio stream.
#else

   #include <botan/asio_async_ops.h>
   #include <botan/asio_context.h>
   #include <botan/asio_error.h>

   #include <botan/tls_callbacks.h>
   #include <botan/tls_channel.h>
   #include <botan/tls_client.h>
   #include <botan/tls_magic.h>
   #include <botan/tls_server.h>

   // We need to define BOOST_ASIO_DISABLE_SERIAL_PORT before any asio imports. Otherwise asio will include <termios.h>,
   // which interferes with Botan's amalgamation by defining macros like 'B0' and 'FF1'.
   #define BOOST_ASIO_DISABLE_SERIAL_PORT
   #include <boost/asio.hpp>
   #include <boost/beast/core.hpp>

   #include <algorithm>
   #include <exception>
   #include <memory>
   #include <new>
   #include <span>
   #include <stdexcept>
   #include <type_traits>
   #include <utility>
   #include <vector>

namespace Botan::TLS {

template <class SL, class C>
class Stream;

namespace detail {

/**
 * @brief The records emitted by the TLS implementation, on their way to the next layer
 *
 * Records are written in the order they were emitted, by one write at a time.
 * The records lent to the next layer by that write are kept apart from the
 * ones emitted in the meantime, which may reallocate the queue's storage.
 * Whatever the next layer did not accept stays in flight and goes out first
 * with the next write, so no record is lost or reordered. Read operations
 * mark the output emitted so far and wait until it is written, whoever writes
 * it. Only push() allocates; everything else may run in a completion handler.
 */
class OutputQueue {
   public:
      //! @brief Append a record; a record that cannot be buffered is refused up front, leaving the queue untouched
      void push(std::span<const uint8_t> record) {
         if(record.size() > m_queued.max_size() - m_queued.size()) {
            throw std::length_error("TLS record does not fit the output queue");
         }
         m_queued.insert(m_queued.end(), record.begin(), record.end());
      }

      //! @brief Check whether a write is lending records to the next layer
      bool write_in_progress() const { return m_write_in_progress; }

      //! @brief Check if records are waiting to be written (queued, or left behind by the last write)
      bool has_data() const { return !m_queued.empty() || (!m_write_in_progress && in_flight().size() > 0); }

      /**
       * @brief Lend the records to write next to the next layer
       *
       * Whatever the previous write did not get through goes out first, on its
       * own. The records queued since are taken (by swapping storage) once the
       * in-flight buffer is empty.
       *
       * @return the records to write
       */
      boost::asio::const_buffer begin_write() {
         if(m_write_in_progress || !has_data()) {
            throw Botan::Invalid_State("ASIO TLS stream write already in progress or nothing to write");
         }

         if(in_flight().size() == 0) {
            m_in_flight.clear();
            m_in_flight_offset = 0;
            std::swap(m_in_flight, m_queued);
         }
         m_write_in_progress = true;
         return in_flight();
      }

      /**
       * @brief Take back the records lent by begin_write()
       *
       * Records the next layer did not accept stay in flight; whoever writes
       * next continues exactly where this write stopped.
       *
       * @param bytes_transferred the number of bytes the next layer accepted
       */
      void end_write(std::size_t bytes_transferred) {
         const auto accepted = std::min(bytes_transferred, in_flight().size());
         m_in_flight_offset += accepted;
         m_written += accepted;
         if(m_in_flight_offset == m_in_flight.size()) {
            m_in_flight.clear();
            m_in_flight_offset = 0;
         }
         m_write_in_progress = false;
      }

      //! @brief Have everything emitted so far written before a read operation reports a condition or consumes input
      void mark_pending() {
         if(has_data()) {
            m_pending_mark = position();
         }
      }

      //! @brief Check whether records marked by mark_pending() are still waiting to be written
      bool pending() const { return m_written < m_pending_mark; }

      //! @brief Number of bytes queued but not lent out yet, see truncate()
      std::size_t queued_size() const { return m_queued.size(); }

      //! @brief Drop the queued records beyond the first @p keep bytes, i.e. those emitted since queued_size() was @p keep
      void truncate(std::size_t keep) {
         if(m_queued.size() > keep) {
            m_queued.resize(keep);
            // Read operations must not wait for records that no longer exist
            m_pending_mark = std::min(m_pending_mark, position());
         }
      }

      //! @brief Discard everything, for a new connection
      void clear() {
         m_queued.clear();
         m_in_flight.clear();
         m_in_flight_offset = 0;
         m_write_in_progress = false;
         m_written = 0;
         m_pending_mark = 0;
      }

   private:
      //! @brief The records currently lent to the next layer, or left behind by the last write
      boost::asio::const_buffer in_flight() const {
         return {m_in_flight.data() + m_in_flight_offset, m_in_flight.size() - m_in_flight_offset};
      }

      //! @brief Position of the end of the records emitted so far in the stream of output bytes
      uint64_t position() const { return m_written + in_flight().size() + m_queued.size(); }

      std::vector<uint8_t> m_queued;
      std::vector<uint8_t> m_in_flight;
      std::size_t m_in_flight_offset = 0;
      bool m_write_in_progress = false;
      uint64_t m_written = 0;
      uint64_t m_pending_mark = 0;
};

}  // namespace detail

/**
 * @brief Specialization of TLS::Callbacks for the ASIO Stream
 *
 * Applications may decide to derive from this for fine-grained customizations
 * of the TLS::Stream's behaviour. Examples may be OCSP integration, custom
 * certificate validation or user-defined key exchange mechanisms.
 *
 * By default, this class provides all necessary customizations for the ASIO
 * integration. The methods required for that are `final` and cannot be
 * overridden.
 *
 * Each instance of TLS::Stream must have their own instance of this class;
 * constructing a Stream with an instance that is still in use by another
 * Stream throws Invalid_Argument. A future major version of Botan will
 * therefor consume instances of this class as a std::unique_ptr. The current
 * usage of std::shared_ptr is erratic.
 */
class StreamCallbacks : public Callbacks {
   public:
      StreamCallbacks() = default;

      void tls_emit_data(std::span<const uint8_t> data) final {
         try {
            m_output.push(data);
         } catch(...) {
            // The TLS implementation swallows this when the record is an alert,
            // see Stream::call_tls()
            m_emit_failure = std::current_exception();
            throw;
         }
      }

      void tls_record_received(uint64_t /*record_number*/, std::span<const uint8_t> data) final {
         m_receive_buffer.commit(boost::asio::buffer_copy(m_receive_buffer.prepare(data.size()),
                                                          boost::asio::const_buffer(data.data(), data.size())));
      }

      bool tls_peer_closed_connection() final {
         // Instruct the TLS implementation to reply with our close_notify to
         // obtain the same behaviour for TLS 1.2 and TLS 1.3. Currently, this
         // prevents a downstream application from closing their write-end while
         // allowing the peer to continue writing.
         //
         // When lifting this limitation, please take good note of the "Future
         // work" remarks in https://github.com/randombit/botan/pull/3801.
         return true;
      }

      /**
       * @param alert  a TLS alert sent by the peer
       */
      void tls_alert(TLS::Alert alert) final {
         if(alert.is_fatal() || alert.type() == TLS::AlertType::CloseNotify) {
            // TLS alerts received from the peer are not passed to the
            // downstream application immediately. Instead, we retain them here
            // and the stream invokes `handle_tls_protocol_errors()` in due time
            // to handle them.
            m_alert_from_peer = alert;
         }
      }

      void tls_verify_cert_chain(const std::vector<X509_Certificate>& cert_chain,
                                 const std::vector<std::optional<OCSP::Response>>& ocsp_responses,
                                 const std::vector<Certificate_Store*>& trusted_roots,
                                 Usage_Type usage,
                                 std::string_view hostname,
                                 const TLS::Policy& policy) override {
         const auto ctx = m_context.lock();

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
         const auto ctx = m_context.lock();

         if(!ctx || ctx->m_app_protocols.empty()) {
            return "";
         }
         // Priority is to the server.
         for(const auto& server_proto : ctx->m_app_protocols) {
            for(const auto& client_proto : client_protos) {
               if(server_proto == client_proto) {
                  return server_proto;
               }
            }
         }
         // No match.
         throw TLS_Exception(
            Alert::NoApplicationProtocol,
            "Rejecting ALPN request: no overlap between client-offered and server-configured application protocols");
      }

   private:
      // The members below are meant for the tightly-coupled Stream class only
      template <class SL, class C>
      friend class Stream;

      /**
       * Bind this instance to a Stream. An instance serves at most one live
       * Stream at a time; the Stream holds the token for as long as it is alive
       * and releases it when it is destroyed or assigned over.
       */
      void bind_to_stream(const std::shared_ptr<const void>& stream_token, std::weak_ptr<Botan::TLS::Context> context) {
         if(!m_stream_token.expired()) {
            throw Invalid_Argument("TLS::StreamCallbacks instance is already in use by another TLS::Stream");
         }

         m_stream_token = stream_token;
         m_context = std::move(context);

         // Discard anything left over from a previous connection
         m_alert_from_peer.reset();
         m_receive_buffer.clear();
         m_output.clear();
         m_emit_failure = nullptr;
      }

      detail::OutputQueue& output_queue() { return m_output; }

      const detail::OutputQueue& output_queue() const { return m_output; }

      //! @brief Hand out and clear the failure of the last tls_emit_data() call that failed
      std::exception_ptr take_emit_failure() { return std::exchange(m_emit_failure, nullptr); }

      boost::beast::flat_buffer& receive_buffer() { return m_receive_buffer; }

      const boost::beast::flat_buffer& receive_buffer() const { return m_receive_buffer; }

      bool shutdown_received() const {
         return m_alert_from_peer && m_alert_from_peer->type() == AlertType::CloseNotify;
      }

      std::optional<Alert> alert_from_peer() const { return m_alert_from_peer; }

   private:
      std::optional<Alert> m_alert_from_peer;
      boost::beast::flat_buffer m_receive_buffer;
      detail::OutputQueue m_output;
      std::exception_ptr m_emit_failure;

      std::weak_ptr<TLS::Context> m_context;
      std::weak_ptr<const void> m_stream_token;
};

namespace detail {

template <typename T>
concept basic_completion_token = boost::asio::completion_token_for<T, void(boost::system::error_code)>;

template <typename T>
concept byte_size_completion_token = boost::asio::completion_token_for<T, void(boost::system::error_code, size_t)>;

}  // namespace detail

/**
 * @brief boost::asio compatible SSL/TLS stream
 *
 * Like boost::asio::ssl::stream, the stream allows one read operation and
 * one write operation (async_write_some or async_shutdown) to be outstanding
 * at the same time. All asynchronous operations must be performed within the
 * same implicit or explicit strand. Operations support terminal cancellation
 * via the completion token's associated cancellation slot.
 *
 * Synchronous operations must not be used while an asynchronous write is in
 * flight; they then fail with boost::asio::error::already_started. A stream
 * must not be destroyed or moved while an operation is outstanding.
 *
 * A failure inside the TLS implementation on an active connection, or a
 * record it emitted that could not be buffered, may leave its record
 * sequence out of step with the peer. The stream then discards whatever
 * the TLS implementation emits afterwards and refuses any further output,
 * reporting that error again.
 *
 * @tparam StreamLayer type of the next layer, usually a network socket
 * @tparam ChannelT type of the native_handle, defaults to TLS::Channel, only needed for testing purposes
 */
template <class StreamLayer, class ChannelT = Channel>
class Stream {
   private:
      using default_completion_token =
         boost::asio::default_completion_token_t<boost::beast::executor_type<StreamLayer>>;

   public:
      //! \name construction
      //! @{

      /**
       * @brief Construct a new Stream with a customizable instance of Callbacks
       *
       * @param context The context parameter is used to set up the underlying native handle.
       * @param callbacks The callbacks parameter may contain an instance of a derived TLS::Callbacks
       *                  class to allow for fine-grained customization of the TLS stream. Note that
       *                  applications need to ensure a 1-to-1 relationship between instances of
       *                  Callbacks and Streams; passing an instance that is still in use by another
       *                  Stream throws Invalid_Argument. A future major version of Botan will use a
       *                  unique_ptr here.
       *
       * @param args Arguments to be forwarded to the construction of the next layer.
       */
      template <typename... Args>
      explicit Stream(std::shared_ptr<Context> context, std::shared_ptr<StreamCallbacks> callbacks, Args&&... args) :
            m_context(std::move(context)),
            m_nextLayer(std::forward<Args>(args)...),
            m_core(std::move(callbacks)),
            m_core_token(std::make_shared<int>(0)),
            m_input_buffer_space(MAX_CIPHERTEXT_SIZE, '\0'),
            m_pending_write(m_nextLayer.get_executor(), std::chrono::steady_clock::time_point::max()) {
         if(!m_context || !m_core) {
            throw Invalid_Argument("TLS::Stream requires a context and a callbacks object");
         }
         m_core->bind_to_stream(m_core_token, m_context);
      }

      /**
       * @brief Construct a new Stream
       *
       * @param context The context parameter is used to set up the underlying native handle.
       * @param args Arguments to be forwarded to the construction of the next layer.
       */
      template <typename... Args>
      explicit Stream(std::shared_ptr<Context> context, Args&&... args) :
            Stream(std::move(context), std::make_shared<StreamCallbacks>(), std::forward<Args>(args)...) {}

      /**
       * @brief Construct a new Stream
       *
       * Convenience overload for boost::asio::ssl::stream compatibility.
       *
       * @param arg This argument is forwarded to the construction of the next layer.
       * @param context The context parameter is used to set up the underlying native handle.
       * @param callbacks The (optional) callbacks object that the stream should use. Note that
       *                  applications need to ensure a 1-to-1 relationship between instances of Callbacks
       *                  and Streams. A future major version of Botan will use a unique_ptr here.
       */
      template <typename Arg>
      explicit Stream(Arg&& arg,
                      std::shared_ptr<Context> context,
                      std::shared_ptr<StreamCallbacks> callbacks = std::make_shared<StreamCallbacks>()) :
            Stream(std::move(context), std::move(callbacks), std::forward<Arg>(arg)) {}

   #if defined(BOTAN_HAS_DEFAULT_TLS_CONTEXT)
      /**
       * @brief Conveniently construct a new Stream with default settings
       *
       * This is typically a good starting point for a basic TLS client. For
       * much more control and configuration options, consider creating a custom
       * Context object and pass it to the respective constructor.
       *
       * @param server_info  Basic information about the host to connect to (SNI)
       * @param args  Arguments to be forwarded to the construction of the next layer.
       */
      template <typename... Args>
      explicit Stream(Server_Information server_info, Args&&... args) :
            Stream(std::make_shared<Context>(std::move(server_info)), std::forward<Args>(args)...) {}
   #endif

      virtual ~Stream() = default;

      // Moving throws if moving the next layer does (e.g. boost::beast::test::stream)
      Stream(Stream&& other) = default;             // NOLINT(*-exception-escape)
      Stream& operator=(Stream&& other) = default;  // NOLINT(*-exception-escape)

      Stream(const Stream& other) = delete;
      Stream& operator=(const Stream& other) = delete;

      //! @}
      //! \name boost::asio accessor methods
      //! @{

      using next_layer_type = std::remove_reference_t<StreamLayer>;

      const next_layer_type& next_layer() const { return m_nextLayer; }

      next_layer_type& next_layer() { return m_nextLayer; }

      using lowest_layer_type = typename boost::beast::lowest_layer_type<StreamLayer>;

      lowest_layer_type& lowest_layer() { return boost::beast::get_lowest_layer(m_nextLayer); }

      const lowest_layer_type& lowest_layer() const { return boost::beast::get_lowest_layer(m_nextLayer); }

      using executor_type = typename next_layer_type::executor_type;

      executor_type get_executor() noexcept { return m_nextLayer.get_executor(); }

      using native_handle_type = std::add_pointer_t<ChannelT>;

      native_handle_type native_handle() {
         if(m_native_handle == nullptr) {
            throw Botan::Invalid_State("ASIO native handle unexpectedly null");
         }
         return m_native_handle.get();
      }

      //! @}
      //! \name configuration and callback setters
      //! @{

      /**
       * @brief Override the tls_verify_cert_chain callback
       *
       * This changes the verify_callback in the stream's TLS::Context, and hence the tls_verify_cert_chain callback
       * used in the handshake.
       * Using this function is equivalent to setting the callback via @see Botan::TLS::Context::set_verify_callback
       *
       * @note This function should only be called before initiating the TLS handshake
       */
      void set_verify_callback(Context::Verify_Callback callback) {
         m_context->set_verify_callback(std::move(callback));
      }

      /**
       * @brief Compatibility overload of @ref set_verify_callback
       *
       * @param callback the callback implementation
       * @param ec This parameter is unused.
       */
      void set_verify_callback(Context::Verify_Callback callback, [[maybe_unused]] boost::system::error_code& ec) {
         m_context->set_verify_callback(std::move(callback));
      }

      /**
       * Not Implemented.
       * @param depth the desired verification depth
       * @throws Not_Implemented todo
       */
      void set_verify_depth([[maybe_unused]] int depth) {
         throw Not_Implemented("set_verify_depth is not implemented");
      }

      /**
       * Not Implemented.
       * @param depth the desired verification depth
       * @param ec Will be set to `Botan::ErrorType::NotImplemented`
       */
      void set_verify_depth([[maybe_unused]] int depth, boost::system::error_code& ec) {
         ec = ErrorType::NotImplemented;
      }

      /**
       * Not Implemented.
       * @param v the desired verify mode
       * @throws Not_Implemented todo
       */
      template <typename verify_mode>
      void set_verify_mode([[maybe_unused]] verify_mode v) {
         throw Not_Implemented("set_verify_mode is not implemented");
      }

      /**
       * Not Implemented.
       * @param v the desired verify mode
       * @param ec Will be set to `Botan::ErrorType::NotImplemented`
       */
      template <typename verify_mode>
      void set_verify_mode([[maybe_unused]] verify_mode v, boost::system::error_code& ec) {
         ec = ErrorType::NotImplemented;
      }

      //! @}
      //! \name handshake methods
      //! @{

      /**
       * @brief Performs SSL handshaking.
       *
       * The function call will block until handshaking is complete or an error occurs.
       *
       * @param side The type of handshaking to be performed, i.e. as a client or as a server.
       * @throws boost::system::system_error if error occurred
       */
      void handshake(Connection_Side side) {
         boost::system::error_code ec;
         handshake(side, ec);
         boost::asio::detail::throw_error(ec, "handshake");
      }

      /**
       * @brief Performs SSL handshaking.
       *
       * The function call will block until handshaking is complete or an error occurs.
       *
       * @param side The type of handshaking to be performed, i.e. as a client or as a server.
       * @param ec Set to indicate what error occurred, if any.
       */
      void handshake(Connection_Side side, boost::system::error_code& ec) {
         ec = {};
         if(async_write_in_flight(ec)) {
            return;
         }

         ec = setup_native_handle(side);

         // We write to the socket if we have data to send and read from it
         // otherwise, until either some error occurred or we have successfully
         // performed the handshake.
         while(!ec) {
            // Send pending data to the peer and abort the handshake if that
            // fails with a network error. We do that first, to allow sending
            // any final message before reporting the handshake as "finished".
            if(has_data_to_send()) {
               send_pending_encrypted_data(ec);
            }

            // Once the underlying TLS implementation reports a complete and
            // successful handshake we're done.
            if(native_handle()->is_handshake_complete()) {
               return;
            }

            // Handle and report any TLS protocol errors that might have
            // surfaced in a previous iteration. By postponing their handling we
            // allow the stream to send a respective TLS alert to the peer before
            // aborting the handshake.
            handle_tls_protocol_errors(ec);

            // If we don't have any encrypted data to send we attempt to read
            // more data from the peer. This reports network errors immediately.
            // TLS protocol errors result in an internal state change which is
            // handled by `handle_tls_protocol_errors()` in the next iteration.
            read_and_process_encrypted_data_from_peer(ec);
         }
      }

      /**
       * @brief Starts an asynchronous SSL handshake.
       *
       * This function call always returns immediately.
       *
       * @param side The type of handshaking to be performed, i.e. as a client or as a server.
       * @param completion_token The completion handler to be called when the handshake operation completes.
       *                         The completion signature of the handler must be: void(boost::system::error_code).
       */
      template <detail::basic_completion_token CompletionToken = default_completion_token>
      auto async_handshake(Botan::TLS::Connection_Side side,
                           // NOLINTNEXTLINE(*-missing-std-forward)
                           CompletionToken&& completion_token = default_completion_token{}) {
         return boost::asio::async_initiate<CompletionToken, void(boost::system::error_code)>(
            [this](auto&& completion_handler, TLS::Connection_Side connection_side) {
               using completion_handler_t = std::decay_t<decltype(completion_handler)>;

               const detail::AsyncHandshakeOperation<completion_handler_t, Stream> op{
                  std::forward<completion_handler_t>(completion_handler), *this, setup_native_handle(connection_side)};
            },
            completion_token,
            side);
      }

      /**
       * Not Implemented.
       * @throws Not_Implemented todo
       */
      template <typename ConstBufferSequence, detail::basic_completion_token BufferedHandshakeHandler>
      auto async_handshake([[maybe_unused]] Connection_Side side,
                           [[maybe_unused]] const ConstBufferSequence& buffers,
                           [[maybe_unused]] BufferedHandshakeHandler&& handler /* NOLINT(*missing-std-forward) */) {
         throw Not_Implemented("buffered async handshake is not implemented");
      }

      //! @}
      //! \name shutdown methods
      //! @{

      /**
       * @brief Shut down SSL on the stream.
       *
       * This function is used to shut down SSL on the stream. The function call will block until SSL has been shut down
       * or an error occurs. Note that this will not close the lowest layer.
       *
       * Note that this can be used in reaction of a received shutdown alert from the peer.
       *
       * @param ec Set to indicate what error occurred, if any.
       */
      void shutdown(boost::system::error_code& ec) {
         ec = {};
         if(async_write_in_flight(ec)) {
            return;
         }

         ec = tls_close();
         send_pending_encrypted_data(ec);
      }

      /**
       * @brief Shut down SSL on the stream.
       *
       * This function is used to shut down SSL on the stream. The function call will block until SSL has been shut down
       * or an error occurs. Note that this will not close the lowest layer.
       *
       * Note that this can be used in reaction of a received shutdown alert from the peer.
       *
       * @throws boost::system::system_error if error occurred
       */
      void shutdown() {
         boost::system::error_code ec;
         shutdown(ec);
         boost::asio::detail::throw_error(ec, "shutdown");
      }

   private:
      /**
       * @brief Internal wrapper type to adapt the expected signature of `async_shutdown` to the completion handler
       *        signature of `AsyncWriteOperation`.
       *
       * This is boilerplate to ignore the `size_t` parameter that is passed to the completion handler of
       * `AsyncWriteOperation`. Note that it needs to retain the wrapped handler's executor, allocator and
       * cancellation slot.
       */
      template <typename Handler, typename Executor>
      struct Wrapper {
            void operator()(boost::system::error_code ec, std::size_t /*unused*/) { handler(ec); }

            using executor_type = boost::asio::associated_executor_t<Handler, Executor>;

            executor_type get_executor() const noexcept {
               return boost::asio::get_associated_executor(handler, io_executor);
            }

            using allocator_type = boost::asio::associated_allocator_t<Handler>;

            allocator_type get_allocator() const noexcept { return boost::asio::get_associated_allocator(handler); }

            using cancellation_slot_type = boost::asio::associated_cancellation_slot_t<Handler>;

            cancellation_slot_type get_cancellation_slot() const noexcept {
               return boost::asio::get_associated_cancellation_slot(handler);
            }

            Handler handler;       // NOLINT(*-non-private-member-variable*)
            Executor io_executor;  // NOLINT(*-non-private-member-variable*)
      };

   public:
      /**
       * @brief Asynchronously shut down SSL on the stream.
       *
       * This function call always returns immediately.
       *
       * Note that this can be used in reaction of a received shutdown alert from the peer.
       *
       * @param completion_token The completion handler to be called when the shutdown operation completes.
       *                         The completion signature of the handler must be: void(boost::system::error_code).
       */
      template <detail::basic_completion_token CompletionToken = default_completion_token>
      // NOLINTNEXTLINE(*-missing-std-forward)
      auto async_shutdown(CompletionToken&& completion_token = default_completion_token{}) {
         return boost::asio::async_initiate<CompletionToken, void(boost::system::error_code)>(
            [this](auto&& completion_handler) {
               using completion_handler_t = std::decay_t<decltype(completion_handler)>;
               using write_handler_t = Wrapper<completion_handler_t, typename Stream::executor_type>;

               // The operation closes the TLS session once no other write is in flight
               const TLS::detail::AsyncWriteOperation<write_handler_t, Stream, boost::asio::const_buffer> op{
                  write_handler_t{std::forward<completion_handler_t>(completion_handler), get_executor()},
                  *this,
                  std::nullopt};
            },
            completion_token);
      }

      //! @}
      //! \name I/O methods
      //! @{

      /**
       * @brief Read some data from the stream.
       *
       * The function call will block until one or more bytes of data has been read successfully, or until an error
       * occurs.
       *
       * @param buffers The buffers into which the data will be read.
       * @param ec Set to indicate what error occurred, if any. Specifically, StreamTruncated will be set if the peer
       *           has closed the connection but did not properly shut down the SSL connection.
       * @return The number of bytes read. Returns 0 if an error occurred.
       */
      template <typename MutableBufferSequence>
      std::size_t read_some(const MutableBufferSequence& buffers, boost::system::error_code& ec) {
         ec = {};

         // Reading into a zero-byte buffer completes immediately, without
         // touching the next layer.
         if(boost::asio::buffer_size(buffers) == 0) {
            return 0;
         }

         // Records this read generates could pile up behind that write
         if(async_write_in_flight(ec) || native_handle_missing(ec)) {
            return 0;
         }

         // We read from the socket until either some error occurred or we have
         // decrypted at least one byte of application data.
         while(!ec) {
            // Some previous invocation of process_encrypted_data() generated
            // application data in the output buffer that can now be returned.
            // Records generated alongside (our close_notify in reply to the
            // peer's, say) stay queued; the next operation writes them.
            if(has_received_data()) {
               return copy_received_data(buffers);
            }

            // Records generated while processing the peer's data (an alert, or
            // our close_notify in reply to the peer's) go out before the
            // condition they announce is reported and before we wait for more
            // input.
            if(has_data_to_send()) {
               send_pending_encrypted_data(ec);
               continue;
            }

            // Handle and report any TLS protocol errors (including a
            // close_notify) that might have surfaced in a previous iteration
            // (in `read_and_process_encrypted_data_from_peer()`). This makes
            // sure that all received application data was handed out to the
            // caller before reporting an error (e.g. EOF at the end of the
            // stream).
            handle_tls_protocol_errors(ec);

            // If we don't have any plaintext application data, yet, we attempt
            // to read more data from the peer. This reports network errors
            // immediately. TLS protocol errors result in an internal state
            // change which is handled by `handle_tls_protocol_errors()` in the
            // next iteration.
            read_and_process_encrypted_data_from_peer(ec);
         }

         return 0;
      }

      /**
       * @brief Read some data from the stream.
       *
       * The function call will block until one or more bytes of data has been read successfully, or until an error
       * occurs.
       *
       * @param buffers The buffers into which the data will be read.
       * @return The number of bytes read. Returns 0 if an error occurred.
       * @throws boost::system::system_error if error occurred
       */
      template <typename MutableBufferSequence>
      std::size_t read_some(const MutableBufferSequence& buffers) {
         boost::system::error_code ec;
         const auto n = read_some(buffers, ec);
         boost::asio::detail::throw_error(ec, "read_some");
         return n;
      }

      /**
       * @brief Write some data to the stream.
       *
       * The function call will block until one or more bytes of data has been written successfully, or until an error
       * occurs.
       *
       * @param buffers The data to be written.
       * @param ec Set to indicate what error occurred, if any.
       * @return The number of bytes processed from the input buffers.
       */
      template <typename ConstBufferSequence>
      std::size_t write_some(const ConstBufferSequence& buffers, boost::system::error_code& ec) {
         ec = {};

         // Writing from a zero-byte buffer completes immediately, without
         // touching the next layer.
         if(boost::asio::buffer_size(buffers) == 0) {
            return 0;
         }

         if(async_write_in_flight(ec)) {
            return 0;
         }

         ec = tls_encrypt(buffers);
         if(ec) {
            return 0;
         }

         // The input is processed once it is encrypted. Records the next layer
         // did not accept stay queued and go out with the next operation.
         send_pending_encrypted_data(ec);
         return boost::asio::buffer_size(buffers);
      }

      /**
       * @brief Write some data to the stream.
       *
       * The function call will block until one or more bytes of data has been written successfully, or until an error
       * occurs.
       *
       * @param buffers The data to be written.
       * @return The number of bytes written.
       * @throws boost::system::system_error if error occurred
       */
      template <typename ConstBufferSequence>
      std::size_t write_some(const ConstBufferSequence& buffers) {
         boost::system::error_code ec;
         const auto n = write_some(buffers, ec);
         boost::asio::detail::throw_error(ec, "write_some");
         return n;
      }

      /**
       * @brief Start an asynchronous write. The function call always returns immediately.
       *
       * @param buffers The data to be written. Although the buffers object may be copied as necessary, ownership of
       *                the underlying buffers is retained by the caller, which must guarantee that they remain valid
       *                until the handler is called: the data is encrypted only once the operation's turn to write
       *                comes.
       * @param completion_token The completion handler to be called when the write operation completes. Copies of the
       *                         handler will be made as required. The completion signature of the handler must be:
       *                         void(boost::system::error_code, std::size_t).
       */
      template <typename ConstBufferSequence,
                detail::byte_size_completion_token CompletionToken = default_completion_token>
      auto async_write_some(const ConstBufferSequence& buffers,
                            // NOLINTNEXTLINE(*-missing-std-forward)
                            CompletionToken&& completion_token = default_completion_token{}) {
         return boost::asio::async_initiate<CompletionToken, void(boost::system::error_code, std::size_t)>(
            [this](auto&& completion_handler, const auto& bufs) {
               using completion_handler_t = std::decay_t<decltype(completion_handler)>;

               // The operation encrypts the data once no other write is in flight
               const detail::AsyncWriteOperation<completion_handler_t, Stream, ConstBufferSequence> op{
                  std::forward<completion_handler_t>(completion_handler), *this, bufs};
            },
            completion_token,
            buffers);
      }

      /**
       * @brief Start an asynchronous read. The function call always returns immediately.
       *
       * @param buffers The buffers into which the data will be read. Although the buffers object may be copied as
       *                necessary, ownership of the underlying buffers is retained by the caller, which must guarantee
       *                that they remain valid until the handler is called.
       * @param completion_token The completion handler to be called when the read operation completes. The completion
       *                         signature of the handler must be: void(boost::system::error_code, std::size_t).
       */
      template <typename MutableBufferSequence,
                detail::byte_size_completion_token CompletionToken = default_completion_token>
      auto async_read_some(const MutableBufferSequence& buffers,
                           // NOLINTNEXTLINE(*-missing-std-forward)
                           CompletionToken&& completion_token = default_completion_token{}) {
         return boost::asio::async_initiate<CompletionToken, void(boost::system::error_code, std::size_t)>(
            [this](auto&& completion_handler, const auto& bufs) {
               using completion_handler_t = std::decay_t<decltype(completion_handler)>;

               // A zero-byte read completes right away, even before the handshake
               boost::system::error_code ec;
               if(boost::asio::buffer_size(bufs) > 0) {
                  native_handle_missing(ec);
               }

               const detail::AsyncReadOperation<completion_handler_t, Stream, MutableBufferSequence> op{
                  std::forward<completion_handler_t>(completion_handler), *this, bufs, ec};
            },
            completion_token,
            buffers);
      }

      //! @}

      //! @brief Indicates whether a close_notify alert has been received from the peer.
      //!
      //! Note that we cannot m_core.is_closed_for_reading() because this wants to
      //! explicitly check that the peer sent close_notify.
      bool shutdown_received() const { return m_core->shutdown_received(); }

   protected:
      template <class H, class S, class M, class A>
      friend class detail::AsyncReadOperation;
      template <class H, class S, class B, class A>
      friend class detail::AsyncWriteOperation;
      template <class H, class S, class A>
      friend class detail::AsyncHandshakeOperation;
      template <class O, class S>
      friend class detail::WriteQueuedStep;
      template <class O, class S>
      friend class detail::ReadAndProcessStep;

      //! @brief Buffer space to read the peer's records into
      boost::asio::mutable_buffer input_buffer() { return boost::asio::buffer(m_input_buffer_space); }

      //! @brief Check if some operation is currently writing to the next layer
      bool write_in_progress() const { return m_core->output_queue().write_in_progress(); }

      //! @brief Synchronous operations must not run while an asynchronous write does; sets @p ec if that is the case
      bool async_write_in_flight(boost::system::error_code& ec) const {
         if(write_in_progress()) {
            ec = boost::asio::error::already_started;
         }
         return write_in_progress();
      }

      //! @brief Nothing but a handshake may be attempted before the native handle exists; sets @p ec if it does not
      bool native_handle_missing(boost::system::error_code& ec) const {
         if(m_native_handle == nullptr) {
            ec = ErrorType::InvalidObjectState;
         }
         return m_native_handle == nullptr;
      }

      //! @brief Lend the records to write next to the next layer, see detail::OutputQueue::begin_write()
      boost::asio::const_buffer begin_write() { return m_core->output_queue().begin_write(); }

      //! @brief Take back the records lent by begin_write() and wake up operations waiting for their turn to write
      void end_write(std::size_t bytes_transferred) {
         m_core->output_queue().end_write(bytes_transferred);
         m_pending_write.cancel();
      }

      /**
       * @brief Have read operations send whatever is queued before they report a condition or consume more input
       *
       * This covers the records generated while processing the peer's data (an alert, or our close_notify in
       * reply to the peer's), but also records left behind by a failed write.
       */
      void mark_output_to_send() { m_core->output_queue().mark_pending(); }

      //! @brief Check whether records marked by mark_output_to_send() are still waiting to be written
      bool output_pending() const { return m_core->output_queue().pending(); }

      /**
       * @brief Make progress on getting the records emitted so far onto the wire
       *
       * If another operation's write is in flight, waits for it to finish. Otherwise lends the queued
       * records to the next layer and writes them. Either way @p operation is resumed with the result
       * (operation_aborted if cancellation was requested in the meantime).
       */
      template <class Operation>
      void async_send_queued(Operation operation) {
         if(write_in_progress()) {
            m_pending_write.async_wait(detail::WaitForWriteStep<Operation>(std::move(operation)));
         } else {
            boost::asio::async_write(
               m_nextLayer, begin_write(), detail::WriteQueuedStep<Operation, Stream>(std::move(operation), *this));
         }
      }

      /**
       * @brief Read from the next layer and hand the data to the TLS implementation
       *
       * @p operation is resumed with the result; TLS protocol errors are retained, see process_encrypted_data().
       */
      template <class Operation>
      void async_read_and_process(Operation operation) {
         m_nextLayer.async_read_some(input_buffer(),
                                     detail::ReadAndProcessStep<Operation, Stream>(std::move(operation), *this));
      }

      //! @brief An EOF from the next layer without a prior close_notify from the peer means the stream was truncated
      void translate_eof(boost::system::error_code& ec) const {
         if(ec == boost::asio::error::eof && !shutdown_received()) {
            ec = StreamError::StreamTruncated;
         }
      }

      //! @brief Check if decrypted data is available in the receive buffer
      bool has_received_data() const { return m_core->receive_buffer().size() > 0; }

      //! @brief Copy decrypted data into the user-provided buffer
      template <typename MutableBufferSequence>
      std::size_t copy_received_data(MutableBufferSequence buffers) {
         // Note: It would be nice to avoid this buffer copy. This could be achieved by equipping the CallbacksT with
         // the user's desired target buffer once a read is started, and reading directly into that buffer in tls_record
         // received. However, we need to deal with the case that the receive buffer provided by the caller is smaller
         // than the decrypted record, so this optimization might not be worth the additional complexity.
         const auto copiedBytes = boost::asio::buffer_copy(buffers, m_core->receive_buffer().data());
         m_core->receive_buffer().consume(copiedBytes);
         return copiedBytes;
      }

      //! @brief Check if records are waiting to be written (queued, or left behind by the last write)
      bool has_data_to_send() const { return m_core->output_queue().has_data(); }

      /**
       * @brief Create the native handle.
       *
       * Depending on the desired connection side, this function will create a TLS::Client or a
       * TLS::Server.
       *
       * @param side The desired connection side (client or server)
       * @return the error that occurred, if any
       */
      boost::system::error_code setup_native_handle(Connection_Side side) {
         // Do not attempt to instantiate the native_handle when a custom (mocked) channel type template parameter has
         // been specified. This allows mocking the native_handle in test code.
         if constexpr(std::is_same_v<ChannelT, Channel>) {
            // A handshake was performed (or at least attempted) already
            if(m_native_handle != nullptr) {
               return ErrorType::InvalidObjectState;
            }

            // Constructing the client emits the ClientHello. Nothing of a
            // failed attempt may be left behind for a retry.
            return call_tls_discarding_output([&] {
               if(side == Connection_Side::Client) {
                  m_native_handle = std::unique_ptr<Client>(
                     new Client(m_core,
                                m_context->m_session_manager,
                                m_context->m_credentials_manager,
                                m_context->m_policy,
                                m_context->m_rng,
                                m_context->m_server_info,
                                m_context->m_policy->latest_supported_version(false /* no DTLS */),
                                m_context->m_app_protocols));
               } else {
                  m_native_handle = std::unique_ptr<Server>(new Server(m_core,
                                                                       m_context->m_session_manager,
                                                                       m_context->m_credentials_manager,
                                                                       m_context->m_policy,
                                                                       m_context->m_rng,
                                                                       false /* no DTLS */));
               }
            });
         } else {
            return {};
         }
      }

      /**
       * The `Stream` has to distinguish from network-related issues (that are
       * reported immediately) from TLS protocol errors, that must be retained
       * and emitted once all legal application traffic received before is
       * pushed to the downstream application.
       *
       * See also `process_encrypted_data()` and `StreamCallbacks::tls_alert()`
       * where those TLS protocol errors are detected and retained for eventual
       * handling in this method.
       *
       * See also https://github.com/randombit/botan/pull/3801 for a detailed
       * description of the ASIO stream's state management.
       *
       * @param ec  this error code is set if we previously detected a TLS
       *            protocol error.
       */
      void handle_tls_protocol_errors(boost::system::error_code& ec) {
         if(ec) {
            return;
         }

         // If we had raised an error while processing TLS records received from
         // the peer, we expose that error here.
         //
         // See also `process_encrypted_data()`.
         else if(const auto error = error_from_us()) {
            ec = error;
         }

         // If we had received a TLS alert from the peer, we expose that error
         // here. See also `StreamCallbacks::tls_alert()` where such alerts
         // would be detected and retained initially.
         //
         // Note that a close_notify is always a legal way for the peer to end a
         // TLS session. When received during the handshake it typically means
         // that the peer wanted to cancel the handshake for some reason not
         // related to the TLS protocol.
         else if(auto alert = alert_from_peer()) {
            if(alert->type() == AlertType::CloseNotify) {
               ec = boost::asio::error::eof;
            } else {
               ec = alert->type();
            }
         }
      }

      /**
       * Reads TLS record data from the peer and forwards it to the native
       * handle for processing. Note that @p ec will reflect network errors
       * only. Any detected or received TLS protocol errors will be retained and
       * must be handled by the downstream operation in due time by invoking
       * `handle_tls_protocol_errors()`.
       *
       * @param ec  this error code might be populated with network-related errors
       */
      void read_and_process_encrypted_data_from_peer(boost::system::error_code& ec) {
         if(ec) {
            return;
         }

         // If we have received application data in a previous invocation, this
         // data needs to be passed to the application first. Otherwise, it
         // might get overwritten.
         if(has_received_data()) {
            throw Botan::Invalid_State("ASIO receive buffer not empty");
         }

         if(error_from_us() || alert_from_peer()) {
            throw Botan::Invalid_State("ASIO TLS session no longer healthy");
         }

         // If there's no existing error condition, read and process data from
         // the peer and report any sort of network error. TLS related errors do
         // not immediately cause an abort, they are checked in the invocation
         // via `error_from_us()`.
         const boost::asio::const_buffer read_buffer{input_buffer().data(), m_nextLayer.read_some(input_buffer(), ec)};
         translate_eof(ec);
         if(!ec) {
            process_encrypted_data(read_buffer);
         }
      }

      /** @brief Synchronously write the records waiting to be written to the next layer.
       *
       * If this function is called with an error code other than 'Success', it will do nothing.
       *
       * @param ec Set to indicate what error occurred, if any. Specifically, StreamTruncated will be set if the peer
       *           has closed the connection but did not properly shut down the SSL connection.
       */
      void send_pending_encrypted_data(boost::system::error_code& ec) {
         if(ec || async_write_in_flight(ec)) {
            return;
         }

         // Records that could not be written stay in flight for the next attempt
         while(!ec && has_data_to_send()) {
            const auto written = boost::asio::write(m_nextLayer, begin_write(), ec);
            end_write(written);
            translate_eof(ec);
         }
      }

      /**
       * @brief Close the TLS session, queueing a close_notify alert for sending
       *
       * @return the error that occurred, if any
       */
      boost::system::error_code tls_close() {
         boost::system::error_code ec;
         if(native_handle_missing(ec)) {
            return ec;
         }

         return call_tls_discarding_output([&] { native_handle()->close(); });
      }

      /**
       * @brief Pass plaintext data to the native handle for processing.
       *
       * The native handle will then create TLS records and hand them back to the Stream via the tls_emit_data callback.
       *
       * @return the error that occurred, if any
       */
      template <typename ConstBufferSequence>
      boost::system::error_code tls_encrypt(const ConstBufferSequence& buffers) {
         boost::system::error_code ec;
         if(native_handle_missing(ec) || output_failed(ec)) {
            return ec;
         }

         // TODO: Once the TLS::Channel can deal with buffer sequences we can
         //       save this copy. Until then we optimize for the smallest amount
         //       of TLS records and flatten the boost buffer sequence.
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

         // Flattening may fail to allocate, which leaves the TLS implementation untouched
         std::span<const uint8_t> plaintext;
         ec = try_with_error_code([&] { plaintext = unpack(buffers); });
         if(ec) {
            return ec;
         }

         // NOTE: This is not asynchronous: it encrypts the data synchronously.
         // The data encrypted by native_handle()->send() is synchronously queued
         // in m_core, but is not actually written to the wire, yet.
         return call_tls_discarding_output([&] { native_handle()->send(plaintext); });
      }

      /**
       * Pass encrypted data received from the peer to the native handle for
       * processing. If the @p read_buffer contains coalesced TLS records, this
       * might result in multiple TLS protocol state changes.
       *
       * To allow the ASIO stream wrapper to disentangle those state changes
       * properly, any TLS protocol errors are retained and must be handled by
       * calling `handle_tls_protocol_errors()` in due time.
       *
       * @param read_buffer Input buffer containing the encrypted data.
       */
      void process_encrypted_data(const boost::asio::const_buffer& read_buffer) {
         if(alert_from_peer() || error_from_us()) {
            throw Botan::Invalid_State("ASIO TLS session no longer healthy");
         }

         // If the local TLS implementation generates an alert, we are notified
         // with an exception that is caught in call_tls(). The error code is
         // retained and not handled directly. Stream operations will have to
         // invoke `handle_tls_protocol_errors()` to handle them later. The
         // alert itself stays queued and is written before that.
         m_ec_from_last_read = call_tls_keeping_output([&] {
            native_handle()->received_data({static_cast<const uint8_t*>(read_buffer.data()), read_buffer.size()});
         });

         // Whatever the TLS implementation generated in response (an alert, or
         // our close_notify in reply to the peer's) must be written before the
         // condition it announces is reported.
         mark_output_to_send();
      }

      //! @brief Run @p f, turning an exception into the error code returned
      template <typename Fun>
      static boost::system::error_code try_with_error_code(Fun f) {
         try {
            f();
         } catch(const TLS_Exception& e) {
            return e.type();
         } catch(const Exception& e) {
            return e.error_type();
         } catch(const std::bad_alloc&) {
            return ErrorType::OutOfMemory;
         } catch(const std::exception&) {
            return ErrorType::Unknown;
         }
         return {};
      }

      /**
       * @brief Call into the TLS implementation to process the peer's data
       *
       * The records emitted stay queued even if the call fails: the TLS
       * implementation sends a fatal alert before it reports a failure, and
       * that alert must reach the peer. They are discarded only once output
       * failed beyond repair, see call_tls().
       *
       * @return the error that occurred, if any
       */
      template <typename Fun>
      boost::system::error_code call_tls_keeping_output(Fun f) {
         return call_tls(f, false);
      }

      /**
       * @brief Call into the TLS implementation to produce output
       *
       * Refused once output failed before. The records emitted by a failed
       * call are discarded: the TLS implementation emits one record at a time,
       * and nothing of input reported as unprocessed may reach the peer.
       *
       * @return the error that occurred, if any
       */
      template <typename Fun>
      boost::system::error_code call_tls_discarding_output(Fun f) {
         boost::system::error_code ec;
         if(output_failed(ec)) {
            return ec;
         }

         return call_tls(f, true);
      }

      //! @brief Sets @p ec if the TLS implementation must not produce further output, see call_tls()
      bool output_failed(boost::system::error_code& ec) const {
         if(m_ec_from_failed_output) {
            ec = m_ec_from_failed_output;
         }
         return static_cast<bool>(m_ec_from_failed_output);
      }

      /**
       * @brief Call into the TLS implementation, which may emit records.
       *
       * The TLS implementation advances its record sequence number before it
       * emits a record. Once a call failed on an active connection, or a
       * record could not be buffered (which the TLS implementation swallows
       * for alerts), the peer could not authenticate anything emitted
       * afterwards: that failure is retained, the records of that call and of
       * any later one are discarded, and output is refused from then on, see
       * call_tls_discarding_output().
       *
       * @param f the call
       * @param discard_output_on_failure whether to drop the records a failed call emitted
       * @return the error that occurred, if any
       */
      template <typename Fun>
      boost::system::error_code call_tls(Fun f, bool discard_output_on_failure) {
         auto& output = m_core->output_queue();
         const auto queued_before = output.queued_size();

         auto ec = try_with_error_code(f);
         const auto emit_failure = m_core->take_emit_failure();
         if(emit_failure && !ec) {
            ec = try_with_error_code([&] { std::rethrow_exception(emit_failure); });
         }

         // A failure before the connection is active leaves no state behind,
         // unless a record went missing (the TLS implementation then considers
         // itself closed after a close_notify it never emitted, for instance)
         if(ec && !m_ec_from_failed_output && m_native_handle != nullptr &&
            (emit_failure || m_native_handle->is_active())) {
            m_ec_from_failed_output = ec;
         }

         if(m_ec_from_failed_output || (ec && discard_output_on_failure)) {
            output.truncate(queued_before);
         }

         return ec;
      }

   private:
      /**
       * Returns any alert previously received from the peer. This may include
       * close_notify. Once the peer has sent any alert, no more data must be
       * read from the stream.
       */
      std::optional<Alert> alert_from_peer() const { return m_core->alert_from_peer(); }

      /**
       * Returns any error code produced by the local TLS implementation. This
       * will _not_ include close_notify. Once our TLS stack has reported an
       * error, no more data must be written to the stream. The peer will receive
       * the error as a TLS alert.
       */
      boost::system::error_code error_from_us() const { return m_ec_from_last_read; }

   protected:
      using timer_type = boost::asio::basic_waitable_timer<std::chrono::steady_clock,
                                                           boost::asio::wait_traits<std::chrono::steady_clock>,
                                                           executor_type>;

      std::shared_ptr<Context> m_context;  // NOLINT(*-non-private-member-variable*)
      StreamLayer m_nextLayer;             // NOLINT(*-non-private-member-variable*)

      std::shared_ptr<StreamCallbacks> m_core;  // NOLINT(*-non-private-member-variable*)
      // Marks m_core as in use by this stream, see StreamCallbacks::bind_to_stream()
      std::shared_ptr<const void> m_core_token;       // NOLINT(*-non-private-member-variable*)
      std::unique_ptr<ChannelT> m_native_handle;      // NOLINT(*-non-private-member-variable*)
      boost::system::error_code m_ec_from_last_read;  // NOLINT(*-non-private-member-variable*)
      // Retained once the TLS implementation failed on an active connection, see call_tls()
      boost::system::error_code m_ec_from_failed_output;  // NOLINT(*-non-private-member-variable*)

      // Buffer space used to read input intended for the core
      std::vector<uint8_t> m_input_buffer_space;  // NOLINT(*-non-private-member-variable*)

      // Never expires; operations wait on it for the write in flight to finish, see async_send_queued()
      timer_type m_pending_write;  // NOLINT(*-non-private-member-variable*)
};

// deduction guides for convenient construction from an existing
// underlying transport stream T
template <typename T>
Stream(Server_Information, T) -> Stream<T>;
template <typename T>
Stream(std::shared_ptr<Context>, std::shared_ptr<StreamCallbacks>, T) -> Stream<T>;
template <typename T>
Stream(std::shared_ptr<Context>, T) -> Stream<T>;
template <typename T>
Stream(T, std::shared_ptr<Context>) -> Stream<T>;

}  // namespace Botan::TLS

#endif
#endif  // BOTAN_ASIO_STREAM_H_
