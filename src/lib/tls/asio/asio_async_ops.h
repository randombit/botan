/*
* Helpers for TLS ASIO Stream
* (C) 2018-2020 Jack Lloyd
*     2018-2020 Hannes Rantzsch, Tim Oesterreich, Rene Meusel
*     2023      Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ASIO_ASYNC_OPS_H_
#define BOTAN_ASIO_ASYNC_OPS_H_

#include <botan/asio_compat.h>
#if defined(BOTAN_FOUND_COMPATIBLE_BOOST_ASIO_VERSION)

   #include <botan/asio_error.h>

   // We need to define BOOST_ASIO_DISABLE_SERIAL_PORT before any asio imports. Otherwise asio will include <termios.h>,
   // which interferes with Botan's amalgamation by defining macros like 'B0' and 'FF1'.
   #define BOOST_ASIO_DISABLE_SERIAL_PORT
   #include <boost/asio.hpp>
   #include <boost/asio/yield.hpp>
   #include <boost/beast/core/bind_handler.hpp>

   #include <optional>

namespace Botan::TLS::detail {

/**
 * Base class for asynchronous stream operations.
 *
 * Asynchronous operations, used for example to implement an interface for boost::asio::async_read_some and
 * boost::asio::async_write_some, are based on boost::asio::coroutines. Derived operations implement a call
 * operator and invoke it upon construction. Whenever they need the next layer they `yield` to one of the
 * steps the stream provides (Stream::async_send_queued() and Stream::async_read_and_process()), which resume
 * the call operator with their result:
 *
 * ```
 * void operator()(boost::system::error_code ec, bool isContinuation = true)
 *    {
 *    reenter(this)
 *       {
 *       // operation specific logic, repeatedly interacting with the stream and, via the steps, the next layer
 *       yield m_stream.async_read_and_process(std::move(*this));
 *
 *       // make sure the handler is not invoked from within the initiating function
 *       if(!isContinuation)
 *          {
 *          yield post_resumption(std::move(*this), ec);
 *          }
 *
 *       // call the completion handler
 *       complete_now(error_code, bytes_transferred);
 *       }
 *    }
 * ```
 *
 * The call operator needs to make sure that the user-provided handler is not called directly from the
 * initiating function. Once the operation is ready to call the completion handler it checks if it was resumed
 * at least once using the `isContinuation` parameter. If not, it posts itself to its executor and `yield`s. As
 * a result, the call operator will be invoked again, this time as a continuation, and will jump to the location
 * where it yielded before using `reenter`. It is now safe to call the handler function via `complete_now`.
 *
 * The operations forward the associations of the user-provided handler (executor, allocator and cancellation
 * slot) to the operations they start on the next layer. Cancellation requested by the caller therefore reaches
 * whatever the operation is currently waiting for.
 *
 * \tparam Handler Type of the completion handler
 * \tparam Executor1 Type of the asio executor (usually derived from the lower layer)
 * \tparam Allocator Type of the allocator to be used
 */
template <class Handler, class Executor1, class Allocator>
class AsyncBase : public boost::asio::coroutine {
   public:
      using allocator_type = boost::asio::associated_allocator_t<Handler, Allocator>;
      using executor_type = boost::asio::associated_executor_t<Handler, Executor1>;
      using cancellation_slot_type = boost::asio::cancellation_slot;

      allocator_type get_allocator() const noexcept { return boost::asio::get_associated_allocator(m_handler); }

      executor_type get_executor() const noexcept {
         return boost::asio::get_associated_executor(m_handler, m_work_guard_1.get_executor());
      }

      cancellation_slot_type get_cancellation_slot() const noexcept { return m_cancellation_state.slot(); }

      /**
       * Check whether the caller requested cancellation of this operation.
       *
       * Operations on the next layer are connected to a child of the handler's
       * cancellation slot and complete with operation_aborted on their own.
       * This is for the steps that have no such operation to abort, e.g.
       * waiting for another write to finish.
       */
      bool cancelled() const noexcept {
         return m_cancellation_state.cancelled() != boost::asio::cancellation_type::none;
      }

   protected:
      template <class HandlerT>
      AsyncBase(HandlerT&& handler, const Executor1& executor) :
            m_handler(std::forward<HandlerT>(handler)),
            m_work_guard_1(executor),
            m_cancellation_state(boost::asio::get_associated_cancellation_slot(m_handler)) {}

      /**
       * Drop the cancellation handler that the last operation on the next
       * layer installed in our slot. It refers to that operation's state,
       * which is gone once the operation completed; a cancellation emitted
       * later must not reach it. Call this at the start of every continuation.
       */
      void reset_cancellation_slot() { m_cancellation_state.slot().clear(); }

      /**
       * Call the completion handler.
       *
       * This function should only be called after an intermediate initiating function has been called.
       *
       * @param args Arguments forwarded to the completion handler function.
       */
      template <class... Args>
      void complete_now(Args&&... args) {
         reset_cancellation_slot();
         m_work_guard_1.reset();
         m_handler(std::forward<Args>(args)...);
      }

      Handler m_handler;                                           // NOLINT(*-non-private-member-variable*)
      boost::asio::executor_work_guard<Executor1> m_work_guard_1;  // NOLINT(*-non-private-member-variable*)
      boost::asio::cancellation_state m_cancellation_state;        // NOLINT(*-non-private-member-variable*)
};

/**
 * Resume @p operation with @p ec from its executor, i.e. not from within the initiating function.
 */
template <class Operation>
void post_resumption(Operation&& operation, boost::system::error_code ec) {
   // The executor must be fetched before the operation is moved into the bound handler
   const auto executor = operation.get_executor();
   boost::asio::post(executor, boost::beast::bind_front_handler(std::forward<Operation>(operation), ec));
}

/**
 * Base class for the steps an operation performs on the next layer.
 *
 * A step holds the operation that started it, forwards the operation's
 * associations to the next layer meanwhile, and resumes the operation with
 * its result once done.
 *
 * \tparam Operation Type of the operation, derived from AsyncBase
 */
template <class Operation>
class StepBase {
   public:
      using allocator_type = typename Operation::allocator_type;
      using executor_type = typename Operation::executor_type;
      using cancellation_slot_type = typename Operation::cancellation_slot_type;

      allocator_type get_allocator() const noexcept { return m_operation.get_allocator(); }

      executor_type get_executor() const noexcept { return m_operation.get_executor(); }

      cancellation_slot_type get_cancellation_slot() const noexcept { return m_operation.get_cancellation_slot(); }

   protected:
      explicit StepBase(Operation operation) : m_operation(std::move(operation)) {}

      /**
       * Resume the operation with the step's result.
       *
       * A cancellation requested in the meantime is reported as
       * operation_aborted, whether or not it aborted the step's operation on
       * the next layer.
       */
      void resume(boost::system::error_code ec) {
         if(!ec && m_operation.cancelled()) {
            ec = boost::asio::error::operation_aborted;
         }

         auto operation = std::move(m_operation);
         operation(ec);
      }

   private:
      Operation m_operation;
};

/**
 * Wait for the write in flight to finish, see Stream::async_send_queued().
 */
template <class Operation>
class WaitForWriteStep : public StepBase<Operation> {
   public:
      explicit WaitForWriteStep(Operation operation) : StepBase<Operation>(std::move(operation)) {}

      // The wait is interrupted once the write in flight ends, see Stream::end_write()
      void operator()(const boost::system::error_code& /* interruption */) { this->resume({}); }
};

/**
 * Write the records lent by Stream::begin_write(), see Stream::async_send_queued().
 */
template <class Operation, class Stream>
class WriteQueuedStep : public StepBase<Operation> {
   public:
      WriteQueuedStep(Operation operation, Stream& stream) :
            StepBase<Operation>(std::move(operation)), m_stream(stream) {}

      void operator()(boost::system::error_code ec, std::size_t bytes_transferred) {
         m_stream.translate_eof(ec);
         m_stream.end_write(bytes_transferred);
         this->resume(ec);
      }

   private:
      Stream& m_stream;
};

/**
 * Hand what was read from the next layer to the TLS implementation, see Stream::async_read_and_process().
 */
template <class Operation, class Stream>
class ReadAndProcessStep : public StepBase<Operation> {
   public:
      ReadAndProcessStep(Operation operation, Stream& stream) :
            StepBase<Operation>(std::move(operation)), m_stream(stream) {}

      void operator()(boost::system::error_code ec, std::size_t bytes_transferred) {
         m_stream.translate_eof(ec);
         if(!ec && bytes_transferred > 0) {
            m_stream.process_encrypted_data(
               boost::asio::const_buffer(m_stream.input_buffer().data(), bytes_transferred));
         }
         this->resume(ec);
      }

   private:
      Stream& m_stream;
};

template <class Handler, class Stream, class MutableBufferSequence, class Allocator = std::allocator<void>>
class AsyncReadOperation : public AsyncBase<Handler, typename Stream::executor_type, Allocator> {
   public:
      /**
       * Construct and invoke an AsyncReadOperation.
       *
       * @param handler Handler function to be called upon completion.
       * @param stream The stream from which the data will be read
       * @param buffers The buffers into which the data will be read.
       * @param ec Optional error code; used to report an error to the handler function.
       */
      template <class HandlerT>
      AsyncReadOperation(HandlerT&& handler,
                         Stream& stream,
                         const MutableBufferSequence& buffers,
                         const boost::system::error_code& ec = {}) :
            AsyncBase<Handler, typename Stream::executor_type, Allocator>(std::forward<HandlerT>(handler),
                                                                          stream.get_executor()),
            m_stream(stream),
            m_buffers(buffers),
            m_decodedBytes(0) {
         this->operator()(ec, false);
      }

      AsyncReadOperation(const AsyncReadOperation& other) = delete;
      AsyncReadOperation(AsyncReadOperation&& other) = default;
      AsyncReadOperation& operator=(const AsyncReadOperation& other) = delete;
      AsyncReadOperation& operator=(AsyncReadOperation&& other) = delete;
      ~AsyncReadOperation() = default;

      /**
       * Read and decrypt application data from the peer. Note, that this is
       * unsuitable to receive initial handshake records! Post-handshake
       * messages like KeyUpdate will transparently work, though.
       *
       * Depending on the situation, this handler will:
       *
       * 1. Copy any received application data out to the downstream application
       *    and finalize this operation, or
       * 2. Make sure the TLS records the TLS implementation generated while
       *    processing the peer's data (e.g. an alert) were written, or
       * 3. Handle any pending TLS protocol errors and (if none were found) wait
       *    for more data from the peer, expecting to find:
       *    * a complete and decryptable application data record,
       *    * a TLS alert (e.g. close_notify)
       */
      void operator()(boost::system::error_code ec, bool isContinuation = true) {
         this->reset_cancellation_slot();

         reenter(this) {
            // "Reading" into a zero-byte buffer completes immediately, without
            // touching the next layer.
            while(!ec && boost::asio::buffer_size(m_buffers) > 0) {
               // If the "input buffer" holds successfully decrypted application
               // data, we copy it to the "output buffers" and finalize the
               // operation with the number of produced bytes. Records generated
               // alongside (our close_notify in reply to the peer's, say) stay
               // queued; the next operation writes them.
               if(m_stream.has_received_data()) {
                  m_decodedBytes = m_stream.copy_received_data(m_buffers);
                  break;
               }

               // Whatever is queued for sending (records generated while
               // processing the peer's data, or left behind by a failed write)
               // must be on the wire before the condition it announces is
               // reported and before we consume more input. Another operation
               // may be sending it already; what matters is that it gets
               // written.
               m_stream.mark_output_to_send();
               if(m_stream.output_pending()) {
                  yield m_stream.async_send_queued(std::move(*this));
                  continue;
               }

               // Ensure that no TLS protocol error was detected until now.
               // Otherwise the read operation is aborted with an error code.
               m_stream.handle_tls_protocol_errors(ec);
               if(ec) {
                  break;
               }

               // Wait for more incoming data and hand it to the native handle
               // for processing. When enough bytes were received to decrypt an
               // application data record, the "input buffer" will become
               // non-empty.
               yield m_stream.async_read_and_process(std::move(*this));
            }

            if(!isContinuation) {
               // Make sure the handler is not called from within the initiating function
               yield post_resumption(std::move(*this), ec);
            }

            this->complete_now(ec, m_decodedBytes);
         }
      }

   private:
      Stream& m_stream;
      MutableBufferSequence m_buffers;
      std::size_t m_decodedBytes;
};

template <typename Handler, class Stream, class ConstBufferSequence, class Allocator = std::allocator<void>>
class AsyncWriteOperation : public AsyncBase<Handler, typename Stream::executor_type, Allocator> {
   public:
      /**
       * Construct and invoke an AsyncWriteOperation.
       *
       * @param handler Handler function to be called upon completion.
       * @param stream The stream to which the data will be written
       * @param plaintext Application data to be encrypted and written, or std::nullopt to shut down the TLS session
       *                  instead, i.e. to write a close_notify alert.
       */
      template <class HandlerT>
      AsyncWriteOperation(HandlerT&& handler, Stream& stream, std::optional<ConstBufferSequence> plaintext) :
            AsyncBase<Handler, typename Stream::executor_type, Allocator>(std::forward<HandlerT>(handler),
                                                                          stream.get_executor()),
            m_stream(stream),
            m_plaintext(std::move(plaintext)),
            m_plainBytesTransferred(0) {
         this->operator()(boost::system::error_code{}, false);
      }

      AsyncWriteOperation(const AsyncWriteOperation& other) = delete;
      AsyncWriteOperation(AsyncWriteOperation&& other) = default;
      AsyncWriteOperation& operator=(const AsyncWriteOperation& other) = delete;
      AsyncWriteOperation& operator=(AsyncWriteOperation&& other) = delete;
      ~AsyncWriteOperation() = default;

      /**
       * Encrypt the plaintext (or shut down the TLS session) and write the
       * resulting TLS records from the output queue to the wire.
       *
       * Depending on the situation, this handler will:
       *
       * 1. Wait for another operation's write to finish, or
       * 2. Hand the plaintext to the TLS implementation for encryption (or
       *    close the TLS session), or
       * 3. Send the resulting records to the peer.
       */
      void operator()(boost::system::error_code ec, bool isContinuation = true) {
         this->reset_cancellation_slot();

         reenter(this) {
            // Writing from a zero-byte buffer completes immediately, without
            // touching the stream or the next layer.
            if(!empty_write()) {
               // Only one operation at a time writes to the next layer. Waiting
               // for our turn before generating any records ensures that they are
               // sent by this operation alone, so that a failure to send them is
               // reported to our handler.
               while(!ec && m_stream.write_in_progress()) {
                  yield m_stream.async_send_queued(std::move(*this));
               }

               if(!ec) {
                  if(m_plaintext.has_value()) {
                     // On failure, tls_encrypt() discards whatever records the
                     // TLS implementation generated from the plaintext, so that
                     // nothing of input reported as unprocessed reaches the peer.
                     ec = m_stream.tls_encrypt(*m_plaintext);

                     if(!ec) {
                        // The size of the sent TLS records can differ from the size of the payload due to TLS
                        // encryption. We need to tell the handler how many bytes of the original data we processed.
                        m_plainBytesTransferred = boost::asio::buffer_size(*m_plaintext);
                     }
                  } else {
                     ec = m_stream.tls_close();
                  }
               }

               // Records a concurrent read operation generates in the meantime are
               // sent as well. That operation waits for them to be written before
               // it reports whatever they announce, and sends them itself should
               // our write fail.
               while(!ec && m_stream.has_data_to_send()) {
                  yield m_stream.async_send_queued(std::move(*this));
               }
            }

            if(!isContinuation) {
               // Make sure the handler is not called from within the initiating function
               yield post_resumption(std::move(*this), ec);
            }

            this->complete_now(ec, m_plainBytesTransferred);
         }
      }

   private:
      bool empty_write() const { return m_plaintext.has_value() && boost::asio::buffer_size(*m_plaintext) == 0; }

      Stream& m_stream;
      std::optional<ConstBufferSequence> m_plaintext;
      std::size_t m_plainBytesTransferred;
};

template <class Handler, class Stream, class Allocator = std::allocator<void>>
class AsyncHandshakeOperation : public AsyncBase<Handler, typename Stream::executor_type, Allocator> {
   public:
      /**
       * Construct and invoke an AsyncHandshakeOperation.
       *
       * @param handler Handler function to be called upon completion.
       * @param stream The stream from which the data will be read
       * @param ec Optional error code; used to report an error to the handler function.
       */
      template <class HandlerT>
      AsyncHandshakeOperation(HandlerT&& handler, Stream& stream, const boost::system::error_code& ec = {}) :
            AsyncBase<Handler, typename Stream::executor_type, Allocator>(std::forward<HandlerT>(handler),
                                                                          stream.get_executor()),
            m_stream(stream) {
         this->operator()(ec, false);
      }

      AsyncHandshakeOperation(const AsyncHandshakeOperation& other) = delete;
      AsyncHandshakeOperation(AsyncHandshakeOperation&& other) = default;
      AsyncHandshakeOperation& operator=(const AsyncHandshakeOperation& other) = delete;
      AsyncHandshakeOperation& operator=(AsyncHandshakeOperation&& other) = delete;
      ~AsyncHandshakeOperation() = default;

      /**
       * Perform a TLS handshake with the peer.
       *
       * Depending on the situation, this handler will:
       *
       * 1. Send pending data to the peer, or
       * 2. Finalize the handshake, or
       * 3. Handle any pending TLS protocol errors and (if none were found) wait
       *    for more data from the peer and process it, which potentially:
       *    * generates a response (another handshake flight, or an alert) or
       *    * finalizes the handshake.
       */
      void operator()(boost::system::error_code ec, bool isContinuation = true) {
         this->reset_cancellation_slot();

         reenter(this) {
            while(!ec) {
               // If we have data to be sent to the peer, we do that now. Note that
               // this might either be a flight in our handshake, or a TLS alert
               // record if we decided to abort due to some failure.
               if(m_stream.has_data_to_send()) {
                  yield m_stream.async_send_queued(std::move(*this));
                  continue;
               }

               // Once the underlying TLS implementation reports a complete and
               // successful handshake we're done.
               if(m_stream.native_handle()->is_handshake_complete()) {
                  break;
               }

               // Ensure that no TLS protocol error was detected until now.
               // Otherwise the handshake is aborted with an error code.
               m_stream.handle_tls_protocol_errors(ec);
               if(ec) {
                  break;
               }

               // The handshake is neither finished nor aborted. Wait for more
               // data from the peer and hand it to the native handle for
               // processing. This will result in the advancement of the
               // handshake state and produce data in the output buffer.
               yield m_stream.async_read_and_process(std::move(*this));
            }

            if(!isContinuation) {
               // Make sure the handler is not called from within the initiating function
               yield post_resumption(std::move(*this), ec);
            }

            this->complete_now(ec);
         }
      }

   private:
      Stream& m_stream;
};

}  // namespace Botan::TLS::detail

   #include <boost/asio/unyield.hpp>

#endif
#endif  // BOTAN_ASIO_ASYNC_OPS_H_
