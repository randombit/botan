/*
* TLS ASIO Stream
* (C) 2018-2019 Jack Lloyd
*     2018-2019 Hannes Rantzsch, Tim Oesterreich, Rene Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ASIO_STREAM_H_
#define BOTAN_ASIO_STREAM_H_

#include <botan/build.h>

// first version to be compatible with Networking TS (N4656) and boost::beast
#include <boost/version.hpp>
#if BOOST_VERSION >= 106600

#include <botan/asio_async_ops.h>
#include <botan/asio_context.h>
#include <botan/asio_error.h>

#include <botan/tls_callbacks.h>
#include <botan/tls_channel.h>
#include <botan/tls_client.h>
#include <botan/tls_magic.h>

// We need to define BOOST_ASIO_DISABLE_SERIAL_PORT before any asio imports. Otherwise asio will include <termios.h>,
// which interferes with Botan's amalgamation by defining macros like 'B0' and 'FF1'.
#define BOOST_ASIO_DISABLE_SERIAL_PORT
#include <boost/asio.hpp>
#include <boost/beast/core/flat_buffer.hpp>

#include <algorithm>
#include <memory>
#include <type_traits>

namespace Botan {
namespace TLS {

/**
 * @brief boost::asio compatible SSL/TLS stream
 *
 * Currently only the TLS::Client specialization is implemented.
 *
 * @tparam StreamLayer type of the next layer, usually a network socket
 * @tparam ChannelT type of the native_handle, defaults to Botan::TLS::Channel, only needed for testing purposes
 */
template <class StreamLayer, class ChannelT = Channel>
class Stream
   {
   public:
      //! \name construction
      //! @{

      /**
       * @brief Construct a new Stream
       *
       * @param context The context parameter is used to set up the underlying native handle. Using code is
       *                responsible for lifetime management of the context and must ensure that it is available for the
       *                lifetime of the stream.
       * @param args Arguments to be forwarded to the construction of the next layer.
       */
      template <typename... Args>
      explicit Stream(Context& context, Args&& ... args)
         : m_context(context)
         , m_nextLayer(std::forward<Args>(args)...)
         , m_core(m_receive_buffer, m_send_buffer, m_context)
         , m_input_buffer_space(MAX_CIPHERTEXT_SIZE, '\0')
         , m_input_buffer(m_input_buffer_space.data(), m_input_buffer_space.size())
         {}

      /**
       * @brief Construct a new Stream
       *
       * Convenience overload for boost::asio::ssl::stream compatibility.
       *
       * @param arg This argument is forwarded to the construction of the next layer.
       * @param context The context parameter is used to set up the underlying native handle. Using code is
       *                responsible for lifetime management of the context and must ensure that is available for the
       *                lifetime of the stream.
       */
      template <typename Arg>
      explicit Stream(Arg&& arg, Context& context)
         : m_context(context)
         , m_nextLayer(std::forward<Arg>(arg))
         , m_core(m_receive_buffer, m_send_buffer, m_context)
         , m_input_buffer_space(MAX_CIPHERTEXT_SIZE, '\0')
         , m_input_buffer(m_input_buffer_space.data(), m_input_buffer_space.size())
         {}

      virtual ~Stream() = default;

      Stream(Stream&& other) = default;
      Stream& operator=(Stream&& other) = default;

      Stream(const Stream& other) = delete;
      Stream& operator=(const Stream& other) = delete;

      //! @}
      //! \name boost::asio accessor methods
      //! @{

      using next_layer_type = typename std::remove_reference<StreamLayer>::type;
      using lowest_layer_type = typename next_layer_type::lowest_layer_type;
      using executor_type = typename next_layer_type::executor_type;
      using native_handle_type = typename std::add_pointer<ChannelT>::type;

      executor_type get_executor() noexcept { return m_nextLayer.get_executor(); }

      const next_layer_type& next_layer() const { return m_nextLayer; }
      next_layer_type& next_layer() { return m_nextLayer; }

      lowest_layer_type& lowest_layer() { return m_nextLayer.lowest_layer(); }
      const lowest_layer_type& lowest_layer() const { return m_nextLayer.lowest_layer(); }

      native_handle_type native_handle() { return m_native_handle.get(); }

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
      void set_verify_callback(Context::Verify_Callback callback)
         {
         m_context.set_verify_callback(std::move(callback));
         }

      /**
       * @brief Compatibility overload of @ref set_verify_callback
       *
       * @param callback the callback implementation
       * @param ec This parameter is unused.
       */
      void set_verify_callback(Context::Verify_Callback callback, boost::system::error_code& ec)
         {
         BOTAN_UNUSED(ec);
         m_context.set_verify_callback(std::move(callback));
         }

      //! @throws Not_Implemented
      void set_verify_depth(int depth)
         {
         BOTAN_UNUSED(depth);
         throw Not_Implemented("set_verify_depth is not implemented");
         }

      /**
       * Not Implemented.
       * @param depth the desired verification depth
       * @param ec Will be set to `Botan::ErrorType::NotImplemented`
       */
      void set_verify_depth(int depth, boost::system::error_code& ec)
         {
         BOTAN_UNUSED(depth);
         ec = Botan::ErrorType::NotImplemented;
         }

      //! @throws Not_Implemented
      template <typename verify_mode>
      void set_verify_mode(verify_mode v)
         {
         BOTAN_UNUSED(v);
         throw Not_Implemented("set_verify_mode is not implemented");
         }

      /**
       * Not Implemented.
       * @param v the desired verify mode
       * @param ec Will be set to `Botan::ErrorType::NotImplemented`
       */
      template <typename verify_mode>
      void set_verify_mode(verify_mode v, boost::system::error_code& ec)
         {
         BOTAN_UNUSED(v);
         ec = Botan::ErrorType::NotImplemented;
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
       * @throws boost::system::system_error if error occured, or if the chosen Connection_Side is not available
       */
      void handshake(Connection_Side side)
         {
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
      void handshake(Connection_Side side, boost::system::error_code& ec)
         {
         setup_native_handle(side, ec);

         // send client hello, which was written to the send buffer on client instantiation
         send_pending_encrypted_data(ec);

         while(!native_handle()->is_active() && !ec)
            {
            boost::asio::const_buffer read_buffer{input_buffer().data(), m_nextLayer.read_some(input_buffer(), ec)};
            if(ec)
               { return; }

            try
               {
               native_handle()->received_data(static_cast<const uint8_t*>(read_buffer.data()), read_buffer.size());
               }
            catch(const TLS_Exception& e)
               {
               ec = e.type();
               }
            catch(const Botan::Exception& e)
               {
               ec = e.error_type();
               }
            catch(const std::exception&)
               {
               ec = Botan::ErrorType::Unknown;
               }

            send_pending_encrypted_data(ec);
            }
         }

      /**
       * @brief Starts an asynchronous SSL handshake.
       *
       * This function call always returns immediately.
       *
       * @param side The type of handshaking to be performed, i.e. as a client or as a server.
       * @param handler The handler to be called when the handshake operation completes.
       *                The equivalent function signature of the handler must be: void(boost::system::error_code)
       * @throws NotImplemented if Connection_Side is not CLIENT
       */
      template <typename HandshakeHandler>
      auto async_handshake(Connection_Side side, HandshakeHandler&& handler) ->
         BOOST_ASIO_INITFN_RESULT_TYPE(HandshakeHandler, void(boost::system::error_code))
         {
         BOOST_ASIO_HANDSHAKE_HANDLER_CHECK(HandshakeHandler, handler) type_check;

         boost::system::error_code ec;
         setup_native_handle(side, ec);
         // If ec is set by setup_native_handle, the AsyncHandshakeOperation created below will do nothing but call the
         // handler with the error_code set appropriately - no need to early return here.

         boost::asio::async_completion<HandshakeHandler, void(boost::system::error_code)> init(handler);

         detail::AsyncHandshakeOperation<typename std::decay<HandshakeHandler>::type, Stream>
         op{std::move(init.completion_handler), *this, ec};

         return init.result.get();
         }

      //! @throws Not_Implemented
      template <typename ConstBufferSequence, typename BufferedHandshakeHandler>
      BOOST_ASIO_INITFN_RESULT_TYPE(BufferedHandshakeHandler,
                                    void(boost::system::error_code, std::size_t))
      async_handshake(Connection_Side side, const ConstBufferSequence& buffers,
                      BufferedHandshakeHandler&& handler)
         {
         BOTAN_UNUSED(side, buffers, handler);
         BOOST_ASIO_HANDSHAKE_HANDLER_CHECK(BufferedHandshakeHandler, handler) type_check;
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
       * @param ec Set to indicate what error occured, if any.
       */
      void shutdown(boost::system::error_code& ec)
         {
         try
            {
            native_handle()->close();
            }
         catch(const TLS_Exception& e)
            {
            ec = e.type();
            }
         catch(const Botan::Exception& e)
            {
            ec = e.error_type();
            }
         catch(const std::exception&)
            {
            ec = Botan::ErrorType::Unknown;
            }

         if(!ec)
            { send_pending_encrypted_data(ec); }
         }

      /**
       * @brief Shut down SSL on the stream.
       *
       * This function is used to shut down SSL on the stream. The function call will block until SSL has been shut down
       * or an error occurs. Note that this will not close the lowest layer.
       *
       * @throws boost::system::system_error if error occured
       */
      void shutdown()
         {
         boost::system::error_code ec;
         shutdown(ec);
         boost::asio::detail::throw_error(ec, "shutdown");
         }

      /**
       * @brief Asynchronously shut down SSL on the stream.
       *
       * This function call always returns immediately.
       *
       * @param handler The handler to be called when the handshake operation completes.
       *                The equivalent function signature of the handler must be: void(boost::system::error_code)
       */
      template <typename ShutdownHandler>
      void async_shutdown(ShutdownHandler&& handler)
         {
         BOOST_ASIO_HANDSHAKE_HANDLER_CHECK(ShutdownHandler, handler) type_check;
         BOTAN_UNUSED(handler);
         throw Not_Implemented("async shutdown is not implemented");
         // TODO: Implement a subclass of AsyncBase that calls native_handle()->close() and writes pending data from
         // the core to the network, e.g. using AsyncWriteOperation.
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
       * @param ec Set to indicate what error occured, if any.
       * @return The number of bytes read. Returns 0 if an error occurred.
       */
      template <typename MutableBufferSequence>
      std::size_t read_some(const MutableBufferSequence& buffers,
                            boost::system::error_code& ec)
         {
         if(has_received_data())
            { return copy_received_data(buffers); }

         boost::asio::const_buffer read_buffer{input_buffer().data(), m_nextLayer.read_some(input_buffer(), ec)};
         if(ec)
            { return 0; }

         try
            {
            native_handle()->received_data(static_cast<const uint8_t*>(read_buffer.data()), read_buffer.size());
            }
         catch(const TLS_Exception& e)
            {
            ec = e.type();
            }
         catch(const Botan::Exception& e)
            {
            ec = e.error_type();
            }
         catch(const std::exception&)
            {
            ec = Botan::ErrorType::Unknown;
            }

         return !ec ? copy_received_data(buffers) : 0;
         }

      /**
       * @brief Read some data from the stream.
       *
       * The function call will block until one or more bytes of data has been read successfully, or until an error
       * occurs.
       *
       * @param buffers The buffers into which the data will be read.
       * @return The number of bytes read. Returns 0 if an error occurred.
       * @throws boost::system::system_error if error occured
       */
      template <typename MutableBufferSequence>
      std::size_t read_some(const MutableBufferSequence& buffers)
         {
         boost::system::error_code ec;
         auto const n = read_some(buffers, ec);
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
      std::size_t write_some(const ConstBufferSequence& buffers,
                             boost::system::error_code& ec)
         {
         tls_encrypt(buffers, ec);
         send_pending_encrypted_data(ec);
         return !ec ? boost::asio::buffer_size(buffers) : 0;
         }

      /**
       * @brief Write some data to the stream.
       *
       * The function call will block until one or more bytes of data has been written successfully, or until an error
       * occurs.
       *
       * @param buffers The data to be written.
       * @return The number of bytes written.
       * @throws boost::system::system_error if error occured
       */
      template <typename ConstBufferSequence>
      std::size_t write_some(const ConstBufferSequence& buffers)
         {
         boost::system::error_code ec;
         auto const n = write_some(buffers, ec);
         boost::asio::detail::throw_error(ec, "write_some");
         return n;
         }

      /**
       * @brief Start an asynchronous write. The function call always returns immediately.
       *
       * @param buffers The data to be written.
       * @param handler The handler to be called when the write operation completes. Copies will be made of the handler
       *        as required. The equivalent function signature of the handler must be:
       *        void(boost::system::error_code, std::size_t)
       */
      template <typename ConstBufferSequence, typename WriteHandler>
      auto async_write_some(const ConstBufferSequence& buffers, WriteHandler&& handler) ->
         BOOST_ASIO_INITFN_RESULT_TYPE(WriteHandler,
                                       void(boost::system::error_code, std::size_t))
         {
         BOOST_ASIO_WRITE_HANDLER_CHECK(WriteHandler, handler) type_check;

         boost::asio::async_completion<WriteHandler, void(boost::system::error_code, std::size_t)> init(handler);

         boost::system::error_code ec;
         tls_encrypt(buffers, ec);
         if(ec)
            {
            // we cannot be sure how many bytes were committed here so clear the send_buffer and let the
            // AsyncWriteOperation call the handler with the error_code set
            consume_send_buffer(m_send_buffer.size());
            detail::AsyncWriteOperation<typename std::decay<WriteHandler>::type, Stream>
            op{std::move(init.completion_handler), *this, std::size_t(0), ec};
            return init.result.get();
            }

         detail::AsyncWriteOperation<typename std::decay<WriteHandler>::type, Stream>
         op{std::move(init.completion_handler), *this, boost::asio::buffer_size(buffers)};

         return init.result.get();
         }

      /**
       * @brief Start an asynchronous read. The function call always returns immediately.
       *
       * @param buffers The buffers into which the data will be read. Although the buffers object may be copied as
       *                necessary, ownership of the underlying buffers is retained by the caller, which must guarantee
       *                that they remain valid until the handler is called.
       * @param handler The handler to be called when the read operation completes. The equivalent function signature of
       *                the handler must be:
       *                void(boost::system::error_code, std::size_t)
       */
      template <typename MutableBufferSequence, typename ReadHandler>
      auto async_read_some(const MutableBufferSequence& buffers, ReadHandler&& handler) ->
         BOOST_ASIO_INITFN_RESULT_TYPE(ReadHandler,
                                       void(boost::system::error_code, std::size_t))
         {
         BOOST_ASIO_READ_HANDLER_CHECK(ReadHandler, handler) type_check;

         boost::asio::async_completion<ReadHandler, void(boost::system::error_code, std::size_t)> init(handler);

         detail::AsyncReadOperation<typename std::decay<ReadHandler>::type, Stream, MutableBufferSequence>
         op{std::move(init.completion_handler), *this, buffers};
         return init.result.get();
         }

      //! @}

   protected:
      template <class H, class S, class M, class A> friend class detail::AsyncReadOperation;
      template <class H, class S, class A> friend class detail::AsyncWriteOperation;
      template <class H, class S, class A> friend class detail::AsyncHandshakeOperation;

      /**
       * @brief Helper class that implements Botan::TLS::Callbacks
       *
       * This class is provided to the stream's native_handle (Botan::TLS::Channel) and implements the callback
       * functions triggered by the native_handle.
       *
       * @param receive_buffer reference to the buffer where decrypted data should be placed
       * @param send_buffer reference to the buffer where encrypted data should be placed
       */
      class StreamCore : public Botan::TLS::Callbacks
         {
         public:
            StreamCore(boost::beast::flat_buffer& receive_buffer, boost::beast::flat_buffer& send_buffer, Context& context)
               : m_receive_buffer(receive_buffer), m_send_buffer(send_buffer), m_tls_context(context) {}

            virtual ~StreamCore() = default;

            void tls_emit_data(const uint8_t data[], std::size_t size) override
               {
               m_send_buffer.commit(
                  boost::asio::buffer_copy(m_send_buffer.prepare(size), boost::asio::buffer(data, size))
               );
               }

            void tls_record_received(uint64_t, const uint8_t data[], std::size_t size) override
               {
               m_receive_buffer.commit(
                  boost::asio::buffer_copy(m_receive_buffer.prepare(size), boost::asio::const_buffer(data, size))
               );
               }

            void tls_alert(Botan::TLS::Alert alert) override
               {
               BOTAN_UNUSED(alert);
               }

            std::chrono::milliseconds tls_verify_cert_chain_ocsp_timeout() const override
               {
               return std::chrono::milliseconds(1000);
               }

            bool tls_session_established(const Botan::TLS::Session&) override
               {
               // TODO: it should be possible to configure this in the using application (via callback?)
               return true;
               }

            void tls_verify_cert_chain(
               const std::vector<X509_Certificate>& cert_chain,
               const std::vector<std::shared_ptr<const OCSP::Response>>& ocsp_responses,
               const std::vector<Certificate_Store*>& trusted_roots,
               Usage_Type usage,
               const std::string& hostname,
               const TLS::Policy& policy) override
               {
               if(m_tls_context.has_verify_callback())
                  {
                  m_tls_context.get_verify_callback()(cert_chain, ocsp_responses, trusted_roots, usage, hostname, policy);
                  }
               else
                  {
                  Callbacks::tls_verify_cert_chain(cert_chain, ocsp_responses, trusted_roots, usage, hostname, policy);
                  }
               }

            boost::beast::flat_buffer& m_receive_buffer;
            boost::beast::flat_buffer& m_send_buffer;
            Context& m_tls_context;
         };

      const boost::asio::mutable_buffer& input_buffer() { return m_input_buffer; }
      boost::asio::const_buffer send_buffer() const { return m_send_buffer.data(); }

      //! @brief Check if decrypted data is available in the receive buffer
      bool has_received_data() const { return m_receive_buffer.size() > 0; }

      //! @brief Copy decrypted data into the user-provided buffer
      template <typename MutableBufferSequence>
      std::size_t copy_received_data(MutableBufferSequence buffers)
         {
         // Note: It would be nice to avoid this buffer copy. This could be achieved by equipping the StreamCore with
         // the user's desired target buffer once a read is started, and reading directly into that buffer in tls_record
         // received. However, we need to deal with the case that the receive buffer provided by the caller is smaller
         // than the decrypted record, so this optimization might not be worth the additional complexity.
         const auto copiedBytes = boost::asio::buffer_copy(buffers, m_receive_buffer.data());
         m_receive_buffer.consume(copiedBytes);
         return copiedBytes;
         }

      //! @brief Check if encrypted data is available in the send buffer
      bool has_data_to_send() const { return m_send_buffer.size() > 0; }

      //! @brief Mark bytes in the send buffer as consumed, removing them from the buffer
      void consume_send_buffer(std::size_t bytesConsumed) { m_send_buffer.consume(bytesConsumed); }

      // This is a helper construct to allow mocking the native_handle in test code. It is activated by explicitly
      // specifying a (mocked) channel type template parameter when constructing the stream and does not attempt to
      // instantiate the native_handle.
      // Note: once we have C++17 we can achieve this much more elegantly using constexpr if.
      template<class T = ChannelT>
      typename std::enable_if<!std::is_same<Channel, T>::value>::type
      setup_native_handle(Connection_Side, boost::system::error_code&) {}

      /**
       * @brief Create the native handle.
       *
       * Depending on the desired connection side, this function will create a Botan::TLS::Client or a
       * Botan::TLS::Server.
       *
       * @param side The desired connection side (client or server)
       * @param ec Set to NotImplemented when side is SERVER - currently only CLIENT is implemented
       */
      template<class T = ChannelT>
      typename std::enable_if<std::is_same<Channel, T>::value>::type
      setup_native_handle(Connection_Side side, boost::system::error_code& ec)
         {
         if(side == CLIENT)
            {
            m_native_handle = std::unique_ptr<Client>(
                                 new Client(m_core,
                                            m_context.m_session_manager,
                                            m_context.m_credentials_manager,
                                            m_context.m_policy,
                                            m_context.m_rng,
                                            m_context.m_server_info));
            }
         else
            {
            // TODO: First steps in order to support the server side of this stream would be to instantiate a
            // Botan::TLS::Server instance as the stream's native_handle and implement the handshake appropriately.
            ec = Botan::ErrorType::NotImplemented;
            }
         }

      size_t send_pending_encrypted_data(boost::system::error_code& ec)
         {
         if(ec)
            { return 0; }

         auto writtenBytes = boost::asio::write(m_nextLayer, send_buffer(), ec);
         consume_send_buffer(writtenBytes);
         return writtenBytes;
         }

      template <typename ConstBufferSequence>
      void tls_encrypt(const ConstBufferSequence& buffers, boost::system::error_code& ec)
         {
         // NOTE: This is not asynchronous: it encrypts the data synchronously.
         // The data encrypted by native_handle()->send() is synchronously stored in the send_buffer of m_core,
         // but is not actually written to the wire, yet.
         for(auto it = boost::asio::buffer_sequence_begin(buffers);
               !ec && it != boost::asio::buffer_sequence_end(buffers);
               it++)
            {
            const boost::asio::const_buffer buffer = *it;
            try
               {
               native_handle()->send(static_cast<const uint8_t*>(buffer.data()), buffer.size());
               }
            catch(const TLS_Exception& e)
               {
               ec = e.type();
               }
            catch(const Botan::Exception& e)
               {
               ec = e.error_type();
               }
            catch(const std::exception&)
               {
               ec = Botan::ErrorType::Unknown;
               }
            }
         }

      Context&                  m_context;
      StreamLayer               m_nextLayer;

      boost::beast::flat_buffer m_receive_buffer;
      boost::beast::flat_buffer m_send_buffer;

      StreamCore                m_core;
      std::unique_ptr<ChannelT> m_native_handle;

      // Buffer space used to read input intended for the core
      std::vector<uint8_t>              m_input_buffer_space;
      const boost::asio::mutable_buffer m_input_buffer;
   };

}  // namespace TLS
}  // namespace Botan

#endif // BOOST_VERSION
#endif // BOTAN_ASIO_STREAM_H_
