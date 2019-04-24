/*
* TLS ASIO Stream Wrapper
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

#include <botan/asio_error.h>

#include <botan/internal/asio_async_handshake_op.h>
#include <botan/internal/asio_async_read_op.h>
#include <botan/internal/asio_async_write_op.h>
#include <botan/internal/asio_includes.h>
#include <botan/asio_context.h>

#include <botan/tls_callbacks.h>
#include <botan/tls_channel.h>
#include <botan/tls_client.h>
#include <botan/tls_magic.h>

#include <boost/beast/core/flat_buffer.hpp>

#include <algorithm>
#include <memory>
#include <thread>
#include <type_traits>

namespace Botan {

namespace TLS {

/**
 * boost::asio compatible SSL/TLS stream
 *
 * Currently only the TLS::Client specialization is implemented.
 *
 * \tparam StreamLayer type of the next layer, usually a network socket
 * \tparam ChannelT type of the native_handle, defaults to Botan::TLS::Channel, only needed for testing purposes
 */
template <class StreamLayer, class ChannelT = Channel>
class Stream
   {
   public:
      using next_layer_type = typename std::remove_reference<StreamLayer>::type;
      using lowest_layer_type = typename next_layer_type::lowest_layer_type;
      using executor_type = typename next_layer_type::executor_type;
      using native_handle_type = typename std::add_pointer<ChannelT>::type;

   public:
      template <typename... Args>
      explicit Stream(Context& context, Args&& ... args)
         : m_context(context), m_nextLayer(std::forward<Args>(args)...) {}

      // overload for boost::asio::ssl::stream compatibility
      template <typename Arg>
      explicit Stream(Arg&& arg, Context& context)
         : m_context(context), m_nextLayer(std::forward<Arg>(arg)) {}

      virtual ~Stream() = default;

      Stream(Stream&& other) = default;
      Stream& operator=(Stream&& other) = default;

      Stream(const Stream& other) = delete;
      Stream& operator=(const Stream& other) = delete;

      //
      // -- -- accessor methods
      //

      executor_type get_executor() noexcept { return m_nextLayer.get_executor(); }

      const next_layer_type& next_layer() const { return m_nextLayer; }
      next_layer_type& next_layer() { return m_nextLayer; }

      lowest_layer_type& lowest_layer() { return m_nextLayer.lowest_layer(); }
      const lowest_layer_type& lowest_layer() const { return m_nextLayer.lowest_layer(); }

      native_handle_type native_handle() { return m_channel.get(); }

      //
      // -- -- configuration and callback setters
      //

      /**
       * @throws Not_Implemented
       */
      template<typename VerifyCallback>
      void set_verify_callback(VerifyCallback callback)
         {
         BOTAN_UNUSED(callback);
         throw Not_Implemented("set_verify_callback is not implemented");
         }

      /**
       * Not Implemented.
       * @param ec Will be set to `Botan::ErrorType::NotImplemented`
       */
      template<typename VerifyCallback>
      void set_verify_callback(VerifyCallback callback,
                               boost::system::error_code& ec)
         {
         BOTAN_UNUSED(callback);
         ec = Botan::ErrorType::NotImplemented;
         }

      /**
       * @throws Not_Implemented
       */
      void set_verify_depth(int depth)
         {
         BOTAN_UNUSED(depth);
         throw Not_Implemented("set_verify_depth is not implemented");
         }

      /**
       * Not Implemented.
       * @param ec Will be set to `Botan::ErrorType::NotImplemented`
       */
      void set_verify_depth(int depth,
                            boost::system::error_code& ec)
         {
         BOTAN_UNUSED(depth);
         ec = Botan::ErrorType::NotImplemented;
         }

      /**
       * @throws Not_Implemented
       */
      template <typename verify_mode>
      void set_verify_mode(verify_mode v)
         {
         BOTAN_UNUSED(v);
         throw Not_Implemented("set_verify_mode is not implemented");
         }

      /**
       * Not Implemented.
       * @param ec Will be set to `Botan::ErrorType::NotImplemented`
       */
      template <typename verify_mode>
      void set_verify_mode(verify_mode v,
                           boost::system::error_code& ec)
         {
         BOTAN_UNUSED(v);
         ec = Botan::ErrorType::NotImplemented;
         }

      //
      // -- -- handshake methods
      //

      /**
       * Performs SSL handshaking.
       * The function call will block until handshaking is complete or an error occurs.
       * @param type The type of handshaking to be performed, i.e. as a client or as a server.
       * @throws boost::system::system_error if error occured
       * @throws Invalid_Argument if Connection_Side could not be validated
       */
      void handshake(Connection_Side side)
         {
         boost::system::error_code ec;
         handshake(side, ec);
         boost::asio::detail::throw_error(ec, "handshake");
         }

      /**
       * Performs SSL handshaking.
       * The function call will block until handshaking is complete or an error occurs.
       * @param type The type of handshaking to be performed, i.e. as a client or as a server.
       * @param ec Set to indicate what error occurred, if any.
       */
      void handshake(Connection_Side side, boost::system::error_code& ec)
         {
         setup_channel(side);

         while(!native_handle()->is_active())
            {
            sendPendingEncryptedData(ec);
            if(ec)
               { return; }

            boost::asio::const_buffer read_buffer
               {
               this->m_core.input_buffer.data(),
               m_nextLayer.read_some(this->m_core.input_buffer, ec)
               };

            if(ec)
               { return; }

            try
               {
               native_handle()->received_data(static_cast<const uint8_t*>(read_buffer.data()),
                                              read_buffer.size());
               }
            catch(const TLS_Exception& e)
               {
               ec = e.type();
               return;
               }
            catch(const Botan::Exception& e)
               {
               ec = e.error_type();
               return;
               }
            catch(const std::exception&)
               {
               ec = Botan::ErrorType::Unknown;
               return;
               }

            sendPendingEncryptedData(ec);
            }
         }

      /**
       * Starts an asynchronous SSL handshake.
       * This function call always returns immediately.
       * @param type The type of handshaking to be performed, i.e. as a client or as a server.
       * @param handler The handler to be called when the handshake operation completes.
       *                The equivalent function signature of the handler must be: void(boost::system::error_code)
       * @throws Invalid_Argument if Connection_Side could not be validated
       */
      template <typename HandshakeHandler>
      BOOST_ASIO_INITFN_RESULT_TYPE(HandshakeHandler,
                                    void(boost::system::error_code))
      async_handshake(Connection_Side side, HandshakeHandler&& handler)
         {
         BOOST_ASIO_HANDSHAKE_HANDLER_CHECK(HandshakeHandler, handler) type_check;

         setup_channel(side);

         boost::asio::async_completion<HandshakeHandler, void(boost::system::error_code)> init(handler);

         AsyncHandshakeOperation<typename std::decay<HandshakeHandler>::type, Stream>
         op{std::move(init.completion_handler), *this, this->m_core};

         return init.result.get();
         }

      /**
       * @throws Not_Implemented
       */
      template <typename ConstBufferSequence, typename BufferedHandshakeHandler>
      BOOST_ASIO_INITFN_RESULT_TYPE(BufferedHandshakeHandler,
                                    void(boost::system::error_code, std::size_t))
      async_handshake(Connection_Side side, const ConstBufferSequence& buffers,
                      BufferedHandshakeHandler&& handler)
         {
         BOTAN_UNUSED(buffers, handler);
         BOOST_ASIO_HANDSHAKE_HANDLER_CHECK(BufferedHandshakeHandler, handler) type_check;
         validate_connection_side(side);
         throw Not_Implemented("buffered async handshake is not implemented");
         }

      //
      // -- -- shutdown methods
      //

      /**
       * Shut down SSL on the stream.
       * The function call will block until SSL has been shut down or an error occurs.
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
            return;
            }
         catch(const Botan::Exception& e)
            {
            ec = e.error_type();
            return;
            }
         catch(const std::exception&)
            {
            ec = Botan::ErrorType::Unknown;
            return;
            }

         sendPendingEncryptedData(ec);
         }

      /**
       * Shut down SSL on the stream.
       * The function call will block until SSL has been shut down or an error occurs.
       * @throws boost::system::system_error if error occured
       */
      void shutdown()
         {
         boost::system::error_code ec;
         shutdown(ec);
         boost::asio::detail::throw_error(ec, "shutdown");
         }

      /**
       * Asynchronously shut down SSL on the stream.
       * This function call always returns immediately.
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

      //
      // -- -- I/O methods
      //

      /**
       * Read some data from the stream. The function call will block until one or more bytes of data has
       * been read successfully, or until an error occurs.
       * @param buffers The buffers into which the data will be read.
       * @param ec Set to indicate what error occured, if any.
       * @return The number of bytes read. Returns 0 if an error occurred.
       */
      template <typename MutableBufferSequence>
      std::size_t read_some(const MutableBufferSequence& buffers,
                            boost::system::error_code& ec)
         {
         if(this->m_core.hasReceivedData())
            { return this->m_core.copyReceivedData(buffers); }

         tls_receive_some(ec);
         if(ec)
            { return 0; }

         return this->m_core.copyReceivedData(buffers);
         }

      /**
       * Read some data from the stream. The function call will block until one or more bytes of data has
       * been read successfully, or until an error occurs.
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
       * Write some data to the stream. The function call will block until one or more bytes of data has been written
       * successfully, or until an error occurs.
       *
       * @param buffers The data to be written.
       * @param ec Set to indicate what error occurred, if any.
       * @return The number of bytes written.
       */
      template <typename ConstBufferSequence>
      std::size_t write_some(const ConstBufferSequence& buffers,
                             boost::system::error_code& ec)
         {
         std::size_t sent = tls_encrypt_some(buffers, ec);
         if(ec)
            { return 0; }

         sendPendingEncryptedData(ec);
         if(ec)
            { return 0; }

         return sent;
         }

      /**
       * Write some data to the stream. The function call will block until one or more bytes of data has been written
       * successfully, or until an error occurs.
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
       * Start an asynchronous write. The function call always returns immediately.
       *
       * @param buffers The data to be written.
       * @param handler The handler to be called when the write operation completes. Copies will be made of the handler
       *        as required. The equivalent function signature of the handler must be:
       *        void(boost::system::error_code, std::size_t)
       */
      template <typename ConstBufferSequence, typename WriteHandler>
      BOOST_ASIO_INITFN_RESULT_TYPE(WriteHandler,
                                    void(boost::system::error_code, std::size_t))
      async_write_some(const ConstBufferSequence& buffers, WriteHandler&& handler)
         {
         BOOST_ASIO_WRITE_HANDLER_CHECK(WriteHandler, handler) type_check;

         boost::asio::async_completion<WriteHandler, void(boost::system::error_code, std::size_t)> init(handler);

         boost::system::error_code ec;
         std::size_t sent = tls_encrypt_some(buffers, ec);
         if(ec)
            {
            // we cannot be sure how many bytes were committed here
            // so clear the send_buffer and let the AsyncWriteOperation call the handler with the error_code set
            this->m_core.clearSendBuffer();
            Botan::TLS::AsyncWriteOperation<typename std::decay<WriteHandler>::type, Stream>
            op{std::move(init.completion_handler), *this, this->m_core, std::size_t(0), ec};
            return init.result.get();
            }

         Botan::TLS::AsyncWriteOperation<typename std::decay<WriteHandler>::type, Stream>
         op{std::move(init.completion_handler), *this, this->m_core, sent};

         return init.result.get();
         }

      /**
       * Start an asynchronous read. The function call always returns immediately.
       *
       * @param buffers The buffers into which the data will be read. Although the buffers object may be copied as
       *                necessary, ownership of the underlying buffers is retained by the caller, which must guarantee
       *                that they remain valid until the handler is called.
       * @param handler The handler to be called when the read operation completes. The equivalent function signature of
       *                the handler must be:
       *                void(boost::system::error_code, std::size_t)
       */
      template <typename MutableBufferSequence, typename ReadHandler>
      BOOST_ASIO_INITFN_RESULT_TYPE(ReadHandler,
                                    void(boost::system::error_code, std::size_t))
      async_read_some(const MutableBufferSequence& buffers, ReadHandler&& handler)
         {
         BOOST_ASIO_READ_HANDLER_CHECK(ReadHandler, handler) type_check;

         boost::asio::async_completion<ReadHandler, void(boost::system::error_code, std::size_t)> init(handler);

         AsyncReadOperation<typename std::decay<ReadHandler>::type, Stream, MutableBufferSequence>
         op{std::move(init.completion_handler), *this, this->m_core, buffers};
         return init.result.get();
         }

      // TODO: remove StreamCore from public interface
      /**
       * Contains the buffers for reading/sending, and the needed botan callbacks
       */
      class StreamCore : public Botan::TLS::Callbacks
         {
         public:
            StreamCore()
               : m_input_buffer_space(MAX_CIPHERTEXT_SIZE, '\0'),
                 input_buffer(m_input_buffer_space.data(), m_input_buffer_space.size()) {}

            virtual ~StreamCore() = default;

            void tls_emit_data(const uint8_t data[], std::size_t size) override
               {
               // Provide the encrypted TLS data in the sendBuffer. Actually sending the data is done
               // using (async_)write_some either in the stream or in an async operation.
               m_send_buffer.commit(
                  boost::asio::buffer_copy(m_send_buffer.prepare(size), boost::asio::buffer(data, size)));
               }

            void tls_record_received(uint64_t, const uint8_t data[], std::size_t size) override
               {
               // TODO: It would be nice to avoid this buffer copy. However, we need to deal with the case
               // that the receive buffer provided by the caller is smaller than the decrypted record.
               auto buffer = m_receive_buffer.prepare(size);
               auto copySize =
                  boost::asio::buffer_copy(buffer, boost::asio::const_buffer(data, size));
               m_receive_buffer.commit(copySize);
               }

            void tls_alert(Botan::TLS::Alert alert) override
               {
               if(alert.type() == Botan::TLS::Alert::CLOSE_NOTIFY)
                  {
                  // TODO
                  }
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

            bool hasReceivedData() const
               {
               return m_receive_buffer.size() > 0;
               }

            template <typename MutableBufferSequence>
            std::size_t copyReceivedData(MutableBufferSequence buffers)
               {
               const auto copiedBytes =
                  boost::asio::buffer_copy(buffers, m_receive_buffer.data());
               m_receive_buffer.consume(copiedBytes);
               return copiedBytes;
               }

            bool hasDataToSend() const { return m_send_buffer.size() > 0; }

            boost::asio::const_buffer sendBuffer() const
               {
               return m_send_buffer.data();
               }

            void consumeSendBuffer(std::size_t bytesConsumed)
               {
               m_send_buffer.consume(bytesConsumed);
               }

            void clearSendBuffer()
               {
               consumeSendBuffer(m_send_buffer.size());
               }

         private:
            // Buffer space used to read input intended for the engine.
            std::vector<uint8_t>      m_input_buffer_space;
            boost::beast::flat_buffer m_receive_buffer;
            boost::beast::flat_buffer m_send_buffer;

         public:
            // A buffer that may be used to read input intended for the engine.
            const boost::asio::mutable_buffer input_buffer;
         };

   protected:
      // TODO: explain, note: c++17 makes this much better with constexpr if
      template<class T = ChannelT>
      typename std::enable_if<!std::is_same<Channel, T>::value>::type
      setup_channel(Connection_Side) {}

      template<class T = ChannelT>
      typename std::enable_if<std::is_same<Channel, T>::value>::type
      setup_channel(Connection_Side side)
         {
         assert(side == CLIENT);
         m_channel = std::unique_ptr<Client>(new Client(m_core,
                          *m_context.sessionManager,
                          *m_context.credentialsManager,
                          *m_context.policy,
                          *m_context.randomNumberGenerator,
                          m_context.serverInfo));
         }

      //! \brief validate the connection side (OpenSSL compatibility)
      void validate_connection_side(Connection_Side side)
         {
         if(side != CLIENT)
            {
            throw Invalid_Argument("wrong connection_side");
            }
         }

      //! \brief validate the connection side (OpenSSL compatibility)
      bool validate_connection_side(Connection_Side side, boost::system::error_code& ec)
         {
         if(side != CLIENT)
            {
            ec = Botan::ErrorType::InvalidArgument;
            return false;
            }

         return true;
         }

      size_t sendPendingEncryptedData(boost::system::error_code& ec)
         {
         auto writtenBytes = boost::asio::write(m_nextLayer, this->m_core.sendBuffer(), ec);

         this->m_core.consumeSendBuffer(writtenBytes);
         return writtenBytes;
         }

      void tls_receive_some(boost::system::error_code& ec)
         {
         boost::asio::const_buffer read_buffer =
            {
            this->m_core.input_buffer.data(),
            m_nextLayer.read_some(this->m_core.input_buffer, ec)
            };

         if(ec)
            { return; }

         try
            {
            native_handle()->received_data(static_cast<const uint8_t*>(read_buffer.data()),
                                           read_buffer.size());
            }
         catch(const TLS_Exception& e)
            {
            ec = e.type();
            return;
            }
         catch(const Botan::Exception& e)
            {
            ec = e.error_type();
            return;
            }
         catch(const std::exception&)
            {
            ec = Botan::ErrorType::Unknown;
            return;
            }
         }

      template <typename ConstBufferSequence>
      std::size_t tls_encrypt_some(const ConstBufferSequence& buffers,
                                   boost::system::error_code& ec)
         {
         std::size_t sent = 0;
         // NOTE: This is not asynchronous: it encrypts the data synchronously.
         // The data encrypted by native_handle()->send() is synchronously stored in the send_buffer of m_core,
         // but is not actually written to the wire, yet.
         for(auto it = boost::asio::buffer_sequence_begin(buffers);
               it != boost::asio::buffer_sequence_end(buffers);
               it++)
            {
            if(sent >= MAX_PLAINTEXT_SIZE)
               { return 0; }

            boost::asio::const_buffer buffer = *it;
            const auto amount =
               std::min<std::size_t>(MAX_PLAINTEXT_SIZE - sent, buffer.size());
            try
               {
               native_handle()->send(static_cast<const uint8_t*>(buffer.data()), amount);
               }
            catch(const TLS_Exception& e)
               {
               ec = e.type();
               return 0;
               }
            catch(const Botan::Exception& e)
               {
               ec = e.error_type();
               return 0;
               }
            catch(const std::exception&)
               {
               ec = Botan::ErrorType::Unknown;
               return 0;
               }
            sent += amount;
            }

         return sent;
         }

      Context                   m_context;
      StreamLayer               m_nextLayer;
      StreamCore                m_core;
      std::unique_ptr<ChannelT> m_channel;
   };

}  // namespace TLS

}  // namespace Botan

#endif // BOOST_VERSION
#endif // BOTAN_ASIO_STREAM_H_
