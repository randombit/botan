/*
* TLS ASIO Stream Wrapper
* (C) 2018-2019 Jack Lloyd
*     2018-2019 Hannes Rantzsch, Tim Oesterreich, Rene Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ASIO_STREAM_H_
#define BOTAN_ASIO_STREAM_H_

#if defined(BOTAN_HAS_TLS) && defined(BOTAN_HAS_BOOST_ASIO)

#include <boost/version.hpp>
#if BOOST_VERSION > 106600

#include <botan/internal/asio_async_handshake_op.h>
#include <botan/internal/asio_async_read_op.h>
#include <botan/internal/asio_async_write_op.h>
#include <botan/internal/asio_convert_exceptions.h>
#include <botan/internal/asio_includes.h>
#include <botan/internal/asio_stream_base.h>
#include <botan/internal/asio_stream_core.h>
#include <botan/asio_context.h>

#include <algorithm>
#include <memory>
#include <thread>
#include <type_traits>

namespace boost {
namespace asio {
namespace ssl {
class context;
}
}
}

namespace Botan {

namespace TLS {

/**
 * boost::asio compatible SSL/TLS stream
 *
 * Currently only the TLS::Client specialization is implemented.
 */
template <class StreamLayer, class Channel>
class Stream : public StreamBase<Channel>
   {
   public:
      using next_layer_type = typename std::remove_reference<StreamLayer>::type;
      using lowest_layer_type = typename next_layer_type::lowest_layer_type;
      using executor_type = typename next_layer_type::executor_type;
      using native_handle_type = typename std::add_pointer<Channel>::type;

      using StreamBase<Channel>::validate_handshake_type;

   public:
      template <typename... Args>
      explicit Stream(Context& context, Args&& ... args)
         : StreamBase<Channel>(context), m_nextLayer(std::forward<Args>(args)...) {}

      // overload for boost::asio::ssl::stream compatibility
      template <typename Arg>
      explicit Stream(Arg&& arg, Context& context)
         : StreamBase<Channel>(context), m_nextLayer(std::forward<Arg>(arg)) {}

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

      native_handle_type native_handle() { return &this->m_channel; }

      //
      // -- -- configuration and callback setters
      //

      /**
       * @throws Not_Implemented
       */
      template<
         typename VerifyCallback>
      void set_verify_callback(VerifyCallback callback)
         {
         BOTAN_UNUSED(callback);
         throw Not_Implemented("set_verify_callback is not implemented");
         }

      /**
       * Not Implemented.
       * @param ec Will be set to `Botan::TLS::error::not_implemented`
       */
      template<
         typename VerifyCallback>
      void set_verify_callback(VerifyCallback callback,
                               boost::system::error_code& ec)
         {
         BOTAN_UNUSED(callback);
         ec = Botan::TLS::error::not_implemented;
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
       * @param ec Will be set to `Botan::TLS::error::not_implemented`
       */
      void set_verify_depth(int depth,
                            boost::system::error_code& ec)
         {
         BOTAN_UNUSED(depth);
         ec = Botan::TLS::error::not_implemented;
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
       * @param ec Will be set to `Botan::TLS::error::not_implemented`
       */
      template <typename verify_mode>
      void set_verify_mode(verify_mode v,
                           boost::system::error_code& ec)
         {
         BOTAN_UNUSED(v);
         ec = Botan::TLS::error::not_implemented;
         }

      //
      // -- -- handshake methods
      //

      /**
       * Performs SSL handshaking.
       * The function call will block until handshaking is complete or an error occurs.
       * @throws boost::system::system_error if error occured
       */
      void handshake()
         {
         boost::system::error_code ec;
         handshake(ec);
         boost::asio::detail::throw_error(ec, "handshake");
         }

      /**
       * Performs SSL handshaking.
       * The function call will block until handshaking is complete or an error occurs.
       * @param ec Set to indicate what error occurred, if any.
       */
      void handshake(boost::system::error_code& ec)
         {
         while(!native_handle()->is_active())
            {
            writePendingTlsData(ec);
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
            catch(const std::exception& ex)
               {
               ec = Botan::TLS::convertException();
               return;
               }

            writePendingTlsData(ec);
            }
         }

      /**
       * Starts an asynchronous SSL handshake.
       * This function call always returns immediately.
       * @param handler The handler to be called when the handshake operation completes.
       *                The equivalent function signature of the handler must be: void(boost::system::error_code)
       */
      template <typename HandshakeHandler>
      BOOST_ASIO_INITFN_RESULT_TYPE(HandshakeHandler,
                                    void(boost::system::error_code))
      async_handshake(HandshakeHandler&& handler)
         {
         BOOST_ASIO_HANDSHAKE_HANDLER_CHECK(HandshakeHandler, handler) type_check;

         boost::asio::async_completion<HandshakeHandler, void(boost::system::error_code)> init(handler);

         AsyncHandshakeOperation<typename std::decay<HandshakeHandler>::type, Stream>
         op{std::move(init.completion_handler), *this, this->m_core};

         return init.result.get();
         }

      //
      // -- -- asio::ssl::stream compatibility methods
      //
      //       The OpenSSL-based stream contains an operation flag that tells
      //       the stream to either impersonate a TLS server or client. This
      //       implementation defines those modes at compile time (via template
      //       specialization of the StreamBase class) and merely checks the
      //       flag's consistency before performing the respective handshakes.
      //

      /**
       * Performs SSL handshaking.
       * The function call will block until handshaking is complete or an error occurs.
       * @param type The type of handshaking to be performed, i.e. as a client or as a server.
       * @throws boost::system::system_error if error occured
       * @throws Invalid_Argument if handshake_type could not be validated
       */
      void handshake(handshake_type type)
         {
         validate_handshake_type(type);
         handshake();
         }

      /**
       * Performs SSL handshaking.
       * The function call will block until handshaking is complete or an error occurs.
       * @param type The type of handshaking to be performed, i.e. as a client or as a server.
       * @param ec Set to indicate what error occurred, if any.
       */
      void handshake(handshake_type type, boost::system::error_code& ec)
         {
         if(validate_handshake_type(type, ec))
            { handshake(ec); }
         }

      /**
       * Starts an asynchronous SSL handshake.
       * This function call always returns immediately.
       * @param type The type of handshaking to be performed, i.e. as a client or as a server.
       * @param handler The handler to be called when the handshake operation completes.
       *                The equivalent function signature of the handler must be: void(boost::system::error_code)
       * @throws Invalid_Argument if handshake_type could not be validated
       */
      template <typename HandshakeHandler>
      BOOST_ASIO_INITFN_RESULT_TYPE(HandshakeHandler,
                                    void(boost::system::error_code))
      async_handshake(handshake_type type, HandshakeHandler&& handler)
         {
         validate_handshake_type(type);
         return async_handshake(std::forward<HandshakeHandler>(handler));
         }

      /**
       * @throws Not_Implemented
       */
      template<typename ConstBufferSequence>
      void handshake(handshake_type type, const ConstBufferSequence& buffers)
         {
         BOTAN_UNUSED(buffers);
         validate_handshake_type(type);
         throw Not_Implemented("buffered handshake is not implemented");
         }

      /**
       * Not Implemented.
       * @param ec Will be set to `Botan::TLS::error::not_implemented`
       */
      template<typename ConstBufferSequence>
      void handshake(handshake_type type,
                     const ConstBufferSequence& buffers,
                     boost::system::error_code& ec)
         {
         BOTAN_UNUSED(buffers);
         if(validate_handshake_type(type, ec))
            { ec = Botan::TLS::error::not_implemented; }
         }

      /**
       * @throws Not_Implemented
       */
      template <typename ConstBufferSequence, typename BufferedHandshakeHandler>
      BOOST_ASIO_INITFN_RESULT_TYPE(BufferedHandshakeHandler,
                                    void(boost::system::error_code, std::size_t))
      async_handshake(handshake_type type, const ConstBufferSequence& buffers,
                      BufferedHandshakeHandler&& handler)
         {
         BOTAN_UNUSED(buffers, handler);
         BOOST_ASIO_HANDSHAKE_HANDLER_CHECK(BufferedHandshakeHandler, handler) type_check;
         validate_handshake_type(type);
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
         catch(const std::exception& ex)
            {
            ec = Botan::TLS::convertException();
            return;
            }
         writePendingTlsData(ec);
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

         tls_decrypt_some(ec);
         if(ec)
            { return 0; }

         return this->m_core.copyReceivedData(buffers);
         }

      /**
       * Read some data from the stream. The function call will block until one or more bytes of data has
       * been read successfully, or until an error occurs.
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
       * @param buffers The data to be written.
       * @param ec Set to indicate what error occurred, if any.
       * @return The number of bytes written.
       */
      template <typename ConstBufferSequence>
      std::size_t write_some(const ConstBufferSequence& buffers,
                             boost::system::error_code& ec)
         {
         std::size_t sent;
         sent = tls_encrypt_some(buffers, ec);
         if(ec)
            { return 0; }

         writePendingTlsData(ec);
         if(ec)
            { return 0; }

         return sent;
         }

      /**
       * Write some data to the stream. The function call will block until one or more bytes of data has been written
       * successfully, or until an error occurs.
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

         std::size_t sent;
         boost::system::error_code ec;
         sent = tls_encrypt_some(buffers, ec);
         if(ec)
            {
            // we can't be sure how many bytes were commited here, so clear the send_buffer and try again
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
       * @param buffers The buffers into which the data will be read. Although the buffers object may be copied as
       *                 necessary, ownership of the underlying buffers is retained by the caller, which must guarantee
       *                 that they remain valid until the handler is called.
       * @param handler The handler to be called when the read operation completes.
       *                The equivalent function signature of the handler must be:
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
         op{std::move(init.completion_handler),
            *this,
            this->m_core,
            buffers};

         return init.result.get();
         }

   protected:
      size_t writePendingTlsData(boost::system::error_code& ec)
         {
         auto writtenBytes = boost::asio::write(m_nextLayer, this->m_core.sendBuffer(), ec);

         this->m_core.consumeSendBuffer(writtenBytes);
         return writtenBytes;
         }

      void tls_decrypt_some(boost::system::error_code& ec)
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
         catch(const std::exception& ex)
            {
            ec = Botan::TLS::convertException();
            }
         }

      template <typename ConstBufferSequence>
      std::size_t tls_encrypt_some(const ConstBufferSequence& buffers,
                                   boost::system::error_code& ec)
         {
         std::size_t sent = 0;
         // NOTE: This is not asynchronous: it encrypts the data synchronously.
         // Only writing on the socket is asynchronous.
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
            catch(const std::exception&)
               {
               ec = Botan::TLS::convertException();
               return 0;
               }
            sent += amount;
            }

         return sent;
         }

      StreamLayer m_nextLayer;
   };

} // TLS

} // namespace Botan

#endif // BOOST_VERSION
#endif // BOTAN_HAS_TLS && BOTAN_HAS_BOOST_ASIO
#endif // BOTAN_ASIO_STREAM_H_
