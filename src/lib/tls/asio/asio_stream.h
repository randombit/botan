/*
* TLS ASIO Stream Wrapper
* (C) 2018-2019 Jack Lloyd
*     2018-2019 Hannes Rantzsch, Tim Oesterreich, Rene Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ASIO_STREAM_H_
#define BOTAN_ASIO_STREAM_H_

#include <botan/internal/asio_async_handshake_op.h>
#include <botan/internal/asio_async_read_op.h>
#include <botan/internal/asio_async_write_op.h>
#include <botan/internal/asio_convert_exceptions.h>
#include <botan/internal/asio_includes.h>
#include <botan/internal/asio_stream_base.h>
#include <botan/internal/asio_stream_core.h>

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
 * boost::asio compatible SSL/TLS stream based on TLS::Client or TLS::Server.
 */
template <class StreamLayer, class Channel>
class Stream final : public StreamBase<Channel>
   {
   public:
      using next_layer_type = typename std::remove_reference<StreamLayer>::type;
      using lowest_layer_type = typename next_layer_type::lowest_layer_type;
      using executor_type = typename next_layer_type::executor_type;
      using native_handle_type = typename std::add_pointer<Channel>::type;

      using StreamBase<Channel>::validate_handshake_type;

   public:
      template <typename... Args>
      Stream(StreamLayer&& nextLayer, Args&& ... args)
         : StreamBase<Channel>(std::forward<Args>(args)...),
           m_nextLayer(std::forward<StreamLayer>(nextLayer)) {}

      Stream(StreamLayer&& nextLayer, boost::asio::ssl::context&)
         : StreamBase<Channel>(Botan::TLS::Session_Manager_Noop(), Botan::Credentials_Manager()),
           m_nextLayer(std::forward<StreamLayer>(nextLayer))
         {
         // Configuring a TLS stream via asio::ssl::context is not supported.
         // The corresponding configuration objects for Botan are:
         //   * TLS::Session_Manager
         //   * Credentials_Manager
         //   * TLS::Policy
         //   * TLS::Server_Information
         // It would be nice to have a masquarading wrapper that exposes an API
         // compatible with asio::ssl::context for convenient drop-in replacement.
         // For now, base your TLS configurations on the above mentioned classes.
         throw Not_Implemented("cannot handle an asio::ssl::context");
         }

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

      template<
         typename VerifyCallback>
      void set_verify_callback(VerifyCallback callback)
         {
         BOTAN_UNUSED(callback);
         throw Not_Implemented("set_verify_callback is not implemented");
         }

      template<
         typename VerifyCallback>
      void set_verify_callback(VerifyCallback callback,
                               boost::system::error_code& ec)
         {
         BOTAN_UNUSED(callback);
         ec = make_error_code(Botan::TLS::error::not_implemented);
         }

      void set_verify_depth(int depth)
         {
         BOTAN_UNUSED(depth);
         throw Not_Implemented("set_verify_depth is not implemented");
         }

      void set_verify_depth(int depth,
                            boost::system::error_code& ec)
         {
         BOTAN_UNUSED(depth);
         ec = make_error_code(Botan::TLS::error::not_implemented);
         }

      template <typename verify_mode>
      void set_verify_mode(verify_mode v)
         {
         BOTAN_UNUSED(v);
         throw Not_Implemented("set_verify_mode is not implemented");
         }

      template <typename verify_mode>
      void set_verify_mode(verify_mode v,
                           boost::system::error_code& ec)
         {
         BOTAN_UNUSED(v);
         ec = make_error_code(Botan::TLS::error::not_implemented);
         }

      //
      // -- -- handshake methods
      //

      void handshake()
         {
         boost::system::error_code ec;
         handshake(ec);
         boost::asio::detail::throw_error(ec, "handshake");
         }

      void handshake(boost::system::error_code& ec)
         {
         while(!native_handle()->is_active())
            {
            writePendingTlsData(ec);
            if(ec)
               {
               return;
               }

            auto read_buffer = boost::asio::buffer(
                                  this->m_core.input_buffer,
                                  m_nextLayer.read_some(this->m_core.input_buffer, ec));
            if(ec)
               {
               return;
               }

            try
               {
               native_handle()->received_data(static_cast<const uint8_t*>(read_buffer.data()),
                                              read_buffer.size());
               }
            catch(...)
               {
               ec = Botan::TLS::convertException();
               return;
               }

            writePendingTlsData(ec);
            }
         }

      template <typename HandshakeHandler>
      BOOST_ASIO_INITFN_RESULT_TYPE(HandshakeHandler,
                                    void(boost::system::error_code))
      async_handshake(HandshakeHandler&& handler)
         {
         BOOST_ASIO_HANDSHAKE_HANDLER_CHECK(HandshakeHandler, handler) type_check;

         boost::asio::async_completion<HandshakeHandler,
               void(boost::system::error_code)>
               init(handler);

         auto op = create_async_handshake_op(std::move(init.completion_handler));
         op(boost::system::error_code{}, 0, 1);

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

      void handshake(handshake_type type)
         {
         validate_handshake_type(type);
         handshake();
         }

      void handshake(handshake_type type, boost::system::error_code& ec)
         {
         if(validate_handshake_type(type, ec))
            {
            handshake(ec);
            }
         }

      template <typename HandshakeHandler>
      BOOST_ASIO_INITFN_RESULT_TYPE(HandshakeHandler,
                                    void(boost::system::error_code))
      async_handshake(handshake_type type, HandshakeHandler&& handler)
         {
         validate_handshake_type(type);
         return async_handshake(handler);
         }

      template<typename ConstBufferSequence>
      void handshake(handshake_type type, const ConstBufferSequence& buffers)
         {
         BOTAN_UNUSED(buffers);
         validate_handshake_type(type);
         throw Not_Implemented("buffered handshake is not implemented");
         }

      template<typename ConstBufferSequence>
      void handshake(handshake_type type,
                     const ConstBufferSequence& buffers,
                     boost::system::error_code& ec)
         {
         BOTAN_UNUSED(buffers);
         if(validate_handshake_type(type, ec))
            {
            ec = make_error_code(Botan::TLS::error::not_implemented);
            }
         }

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

      void shutdown(boost::system::error_code& ec)
         {
         try
            {
            native_handle()->close();
            }
         catch(...)
            {
            ec = Botan::TLS::convertException();
            return;
            }
         writePendingTlsData(ec);
         }

      void shutdown()
         {
         boost::system::error_code ec;
         shutdown(ec);
         boost::asio::detail::throw_error(ec, "shutdown");
         }

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

      template <typename MutableBufferSequence>
      std::size_t read_some(const MutableBufferSequence& buffers,
                            boost::system::error_code& ec)
         {
         if(this->m_core.hasReceivedData())
            {
            return this->m_core.copyReceivedData(buffers);
            }

         auto read_buffer = boost::asio::buffer(
                               this->m_core.input_buffer,
                               m_nextLayer.read_some(this->m_core.input_buffer, ec));
         if(ec)
            {
            return 0;
            }

         try
            {
            native_handle()->received_data(static_cast<const uint8_t*>(read_buffer.data()),
                                           read_buffer.size());
            }
         catch(...)
            {
            ec = Botan::TLS::convertException();
            return 0;
            }

         return this->m_core.copyReceivedData(buffers);
         }

      template <typename MutableBufferSequence>
      std::size_t read_some(const MutableBufferSequence& buffers)
         {
         boost::system::error_code ec;
         auto const n = read_some(buffers, ec);
         boost::asio::detail::throw_error(ec, "read_some");
         return n;
         }

      template <typename ConstBufferSequence>
      std::size_t write_some(const ConstBufferSequence& buffers,
                             boost::system::error_code& ec)
         {
         boost::asio::const_buffer buffer =
            boost::asio::detail::buffer_sequence_adapter<
            boost::asio::const_buffer, ConstBufferSequence>::first(buffers);

         try
            {
            native_handle()->send(static_cast<const uint8_t*>(buffer.data()), buffer.size());
            }
         catch(...)
            {
            ec = Botan::TLS::convertException();
            return 0;
            }

         writePendingTlsData(ec);
         if(ec)
            {
            return 0;
            }
         return buffer.size();
         }

      template <typename ConstBufferSequence>
      std::size_t write_some(const ConstBufferSequence& buffers)
         {
         boost::system::error_code ec;
         auto const n = write_some(buffers, ec);
         boost::asio::detail::throw_error(ec, "write_some");
         return n;
         }

      template <typename ConstBufferSequence, typename WriteHandler>
      BOOST_ASIO_INITFN_RESULT_TYPE(WriteHandler,
                                    void(boost::system::error_code, std::size_t))
      async_write_some(const ConstBufferSequence& buffers, WriteHandler&& handler)
         {
         BOOST_ASIO_WRITE_HANDLER_CHECK(WriteHandler, handler) type_check;

         boost::asio::const_buffer buffer =
            boost::asio::detail::buffer_sequence_adapter<
            boost::asio::const_buffer, ConstBufferSequence>::first(buffers);

         boost::asio::async_completion<WriteHandler,
               void(boost::system::error_code, std::size_t)>
               init(handler);

         try
            {
            // NOTE: This is not asynchronous: it encrypts the data synchronously.
            // Only writing on the socket is asynchronous.
            native_handle()->send(static_cast<const uint8_t*>(buffer.data()),
                                  buffer.size());
            }
         catch(...)
            {
            init.completion_handler(Botan::TLS::convertException(), 0);
            return init.result.get();
            }

         auto op = create_async_write_op(std::move(init.completion_handler),
                                         buffer.size());

         boost::asio::async_write(m_nextLayer, this->m_core.sendBuffer(),
                                  std::move(op));
         return init.result.get();
         }

      template <typename MutableBufferSequence, typename ReadHandler>
      BOOST_ASIO_INITFN_RESULT_TYPE(ReadHandler,
                                    void(boost::system::error_code, std::size_t))
      async_read_some(const MutableBufferSequence& buffers, ReadHandler&& handler)
         {
         BOOST_ASIO_READ_HANDLER_CHECK(ReadHandler, handler) type_check;

         boost::asio::async_completion<ReadHandler,
               void(boost::system::error_code, std::size_t)>
               init(handler);

         auto op = create_async_read_op(std::move(init.completion_handler), buffers);
         op(boost::system::error_code{}, 0);
         return init.result.get();
         }

   protected:
      size_t writePendingTlsData(boost::system::error_code& ec)
         {
         auto writtenBytes =
            boost::asio::write(m_nextLayer, this->m_core.sendBuffer(), ec);

         this->m_core.consumeSendBuffer(writtenBytes);
         return writtenBytes;
         }

      template <typename Handler>
      Botan::TLS::AsyncHandshakeOperation<Channel, StreamLayer, Handler>
      create_async_handshake_op(Handler&& handler)
         {
         return Botan::TLS::AsyncHandshakeOperation<Channel, StreamLayer, Handler>(
                   native_handle(), this->m_core, m_nextLayer, std::forward<Handler>(handler));
         }

      template <typename Handler, typename MutableBufferSequence>
      Botan::TLS::AsyncReadOperation<Channel, StreamLayer, Handler,
            MutableBufferSequence>
            create_async_read_op(Handler&& handler,
                                 const MutableBufferSequence& buffers)
         {
         return Botan::TLS::AsyncReadOperation<Channel, StreamLayer, Handler,
                MutableBufferSequence>(
                   native_handle(), this->m_core, m_nextLayer, std::forward<Handler>(handler),
                   buffers);
         }

      template <typename Handler>
      Botan::TLS::AsyncWriteOperation<Handler>
      create_async_write_op(Handler&& handler, std::size_t plainBytesTransferred)
         {
         return Botan::TLS::AsyncWriteOperation<Handler>(
                   this->m_core, std::forward<Handler>(handler), plainBytesTransferred);
         }

   protected:
      StreamLayer m_nextLayer;
   };

} // TLS

} // namespace Botan

#endif
