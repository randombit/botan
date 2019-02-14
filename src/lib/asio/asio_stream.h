#ifndef BOTAN_ASIO_STREAM_H_
#define BOTAN_ASIO_STREAM_H_

#include <botan/asio_async_handshake_op.h>
#include <botan/asio_async_read_op.h>
#include <botan/asio_async_write_op.h>
#include <botan/asio_convert_exceptions.h>
#include <botan/asio_includes.h>
#include <botan/asio_stream_base.h>
#include <botan/asio_stream_core.h>

#include <memory>
#include <thread>
#include <type_traits>

namespace Botan {

/**
 * boost::asio compatible SSL/TLS stream based on TLS::Client or TLS::Server.
 */
template <class StreamLayer, class Channel>
class Stream : public StreamBase<Channel>
   {
   public:
      using next_layer_type = typename std::remove_reference<StreamLayer>::type;

      using lowest_layer_type = typename next_layer_type::lowest_layer_type;

      using executor_type = typename next_layer_type::executor_type;

      template <typename... Args>
      Stream(StreamLayer nextLayer, Args&& ... args)
         : StreamBase<Channel>(std::forward<Args>(args)...),
           nextLayer_(std::forward<StreamLayer>(nextLayer)) {}

      executor_type get_executor() noexcept { return nextLayer_.get_executor(); }

      const next_layer_type& next_layer() const { return nextLayer_; }
      next_layer_type& next_layer() { return nextLayer_; }

      lowest_layer_type& lowest_layer() { return nextLayer_.lowest_layer(); }

      Channel& channel() { return this->channel_; }

      const Channel& channel() const { return this->channel_; }

      void handshake(boost::system::error_code& ec)
         {
         while(!channel().is_active())
            {
            writePendingTlsData(ec);
            if(ec)
               {
               return;
               }

            auto read_buffer = boost::asio::buffer(
                                  this->core_.input_buffer_,
                                  nextLayer_.read_some(this->core_.input_buffer_, ec));
            if(ec)
               {
               return;
               }

            try
               {
               channel().received_data(static_cast<const uint8_t*>(read_buffer.data()),
                                       read_buffer.size());
               }
            catch(...)
               {
               ec = Botan::convertException();
               return;
               }

            writePendingTlsData(ec);
            }
         }

      void handshake()
         {
         boost::system::error_code ec;
         handshake(ec);
         boost::asio::detail::throw_error(ec, "handshake");
         }

      template <typename HandshakeHandler>
      BOOST_ASIO_INITFN_RESULT_TYPE(HandshakeHandler,
                                    void(boost::system::error_code))
      async_handshake(HandshakeHandler&& handler)
         {
         // If you get an error on the following line it means that your handler does
         // not meet the documented type requirements for a HandshakeHandler.
         BOOST_ASIO_HANDSHAKE_HANDLER_CHECK(HandshakeHandler, handler) type_check;

         boost::asio::async_completion<HandshakeHandler,
               void(boost::system::error_code)>
               init(handler);

         auto op = create_async_handshake_op(std::move(init.completion_handler));
         op(boost::system::error_code{}, 0, 1);

         return init.result.get();
         }

      void shutdown(boost::system::error_code& ec)
         {
         try
            {
            channel().close();
            }
         catch(...)
            {
            ec = Botan::convertException();
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

      template <typename MutableBufferSequence>
      std::size_t read_some(const MutableBufferSequence& buffers,
                            boost::system::error_code& ec)
         {
         if(this->core_.hasReceivedData())
            {
            return this->core_.copyReceivedData(buffers);
            }

         auto read_buffer = boost::asio::buffer(
                               this->core_.input_buffer_,
                               nextLayer_.read_some(this->core_.input_buffer_, ec));
         if(ec)
            {
            return 0;
            }

         try
            {
            channel().received_data(static_cast<const uint8_t*>(read_buffer.data()),
                                    read_buffer.size());
            }
         catch(...)
            {
            ec = Botan::convertException();
            return 0;
            }

         return this->core_.copyReceivedData(buffers);
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
            channel().send(static_cast<const uint8_t*>(buffer.data()), buffer.size());
            }
         catch(...)
            {
            ec = Botan::convertException();
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

         try
            {
            channel().send(static_cast<const uint8_t*>(buffer.data()),
                           buffer.size());
            }
         catch(...)
            {
            // TODO: don't call directly
            handler(Botan::convertException(), 0);
            return;
            }

         boost::asio::async_completion<WriteHandler,
               void(boost::system::error_code, std::size_t)>
               init(handler);
         auto op = create_async_write_op(std::move(init.completion_handler),
                                         buffer.size());

         boost::asio::async_write(nextLayer_, this->core_.sendBuffer(),
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
            boost::asio::write(nextLayer_, this->core_.sendBuffer(), ec);

         this->core_.consumeSendBuffer(writtenBytes);
         return writtenBytes;
         }

      template <typename Handler>
      Botan::AsyncHandshakeOperation<Channel, StreamLayer, Handler>
      create_async_handshake_op(Handler&& handler)
         {
         return Botan::AsyncHandshakeOperation<Channel, StreamLayer, Handler>(
                   channel(), this->core_, nextLayer_, std::forward<Handler>(handler));
         }

      template <typename Handler, typename MutableBufferSequence>
      Botan::AsyncReadOperation<Channel, StreamLayer, Handler,
            MutableBufferSequence>
            create_async_read_op(Handler&& handler,
                                 const MutableBufferSequence& buffers)
         {
         return Botan::AsyncReadOperation<Channel, StreamLayer, Handler,
                MutableBufferSequence>(
                   channel(), this->core_, nextLayer_, std::forward<Handler>(handler),
                   buffers);
         }

      template <typename Handler>
      Botan::AsyncWriteOperation<Handler>
      create_async_write_op(Handler&& handler, std::size_t plainBytesTransferred)
         {
         return Botan::AsyncWriteOperation<Handler>(
                   this->core_, std::forward<Handler>(handler), plainBytesTransferred);
         }

      StreamLayer nextLayer_;
   };

} // namespace Botan

#endif
