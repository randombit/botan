#ifndef BOTAN_ASIO_ASYNC_READ_OP_H_
#define BOTAN_ASIO_ASYNC_READ_OP_H_

#include <botan/internal/asio_convert_exceptions.h>
#include <botan/internal/asio_includes.h>
#include <botan/internal/asio_stream_core.h>

namespace Botan {

namespace TLS {

template <class Channel, class StreamLayer, class Handler,
          class MutableBufferSequence>
struct AsyncReadOperation
   {
      AsyncReadOperation(Channel* channel, StreamCore& core, StreamLayer& nextLayer,
                         Handler&& handler, const MutableBufferSequence& buffers)
         : channel_(channel), core_(core), nextLayer_(nextLayer),
           handler_(std::forward<Handler>(handler)), buffers_(buffers) {}

      AsyncReadOperation(AsyncReadOperation&& right)
         : channel_(right.channel_), core_(right.core_),
           nextLayer_(right.nextLayer_), handler_(std::move(right.handler_)),
           buffers_(right.buffers_) {}

      ~AsyncReadOperation() = default;
      AsyncReadOperation(AsyncReadOperation const&) = delete;

      void operator()(boost::system::error_code ec,
                      std::size_t bytes_transferred = ~std::size_t(0))
         {
         std::size_t decodedBytes = 0;

         if(bytes_transferred > 0)
            {
            auto read_buffer =
               boost::asio::buffer(core_.input_buffer_, bytes_transferred);
            try
               {
               channel_->received_data(static_cast<const uint8_t*>(read_buffer.data()),
                                       read_buffer.size());
               }
            catch(...)
               {
               // TODO: don't call handler directly
               handler_(convertException(), 0);
               return;
               }
            }

         if(!core_.hasReceivedData() && !ec)
            {
            // we need more tls packets from the socket
            nextLayer_.async_read_some(core_.input_buffer_, std::move(*this));
            return;
            }

         if(core_.hasReceivedData())
            {
            decodedBytes = core_.copyReceivedData(buffers_);
            ec = boost::system::error_code{};
            }

         handler_(ec, decodedBytes);
         }

   private:
      Channel* channel_;
      StreamCore& core_;
      StreamLayer& nextLayer_;
      Handler handler_;
      MutableBufferSequence buffers_;
   };

}  // namespace TLS

}  // namespace Botan

#endif
