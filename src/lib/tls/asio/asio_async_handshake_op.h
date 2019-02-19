#ifndef BOTAN_ASIO_ASYNC_HANDSHAKE_OP_H_
#define BOTAN_ASIO_ASYNC_HANDSHAKE_OP_H_

#include <botan/internal/asio_async_write_op.h>
#include <botan/internal/asio_convert_exceptions.h>
#include <botan/internal/asio_stream_core.h>
#include <botan/internal/asio_includes.h>

namespace Botan {

namespace TLS {

template <class Channel, class StreamLayer, class Handler>
struct AsyncHandshakeOperation
   {
      AsyncHandshakeOperation(Channel* channel, StreamCore& core,
                              StreamLayer& nextLayer, Handler&& handler)
         : m_channel(channel),
           m_core(core),
           m_nextLayer(nextLayer),
           m_handler(std::forward<Handler>(handler)) {}

      AsyncHandshakeOperation(AsyncHandshakeOperation&& right)
         : m_channel(right.m_channel),
           m_core(right.m_core),
           m_nextLayer(right.m_nextLayer),
           m_handler(std::move(right.m_handler)) {}

      ~AsyncHandshakeOperation() = default;
      AsyncHandshakeOperation(AsyncHandshakeOperation const&) = delete;

      void operator()(boost::system::error_code ec,
                      std::size_t bytesTransferred = 0, int start = 0)
         {
         // process tls packets from socket first
         if(bytesTransferred > 0)
            {
            auto read_buffer =
               boost::asio::buffer(m_core.input_buffer, bytesTransferred);
            try
               {
               m_channel->received_data(
                  static_cast<const uint8_t*>(read_buffer.data()),
                  read_buffer.size());
               }
            catch(...)
               {
               ec = convertException();
               m_handler(ec);
               return;
               }
            }

         // send tls packets
         if(m_core.hasDataToSend())
            {
            AsyncWriteOperation<AsyncHandshakeOperation<Channel, StreamLayer, Handler>>
                  op{m_core, std::move(*this), 0};
            boost::asio::async_write(m_nextLayer, m_core.sendBuffer(),
                                     std::move(op));
            return;
            }

         if(!m_channel->is_active() && !ec)
            {
            // we need more tls data from the socket
            m_nextLayer.async_read_some(m_core.input_buffer, std::move(*this));
            return;
            }

         if(start)
            {
            // don't call the handler directly, similar to io_context.post
            m_nextLayer.async_read_some(
               boost::asio::buffer(m_core.input_buffer, 0), std::move(*this));
            return;
            }
         m_handler(ec);
         }

   private:
      Channel*     m_channel;
      StreamCore&  m_core;
      StreamLayer& m_nextLayer;
      Handler      m_handler;
   };

}  // namespace TLS

}  // namespace Botan

#endif
