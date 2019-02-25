/*
* TLS Stream Helper
* (C) 2018-2019 Jack Lloyd
*     2018-2019 Hannes Rantzsch, Tim Oesterreich, Rene Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ASIO_ASYNC_HANDSHAKE_OP_H_
#define BOTAN_ASIO_ASYNC_HANDSHAKE_OP_H_

#include <botan/internal/asio_async_write_op.h>
#include <botan/internal/asio_convert_exceptions.h>
#include <botan/internal/asio_stream_core.h>
#include <botan/internal/asio_includes.h>

namespace Botan {

namespace TLS {

template <class Handler, class StreamLayer, class Channel>
struct AsyncHandshakeOperation
   {
      template<class HandlerT>
      AsyncHandshakeOperation(
         HandlerT&& handler,
         StreamLayer& nextLayer,
         Channel* channel,
         StreamCore& core)
         : m_handler(std::forward<HandlerT>(handler))
         , m_nextLayer(nextLayer)
         , m_channel(channel)
         , m_core(core) {}

      AsyncHandshakeOperation(AsyncHandshakeOperation&&) = default;

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
            catch(const std::exception &)
               {
               ec = convertException();
               m_handler(ec);
               return;
               }
            }

         // send tls packets
         if(m_core.hasDataToSend())
            {
            AsyncWriteOperation<AsyncHandshakeOperation<typename std::decay<Handler>::type, StreamLayer, Channel>>
                  op{std::move(*this), m_core, 0};
            boost::asio::async_write(m_nextLayer, m_core.sendBuffer(), std::move(op));
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
      Handler      m_handler;
      StreamLayer& m_nextLayer;
      Channel*     m_channel;
      StreamCore&  m_core;
   };

}  // namespace TLS

}  // namespace Botan

#endif
