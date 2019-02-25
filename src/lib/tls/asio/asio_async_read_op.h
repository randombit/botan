/*
* TLS Stream Helper
* (C) 2018-2019 Jack Lloyd
*     2018-2019 Hannes Rantzsch, Tim Oesterreich, Rene Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ASIO_ASYNC_READ_OP_H_
#define BOTAN_ASIO_ASYNC_READ_OP_H_

#include <botan/internal/asio_convert_exceptions.h>
#include <botan/internal/asio_includes.h>
#include <botan/internal/asio_stream_core.h>

namespace Botan {

namespace TLS {

template <class Handler, class StreamLayer, class Channel, class MutableBufferSequence>
struct AsyncReadOperation
   {
      template <class HandlerT>
      AsyncReadOperation(HandlerT&& handler,
                         StreamLayer& nextLayer,
                         Channel* channel,
                         StreamCore& core,
                         const MutableBufferSequence& buffers)
         : m_handler(std::forward<HandlerT>(handler))
         , m_nextLayer(nextLayer)
         , m_channel(channel)
         , m_core(core)
         , m_buffers(buffers) {}

      AsyncReadOperation(AsyncReadOperation&&) = default;

      void operator()(boost::system::error_code ec, std::size_t bytes_transferred)
         {
         std::size_t decodedBytes = 0;

         if(bytes_transferred > 0 && !ec)
            {
            boost::asio::const_buffer read_buffer {m_core.input_buffer.data(), bytes_transferred};
            try
               {
               m_channel->received_data(static_cast<const uint8_t*>(read_buffer.data()),
                                        read_buffer.size());
               }
            catch(const std::exception&)
               {
               ec = convertException();
               }
            }

         if(!m_core.hasReceivedData() && !ec)
            {
            // we need more tls packets from the socket
            m_nextLayer.async_read_some(m_core.input_buffer, std::move(*this));
            return;
            }

         if(m_core.hasReceivedData() && !ec)
            {
            decodedBytes = m_core.copyReceivedData(m_buffers);
            ec = boost::system::error_code{};
            }

         m_handler(ec, decodedBytes);
         }

   private:
      Handler               m_handler;
      StreamLayer&          m_nextLayer;
      Channel*              m_channel;
      StreamCore&           m_core;
      MutableBufferSequence m_buffers;
   };

}  // namespace TLS

}  // namespace Botan

#endif
