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

template <class Channel, class StreamLayer, class Handler,
          class MutableBufferSequence>
struct AsyncReadOperation
   {
      AsyncReadOperation(Channel* channel, StreamCore& core, StreamLayer& nextLayer,
                         Handler&& handler, const MutableBufferSequence& buffers)
         : m_channel(channel), m_core(core), m_nextLayer(nextLayer),
           m_handler(std::forward<Handler>(handler)), m_buffers(buffers) {}

      AsyncReadOperation(AsyncReadOperation&& right)
         : m_channel(right.m_channel), m_core(right.m_core),
           m_nextLayer(right.m_nextLayer), m_handler(std::move(right.m_handler)),
           m_buffers(right.m_buffers) {}

      ~AsyncReadOperation() = default;
      AsyncReadOperation(AsyncReadOperation const&) = delete;

      void operator()(boost::system::error_code ec,
                      std::size_t bytes_transferred = ~std::size_t(0))
         {
         std::size_t decodedBytes = 0;

         if(bytes_transferred > 0)
            {
            auto read_buffer =
               boost::asio::buffer(m_core.input_buffer, bytes_transferred);
            try
               {
               m_channel->received_data(static_cast<const uint8_t*>(read_buffer.data()),
                                        read_buffer.size());
               }
            catch(...)
               {
               m_handler(convertException(), 0);
               return;
               }
            }

         if(!m_core.hasReceivedData() && !ec)
            {
            // we need more tls packets from the socket
            m_nextLayer.async_read_some(m_core.input_buffer, std::move(*this));
            return;
            }

         if(m_core.hasReceivedData())
            {
            decodedBytes = m_core.copyReceivedData(m_buffers);
            ec = boost::system::error_code{};
            }

         m_handler(ec, decodedBytes);
         }

   private:
      Channel*              m_channel;
      StreamCore&           m_core;
      StreamLayer&          m_nextLayer;
      Handler               m_handler;
      MutableBufferSequence m_buffers;
   };

}  // namespace TLS

}  // namespace Botan

#endif
