/*
* TLS Stream Helper
* (C) 2018-2019 Jack Lloyd
*     2018-2019 Hannes Rantzsch, Tim Oesterreich, Rene Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ASIO_ASYNC_READ_OP_H_
#define BOTAN_ASIO_ASYNC_READ_OP_H_

#include <botan/internal/asio_async_base.h>
#include <botan/internal/asio_convert_exceptions.h>
#include <botan/internal/asio_includes.h>
#include <botan/internal/asio_stream_core.h>

#include <boost/asio/yield.hpp>

namespace Botan {

namespace TLS {

template <class Handler, class Stream, class MutableBufferSequence, class Allocator = std::allocator<void>>
struct AsyncReadOperation : public AsyncBase<Handler, typename Stream::executor_type, Allocator>
   {
      template <class HandlerT>
      AsyncReadOperation(HandlerT&& handler,
                         Stream& stream,
                         StreamCore& core,
                         const MutableBufferSequence& buffers)
         : AsyncBase<Handler, typename Stream::executor_type, Allocator>(
              std::forward<HandlerT>(handler),
              stream.get_executor())
         , m_stream(stream)
         , m_core(core)
         , m_buffers(buffers)
         , m_decodedBytes(0)
         {
         }

      AsyncReadOperation(AsyncReadOperation&&) = default;

      using typename AsyncBase<Handler, typename Stream::executor_type, Allocator>::allocator_type;
      using typename AsyncBase<Handler, typename Stream::executor_type, Allocator>::executor_type;

      void operator()(boost::system::error_code ec, std::size_t bytes_transferred, bool isContinuation = true)
         {
         reenter(this)
            {
            if(bytes_transferred > 0 && !ec)
               {
               boost::asio::const_buffer read_buffer{m_core.input_buffer.data(), bytes_transferred};
               try
                  {
                  m_stream.native_handle()->received_data(static_cast<const uint8_t*>(read_buffer.data()),
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
               m_stream.next_layer().async_read_some(m_core.input_buffer, std::move(*this));
               return;
               }

            if(m_core.hasReceivedData() && !ec)
               {
               m_decodedBytes = m_core.copyReceivedData(m_buffers);
               ec = {};
               }

            if(!isContinuation)
               {
               m_ec_store = ec;
               yield m_stream.next_layer().async_read_some(boost::asio::mutable_buffer(), std::move(*this));
               ec = m_ec_store;
               }

            this->invoke_now(ec, m_decodedBytes);
            }
         }

   private:
      Stream&               m_stream;
      StreamCore&           m_core;
      MutableBufferSequence m_buffers;

      boost::system::error_code m_ec_store;
      size_t                    m_decodedBytes;
   };

}  // namespace TLS

}  // namespace Botan

#include <boost/asio/unyield.hpp>

#endif
