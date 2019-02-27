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
#include <botan/internal/asio_includes.h>
#include <botan/internal/asio_stream_core.h>

#include <boost/asio/yield.hpp>

namespace Botan {

namespace TLS {

template <class Handler, class Stream, class Allocator = std::allocator<void>>
struct AsyncHandshakeOperation : public AsyncBase<Handler, typename Stream::executor_type, Allocator>
   {
      template<class HandlerT>
      AsyncHandshakeOperation(
         HandlerT&& handler,
         Stream& stream,
         StreamCore& core)
         : AsyncBase<Handler, typename Stream::executor_type, Allocator>(
              std::forward<HandlerT>(handler),
              stream.get_executor())
         , m_stream(stream)
         , m_core(core)
         {
         }

      AsyncHandshakeOperation(AsyncHandshakeOperation&&) = default;

      using typename AsyncBase<Handler, typename Stream::executor_type, Allocator>::allocator_type;
      using typename AsyncBase<Handler, typename Stream::executor_type, Allocator>::executor_type;

      void operator()(boost::system::error_code ec, std::size_t bytesTransferred, bool isContinuation = true)
         {
         m_ec = ec;
         reenter(this)
            {
            // process tls packets from socket first

            if(bytesTransferred > 0)
               {
               boost::asio::const_buffer read_buffer {m_core.input_buffer.data(), bytesTransferred};
               try
                  {
                  m_stream.native_handle()->received_data(static_cast<const uint8_t*>(read_buffer.data()), read_buffer.size());
                  }
               catch(const std::exception&)
                  {
                  m_ec = convertException();
                  }
               }

            // send tls packets
            if(m_core.hasDataToSend() && !m_ec)
               {
               // \note: we construct `AsyncWriteOperation` with 0 as its last parameter (`plainBytesTransferred`).
               //        This operation will eventually call `*this` as its own handler, passing the 0 back to this call
               //        operator. This is necessary because, the check of `bytesTransferred > 0` assumes that
               //        `bytesTransferred` bytes were just read and are in the cores input_buffer for further processing.
               AsyncWriteOperation<
               AsyncHandshakeOperation<typename std::decay<Handler>::type, Stream, Allocator>,
                                       Stream,
                                       Allocator>
                                       op{std::move(*this), m_stream, m_core, 0};
               boost::asio::async_write(m_stream.next_layer(), m_core.sendBuffer(), std::move(op));
               return;
               }

            // we need more tls data from the socket
            if(!m_stream.native_handle()->is_active() && !m_ec)
               {
               m_stream.next_layer().async_read_some(m_core.input_buffer, std::move(*this));
               return;
               }

            if(!isContinuation)
               {
               // this 0 byte read completes immediately. `yield` causes the coroutine to reenter the function after
               // this read, enabling us to call the handler, while respecting asios guarantee that the handler will not
               // be called without an intermediate initiating function
               yield m_stream.next_layer().async_read_some(boost::asio::mutable_buffer(), std::move(*this));
               }

            this->invoke_now(m_ec);
            }
         }

   private:
      Stream&     m_stream;
      StreamCore& m_core;

      boost::system::error_code m_ec;
   };

}  // namespace TLS

}  // namespace Botan

#include <boost/asio/unyield.hpp>

#endif
