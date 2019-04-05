/*
* TLS Stream Helper
* (C) 2018-2019 Jack Lloyd
*     2018-2019 Hannes Rantzsch, Tim Oesterreich, Rene Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ASIO_ASYNC_READ_OP_H_
#define BOTAN_ASIO_ASYNC_READ_OP_H_

#if defined(BOTAN_HAS_TLS) && defined(BOTAN_HAS_BOOST_ASIO)

#include <boost/version.hpp>
#if BOOST_VERSION > 106600

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
                         const MutableBufferSequence& buffers,
                         const boost::system::error_code& ec = {})
         : AsyncBase<Handler, typename Stream::executor_type, Allocator>(
              std::forward<HandlerT>(handler),
              stream.get_executor())
         , m_stream(stream)
         , m_core(core)
         , m_buffers(buffers)
         , m_decodedBytes(0)
         {
         this->operator()(ec, m_decodedBytes, false);
         }

      AsyncReadOperation(AsyncReadOperation&&) = default;

      void operator()(boost::system::error_code ec, std::size_t bytes_transferred, bool isContinuation = true)
         {
         reenter(this)
            {
            if(bytes_transferred > 0 && !ec)
               {
               // We have transferred encrypted data from the socket, now hand it to the channel.
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

            if(!m_core.hasReceivedData() && !ec && boost::asio::buffer_size(m_buffers) > 0)
               {
               // The channel did not decrypt a complete record yet, we need more data from the socket.
               m_stream.next_layer().async_read_some(m_core.input_buffer, std::move(*this));
               return;
               }

            if(m_core.hasReceivedData() && !ec)
               {
               // The channel has decrypted a TLS record, now copy it to the output buffers.
               m_decodedBytes = m_core.copyReceivedData(m_buffers);
               }

            if(!isContinuation)
               {
               // Make sure the handler is not called without an intermediate initiating function.
               // "Reading" into a zero-byte buffer will "return" immediately.
               m_ec = ec;
               yield m_stream.next_layer().async_read_some(boost::asio::mutable_buffer(), std::move(*this));
               ec = m_ec;
               }

            this->complete_now(ec, m_decodedBytes);
            }
         }

   private:
      Stream&               m_stream;
      StreamCore&           m_core;
      MutableBufferSequence m_buffers;

      size_t                    m_decodedBytes;
      boost::system::error_code m_ec;
   };

}  // namespace TLS

}  // namespace Botan

#include <boost/asio/unyield.hpp>

#endif // BOOST_VERSION
#endif // BOTAN_HAS_TLS && BOTAN_HAS_BOOST_ASIO
#endif // BOTAN_ASIO_ASYNC_READ_OP_H_
