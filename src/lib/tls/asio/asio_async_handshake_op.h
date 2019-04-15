/*
* TLS Stream Helper
* (C) 2018-2019 Jack Lloyd
*     2018-2019 Hannes Rantzsch, Tim Oesterreich, Rene Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ASIO_ASYNC_HANDSHAKE_OP_H_
#define BOTAN_ASIO_ASYNC_HANDSHAKE_OP_H_

#include <botan/build.h>

#if defined(BOTAN_HAS_TLS) && defined(BOTAN_HAS_BOOST_ASIO)

#include <boost/version.hpp>
#if BOOST_VERSION >= 106600

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
      /**
       * Construct and invoke an AsyncHandshakeOperation.
       *
       * @param handler Handler function to be called upon completion.
       * @param stream The stream from which the data will be read
       * @param core The stream's core; used to extract decrypted data.
       * @param ec Optional error code; used to report an error to the handler function.
       */
      template<class HandlerT>
      AsyncHandshakeOperation(
         HandlerT&& handler,
         Stream& stream,
         StreamCore& core,
         const boost::system::error_code& ec = {})
         : AsyncBase<Handler, typename Stream::executor_type, Allocator>(
              std::forward<HandlerT>(handler),
              stream.get_executor())
         , m_stream(stream)
         , m_core(core)
         {
         this->operator()(ec, std::size_t(0), false);
         }

      AsyncHandshakeOperation(AsyncHandshakeOperation&&) = default;

      void operator()(boost::system::error_code ec, std::size_t bytesTransferred, bool isContinuation = true)
         {
         reenter(this)
            {
            // Provide TLS data from the core to the TLS::Channel
            if(bytesTransferred > 0 && !ec)
               {
               boost::asio::const_buffer read_buffer {m_core.input_buffer.data(), bytesTransferred};
               try
                  {
                  m_stream.native_handle()->received_data(static_cast<const uint8_t*>(read_buffer.data()), read_buffer.size());
                  }
               catch(const std::exception&)
                  {
                  ec = convertException();
                  }
               }

            // Write TLS data that TLS::Channel has provided to the core
            if(m_core.hasDataToSend() && !ec)
               {
               // Note: we construct `AsyncWriteOperation` with 0 as its last parameter (`plainBytesTransferred`).
               // This operation will eventually call `*this` as its own handler, passing the 0 back to this call
               // operator. This is necessary because the check of `bytesTransferred > 0` assumes that
               // `bytesTransferred` bytes were just read and are in the core's input_buffer for further processing.
               AsyncWriteOperation<
               AsyncHandshakeOperation<typename std::decay<Handler>::type, Stream, Allocator>,
                                       Stream,
                                       Allocator>
                                       op{std::move(*this), m_stream, m_core, 0};
               return;
               }

            // Read more data from the socket
            if(!m_stream.native_handle()->is_active() && !ec)
               {
               m_stream.next_layer().async_read_some(m_core.input_buffer, std::move(*this));
               return;
               }

            if(!isContinuation)
               {
               // Make sure the handler is not called without an intermediate initiating function.
               // "Reading" into a zero-byte buffer will complete immediately.
               m_ec = ec;
               yield m_stream.next_layer().async_read_some(boost::asio::mutable_buffer(), std::move(*this));
               ec = m_ec;
               }

            this->complete_now(ec);
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

#endif // BOOST_VERSION
#endif // BOTAN_HAS_TLS && BOTAN_HAS_BOOST_ASIO
#endif // BOTAN_ASIO_ASYNC_HANDSHAKE_OP_H_
