/*
* TLS Stream Helper
* (C) 2018-2019 Jack Lloyd
*     2018-2019 Hannes Rantzsch, Tim Oesterreich, Rene Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ASIO_ASYNC_WRITE_OP_H_
#define BOTAN_ASIO_ASYNC_WRITE_OP_H_

#include <botan/internal/asio_stream_core.h>
#include <botan/internal/asio_includes.h>
#include <botan/internal/asio_async_base.h>

namespace Botan {

namespace TLS {

template <typename Handler, class Stream, class Allocator = std::allocator<void>>
struct AsyncWriteOperation : public AsyncBase<Handler, typename Stream::executor_type, Allocator>
   {
   template <class HandlerT>
   AsyncWriteOperation(HandlerT&& handler,
                       Stream& stream,
                       StreamCore& core,
                       std::size_t plainBytesTransferred)
      : AsyncBase<Handler, typename Stream::executor_type, Allocator>(
           std::forward<HandlerT>(handler),
           stream.get_executor())
      , m_stream(stream)
      , m_core(core)
      , m_plainBytesTransferred(plainBytesTransferred)
      {
      }

   AsyncWriteOperation(AsyncWriteOperation&&) = default;

   using typename AsyncBase<Handler, typename Stream::executor_type, Allocator>::allocator_type;
   using typename AsyncBase<Handler, typename Stream::executor_type, Allocator>::executor_type;

   void operator()(boost::system::error_code ec, std::size_t bytes_transferred, bool isContinuation = true)
      {
      m_core.consumeSendBuffer(bytes_transferred);
      this->invoke(isContinuation, ec, ec ? 0 : m_plainBytesTransferred);
      }

   Stream&      m_stream;
   StreamCore&  m_core;
   std::size_t m_plainBytesTransferred;
   };

}  // namespace TLS

}  // namespace Botan

#endif
