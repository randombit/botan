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

namespace Botan {

namespace TLS {

template <typename Handler>
struct AsyncWriteOperation
   {
   template <class HandlerT>
   AsyncWriteOperation(HandlerT&& handler,
                       StreamCore& core,
                       std::size_t plainBytesTransferred)
      : m_handler(std::forward<HandlerT>(handler))
      , m_core(core)
      , m_plainBytesTransferred(plainBytesTransferred) {}

   AsyncWriteOperation(AsyncWriteOperation&&) = default;

   void operator()(boost::system::error_code ec, std::size_t bytes_transferred)
      {
      m_core.consumeSendBuffer(bytes_transferred);
      m_handler(ec, ec ? 0 : m_plainBytesTransferred);
      }

   Handler     m_handler;
   StreamCore& m_core;
   std::size_t m_plainBytesTransferred;
   };

}  // namespace TLS

}  // namespace Botan

#endif
