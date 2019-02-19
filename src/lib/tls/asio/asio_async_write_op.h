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
   AsyncWriteOperation(StreamCore& core, Handler&& handler,
                       std::size_t plainBytesTransferred)
      : m_core(core),
        m_handler(std::forward<Handler>(handler)),
        m_plainBytesTransferred(plainBytesTransferred) {}

   AsyncWriteOperation(AsyncWriteOperation&& right)
      : m_core(right.m_core),
        m_handler(std::move(right.m_handler)),
        m_plainBytesTransferred(right.m_plainBytesTransferred) {}

   ~AsyncWriteOperation() = default;
   AsyncWriteOperation(AsyncWriteOperation const&) = delete;

   void operator()(boost::system::error_code ec,
                   std::size_t bytes_transferred = ~std::size_t(0))
      {
      m_core.consumeSendBuffer(bytes_transferred);
      // TODO: make sure returning 0 in error case is correct here--core has already eaten the data
      m_handler(ec, ec ? 0 : m_plainBytesTransferred);
      }

   StreamCore& m_core;
   Handler     m_handler;
   std::size_t m_plainBytesTransferred;
   };

}  // namespace TLS

}  // namespace Botan

#endif
