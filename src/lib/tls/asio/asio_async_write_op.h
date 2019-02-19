#ifndef BOTAN_ASIO_ASYNC_WRITE_OP_H_
#define BOTAN_ASIO_ASYNC_WRITE_OP_H_

#include <botan/internal/asio_stream_core.h>
#include <botan/internal/asio_includes.h>

namespace Botan {

template <typename Handler>
struct AsyncWriteOperation
   {
   AsyncWriteOperation(StreamCore& core, Handler&& handler,
                       std::size_t plainBytesTransferred)
      : core_(core),
        handler_(std::forward<Handler>(handler)),
        plainBytesTransferred_(plainBytesTransferred) {}

   AsyncWriteOperation(AsyncWriteOperation&& right)
      : core_(right.core_),
        handler_(std::move(right.handler_)),
        plainBytesTransferred_(right.plainBytesTransferred_) {}

   ~AsyncWriteOperation() = default;
   AsyncWriteOperation(AsyncWriteOperation const&) = delete;

   void operator()(boost::system::error_code ec,
                   std::size_t bytes_transferred = ~std::size_t(0))
      {
      core_.consumeSendBuffer(bytes_transferred);
      // TODO: make sure returning 0 in error case is correct here--core has already eaten the data
      handler_(ec, ec ? 0 : plainBytesTransferred_);
      }

   StreamCore& core_;
   Handler handler_;
   std::size_t plainBytesTransferred_;
   };
}  // namespace Botan

#endif
