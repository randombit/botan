/*
* TLS ASIO Stream Helper
* (C) 2018-2019 Jack Lloyd
*     2018-2019 Hannes Rantzsch, Tim Oesterreich, Rene Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ASIO_ASYNC_BASE_H_
#define BOTAN_ASIO_ASYNC_BASE_H_

#include <botan/build.h>

#include <boost/version.hpp>
#if BOOST_VERSION >= 106600

#include <botan/internal/asio_includes.h>

namespace Botan {

namespace TLS {

/**
 * Base class for asynchronous stream operations.
 *
 * Asynchronous operations, used for example to implement an interface for boost::asio::async_read_some and
 * boost::asio::async_write_some, are based on boost::asio::coroutines.
 * Derived operations should implement a call operator and invoke it with the correct parameters upon construction. The
 * call operator needs to make sure that the user-provided handler is not called directly. Typically, yield / reenter is
 * used for this in the following fashion:
 *
 * ```
 * void operator()(boost::system::error_code ec, std::size_t bytes_transferred, bool isContinuation = true)
 *    {
 *    reenter(this)
 *       {
 *       // operation specific logic, repeatedly interacting with the stream_core and the next_layer (socket)
 *
 *       // make sure intermediate initiating function is called
 *       if(!isContinuation)
 *          {
 *          yield next_layer.async_operation(empty_buffer, this);
 *          }
 *
 *       // call the completion handler
 *       complete_now(error_code, bytes_transferred);
 *       }
 *    }
 * ```
 *
 * Once the operation is completed and ready to call the completion handler it checks if an intermediate initiating
 * function has been called using the `isContinuation` parameter. If not, it will call an asynchronous operation, such
 * as `async_read_some`, with and empty buffer, set the object itself as the handler, and `yield`. As a result, the call
 * operator will be invoked again, this time as a continuation, and will jump to the location where it yielded before
 * using `reenter`. It is now safe to call the handler function via `complete_now`.
 *
 * \tparam Handler Type of the completion handler
 * \tparam Executor1 Type of the asio executor (usually derived from the lower layer)
 * \tparam Allocator Type of the allocator to be used
 */
template <class Handler, class Executor1, class Allocator>
struct AsyncBase : boost::asio::coroutine
   {
      using allocator_type = boost::asio::associated_allocator_t<Handler, Allocator>;
      using executor_type = boost::asio::associated_executor_t<Handler, Executor1>;

      allocator_type get_allocator() const noexcept
         {
         return boost::asio::get_associated_allocator(m_handler);
         }

      executor_type get_executor() const noexcept
         {
         return boost::asio::get_associated_executor(m_handler, m_work_guard_1.get_executor());
         }

   protected:
      template <class HandlerT>
      AsyncBase(HandlerT&& handler, const Executor1& executor)
         : m_handler(std::forward<HandlerT>(handler))
         , m_work_guard_1(executor)
         {
         }

      /**
       * Call the completion handler.
       *
       * This function should only be called after an intermediate initiating function has been called.
       *
       * @param args Arguments forwarded to the completion handler function.
       */
      template<class... Args>
      void complete_now(Args&& ... args)
         {
         m_work_guard_1.reset();
         m_handler(std::forward<Args>(args)...);
         }

      Handler m_handler;
      boost::asio::executor_work_guard<Executor1> m_work_guard_1;
   };

}  // namespace TLS

}  // namespace Botan

#endif // BOOST_VERSION
#endif // BOTAN_ASIO_ASYNC_BASE_H_
