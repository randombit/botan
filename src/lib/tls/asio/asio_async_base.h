/*
* TLS ASIO Stream Helper
* (C) 2018-2019 Jack Lloyd
*     2018-2019 Hannes Rantzsch, Tim Oesterreich, Rene Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ASIO_ASYNC_BASE_H_
#define BOTAN_ASIO_ASYNC_BASE_H_

#include <boost/beast/core/bind_handler.hpp>

#include <botan/internal/asio_includes.h>

namespace Botan {

namespace TLS {

template <class Handler, class Executor1, class Allocator>
struct AsyncBase
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

      template<class... Args>
      void invoke(bool isContinuation, Args&& ... args)
         {
         if(!isContinuation)
            {
            // \note(toesterreich): Is this ok to do with bind_handler? Do we need placeholders?
            boost::asio::post(boost::asio::bind_executor(
                                 m_work_guard_1.get_executor(), boost::beast::bind_handler(std::move(m_handler), args...))
                             );

            m_work_guard_1.reset();
            }
         else
            {
            m_handler(std::forward<Args>(args)...);
            m_work_guard_1.reset();
            }
         }

      Handler m_handler;
      boost::asio::executor_work_guard<Executor1> m_work_guard_1;
   };
}
}

#endif
