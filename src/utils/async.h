/**
* Standin for C++0x's std::async
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ASYNC_H__
#define BOTAN_ASYNC_H__

#include <future>
#include <thread>

namespace Botan {

/**
* A simple version of std::async (as it is not in GCC 4.5)
* Will be removed once GCC supports it natively
*/
template<typename F>
auto std_async(F f) -> std::future<decltype(f())>
   {
   typedef decltype(f()) result_type;
   std::packaged_task<result_type ()> task(std::move(f));
   std::future<result_type> future = task.get_future();
   std::thread thread(std::move(task));
   thread.detach();
   return future;
   }

}

#endif
