/*
* (C) 2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_TARGET_OS_HAS_THREADS) && defined(BOTAN_HAS_THREAD_UTILS)

#include <botan/internal/thread_pool.h>
#include <chrono>

namespace Botan_Tests {

// TODO test Barrier
// TODO test Semaphore

namespace {

Test::Result thread_pool()
   {
   Test::Result result("Thread_Pool");

   // Using lots of threads since here the works spend most of the time sleeping
   Botan::Thread_Pool pool(16);

   auto sleep_or_throw = [](size_t x) -> size_t {
      std::this_thread::sleep_for(std::chrono::milliseconds((x*97)%127));

      if(x % 2 == 0)
         throw x;
      return x;
      };

   std::vector<std::future<size_t>> futures;
   for(size_t i = 0; i != 100; ++i)
      {
      auto fut = pool.run(sleep_or_throw, i);
      futures.push_back(std::move(fut));
      }

   for(size_t i = 0; i != futures.size(); ++i)
      {
      if(i % 2 == 0)
         {
         try
            {
            futures[i].get();
            result.test_failure("Expected future to throw");
            }
         catch(size_t x)
            {
            result.test_eq("Expected thrown value", x, i);
            }
         }
      else
         {
         result.test_eq("Expected return value", futures[i].get(), i);
         }
      }

   pool.shutdown();

   return result;
   }

BOTAN_REGISTER_TEST_FN("utils", "thread_pool", thread_pool);

}

}

#endif
