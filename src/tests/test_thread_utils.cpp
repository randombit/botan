/*
* (C) 2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_TARGET_OS_HAS_THREADS) && defined(BOTAN_HAS_THREAD_UTILS)

   #include <botan/exceptn.h>
   #include <botan/work_executor.h>
   #include <botan/internal/thread_pool.h>
   #include <algorithm>
   #include <atomic>
   #include <chrono>
   #include <condition_variable>
   #include <deque>
   #include <mutex>
   #include <thread>
   #include <vector>

namespace Botan_Tests {

// TODO test Barrier
// TODO test Semaphore

namespace {

// Runs queued work on its own threads
class Test_Executor final : public Botan::Work_Executor {
   public:
      explicit Test_Executor(size_t threads) {
         for(size_t i = 0; i != threads; ++i) {
            m_threads.emplace_back([this]() { this->run(); });
         }
      }

      ~Test_Executor() override {
         {
            const std::scoped_lock lock(m_mutex);
            m_stop = true;
         }
         m_cv.notify_all();
         for(auto& thread : m_threads) {
            thread.join();
         }
      }

      Test_Executor(const Test_Executor&) = delete;
      Test_Executor& operator=(const Test_Executor&) = delete;
      Test_Executor(Test_Executor&&) = delete;
      Test_Executor& operator=(Test_Executor&&) = delete;

      void queue_work(std::function<void()> work) override {
         // Work queued from one of the executor's own threads runs directly,
         // since that thread would otherwise block waiting on itself
         if(owns_thread(std::this_thread::get_id())) {
            work();
            return;
         }

         {
            const std::scoped_lock lock(m_mutex);
            m_queue.push_back(std::move(work));
         }
         m_cv.notify_one();
      }

      size_t max_concurrency() const override { return m_threads.size(); }

      bool owns_thread(std::thread::id id) const {
         return std::any_of(
            m_threads.begin(), m_threads.end(), [id](const std::thread& t) { return t.get_id() == id; });
      }

      size_t work_run() const {
         const std::scoped_lock lock(m_mutex);
         return m_work_run;
      }

   private:
      void run() {
         for(;;) {
            std::function<void()> work;

            {
               std::unique_lock<std::mutex> lock(m_mutex);
               m_cv.wait(lock, [this] { return m_stop || !m_queue.empty(); });

               if(m_queue.empty()) {
                  return;
               }

               work = std::move(m_queue.front());
               m_queue.pop_front();
               m_work_run += 1;
            }

            work();
         }
      }

      mutable std::mutex m_mutex;
      std::condition_variable m_cv;
      std::deque<std::function<void()>> m_queue;
      bool m_stop = false;
      size_t m_work_run = 0;
      // Declared last since the threads start in the constructor
      std::vector<std::thread> m_threads;
};

// Runs all queued work in the calling thread
class Inline_Executor final : public Botan::Work_Executor {
   public:
      void queue_work(std::function<void()> work) override { work(); }

      size_t max_concurrency() const override { return 1; }
};

// Refuses all work by throwing
class Refusing_Executor final : public Botan::Work_Executor {
   public:
      void queue_work(std::function<void()> /*work*/) override { throw Botan::Invalid_State("refused"); }

      size_t max_concurrency() const override { return 4; }
};

std::thread::id whoami() {
   return std::this_thread::get_id();
}

Test::Result thread_pool() {
   Test::Result result("Thread_Pool");

   // Using lots of threads since here the works spend most of the time sleeping
   Botan::Thread_Pool pool(16);

   const auto sleep_or_throw = [](size_t x) -> size_t {
      std::this_thread::sleep_for(std::chrono::milliseconds((x * 97) % 127));

      if(x % 2 == 0) {
         throw x;  // NOLINT(*-exception-baseclass)
      }
      return x;
   };

   std::vector<Botan::Joining_Future<size_t>> futures;
   for(size_t i = 0; i != 100; ++i) {
      auto fut = pool.run(sleep_or_throw, i);
      futures.push_back(std::move(fut));
   }

   for(size_t i = 0; i != futures.size(); ++i) {
      if(i % 2 == 0) {
         try {
            futures[i].get();
            result.test_failure("Expected future to throw");
         } catch(size_t x) {
            result.test_sz_eq("Expected thrown value", x, i);
         }
      } else {
         result.test_sz_eq("Expected return value", futures[i].get(), i);
      }
   }

   pool.shutdown();

   return result;
}

Test::Result thread_pool_nested() {
   Test::Result result("Thread_Pool nested");

   // A small pool, so that without the immediate execution of tasks
   // queued by the pool's own workers, all workers would block in the
   // inner get() with the inner tasks stuck behind them in the queue
   Botan::Thread_Pool pool(2);

   const auto fan_out = [&pool](size_t i) -> size_t {
      std::vector<Botan::Joining_Future<size_t>> inner;
      inner.reserve(4);
      for(size_t j = 0; j != 4; ++j) {
         inner.push_back(pool.run([i, j]() -> size_t { return i * 4 + j; }));
      }

      size_t sum = 0;
      for(auto& fut : inner) {
         sum += fut.get();
      }
      return sum;
   };

   std::vector<Botan::Joining_Future<size_t>> outer;
   for(size_t i = 0; i != 16; ++i) {
      outer.push_back(pool.run(fan_out, i));
   }

   for(size_t i = 0; i != outer.size(); ++i) {
      result.test_sz_eq("Expected nested sum", outer[i].get(), 16 * i + 6);
   }

   pool.shutdown();

   return result;
}

Test::Result thread_pool_executor() {
   Test::Result result("Thread_Pool executor");

   auto executor = std::make_shared<Test_Executor>(1);
   const auto my_tid = whoami();

   Botan::Thread_Pool pool(2);

   {
      const auto tid = pool.run(whoami).get();
      result.test_is_true("Without an executor work runs on a pool thread",
                          tid != my_tid && !executor->owns_thread(tid));
      result.test_sz_eq("Worker count is the pool size", pool.worker_count(), 2);
   }

   result.test_throws("Null executor is rejected", [&]() { pool.set_executor(nullptr); });

   // Installing the executor stops the pool's own threads
   pool.set_executor(executor);
   result.test_sz_eq("Worker count reflects executor", pool.worker_count(), executor->max_concurrency());

   {
      std::vector<Botan::Joining_Future<std::thread::id>> futures;
      for(size_t i = 0; i != 8; ++i) {
         futures.push_back(pool.run(whoami));
      }

      for(auto& fut : futures) {
         result.test_is_true("Work runs on the executor thread", executor->owns_thread(fut.get()));
      }

      result.test_sz_eq("Executor ran the work", executor->work_run(), 8);
   }

   // Work queued from within work the executor is running must run inline:
   // with a single executor thread, queuing it would deadlock since the outer
   // work blocks that thread
   {
      auto nested = [&pool]() { return pool.run(whoami).get(); };
      result.test_is_true("Nested work runs inline on the executor thread",
                          executor->owns_thread(pool.run(nested).get()));
      result.test_sz_eq("Nested work did not go through the executor", executor->work_run(), 9);
   }

   {
      auto fut = pool.run([]() -> size_t { throw Botan::Invalid_Argument("expected"); });
      result.test_throws("Exceptions propagate via the future", [&]() { fut.get(); });
   }

   {
      auto fut = pool.run([&pool]() { pool.set_executor(std::make_shared<Inline_Executor>()); });
      result.test_throws("Cannot set executor from within pool work", [&]() { fut.get(); });
   }

   result.test_throws("Executor can only be set once",
                      [&]() { pool.set_executor(std::make_shared<Inline_Executor>()); });
   result.test_is_true("Original executor remains in use", executor->owns_thread(pool.run(whoami).get()));

   pool.shutdown();

   return result;
}

Test::Result thread_pool_inline_executor() {
   Test::Result result("Thread_Pool inline executor");

   Botan::Thread_Pool pool(2);
   pool.set_executor(std::make_shared<Inline_Executor>());

   result.test_sz_eq("Worker count reflects executor", pool.worker_count(), 1);

   const auto my_tid = whoami();
   result.test_is_true("Work runs in the calling thread", pool.run(whoami).get() == my_tid);

   auto nested = [&pool]() { return pool.run(whoami).get(); };
   result.test_is_true("Nested work runs in the calling thread", pool.run(nested).get() == my_tid);

   pool.shutdown();

   return result;
}

Test::Result thread_pool_refusing_executor() {
   Test::Result result("Thread_Pool refusing executor");

   Botan::Thread_Pool pool(2);
   pool.set_executor(std::make_shared<Refusing_Executor>());

   // Work the executor refuses runs in the calling thread instead
   const auto my_tid = whoami();
   result.test_is_true("Refused work runs in the calling thread", pool.run(whoami).get() == my_tid);
   result.test_sz_eq("Refused work still produces its result", pool.run([]() { return size_t(42); }).get(), 42);

   pool.shutdown();

   return result;
}

Test::Result thread_pool_future_joins() {
   Test::Result result("Thread_Pool future waits on destruction");

   Botan::Thread_Pool pool(2);

   std::atomic<bool> finished = false;
   {
      auto fut = pool.run([&finished]() {
         std::this_thread::sleep_for(std::chrono::milliseconds(50));
         finished = true;
      });
      // Discarded without get()
   }
   result.test_is_true("Work finished before its future was destroyed", finished.load());

   pool.shutdown();

   return result;
}

BOTAN_REGISTER_TEST_FN("utils", "thread_pool", thread_pool);
BOTAN_REGISTER_TEST_FN("utils", "thread_pool_nested", thread_pool_nested);
BOTAN_REGISTER_TEST_FN("utils", "thread_pool_executor", thread_pool_executor);
BOTAN_REGISTER_TEST_FN("utils", "thread_pool_inline_executor", thread_pool_inline_executor);
BOTAN_REGISTER_TEST_FN("utils", "thread_pool_refusing_executor", thread_pool_refusing_executor);
BOTAN_REGISTER_TEST_FN("utils", "thread_pool_future_joins", thread_pool_future_joins);

}  // namespace

}  // namespace Botan_Tests

#endif
