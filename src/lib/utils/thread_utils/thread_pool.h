/*
* (C) 2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_THREAD_POOL_H_
#define BOTAN_THREAD_POOL_H_

#include <botan/types.h>
#include <botan/work_executor.h>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <type_traits>
#include <utility>

namespace Botan {

/**
* A future which waits for its work to finish when destroyed, so that work
* referencing the enclosing frame cannot outlive it
*/
template <typename T>
class Joining_Future final {
   public:
      explicit Joining_Future(std::future<T> future) : m_future(std::move(future)) {}

      ~Joining_Future() {
         if(m_future.valid()) {
            m_future.wait();
         }
      }

      Joining_Future(const Joining_Future&) = delete;
      Joining_Future& operator=(const Joining_Future&) = delete;

      Joining_Future(Joining_Future&&) noexcept = default;

      Joining_Future& operator=(Joining_Future&& other) noexcept {
         if(this != &other) {
            if(m_future.valid()) {
               m_future.wait();
            }
            m_future = std::move(other.m_future);
         }
         return *this;
      }

      decltype(auto) get() { return m_future.get(); }

      void wait() const { m_future.wait(); }

      bool valid() const noexcept { return m_future.valid(); }

   private:
      std::future<T> m_future;
};

/**
* Thread pool for computationally bound tasks
*
* Callers queue fork-join work which is executed in arbitrary order.
* Do not use this interface for any kind of IO scheduling.
*/
class BOTAN_TEST_API Thread_Pool final {
   public:
      /**
      * Return an instance to a shared thread pool
      */
      static Thread_Pool& global_instance();

      /**
      * Initialize a thread pool with some number of threads
      * @param pool_size number of threads in the pool, if 0
      *        then some default value is chosen. If the optional
      *        is nullopt then the thread pool is disabled; all
      *        work is executed immediately when queued.
      *
      * The threads are not started until work is first queued.
      */
      explicit Thread_Pool(std::optional<size_t> pool_size);

      /**
      * Initialize a thread pool with some number of threads
      * @param pool_size number of threads in the pool, if 0
      *        then some default value is chosen.
      */
      explicit Thread_Pool(size_t pool_size = 0) : Thread_Pool(std::optional<size_t>(pool_size)) {}

      ~Thread_Pool() { shutdown(); }

      void shutdown();

      /**
      * Return the number of threads available to run queued work
      *
      * With an executor installed this is the max_concurrency it reported
      * when it was installed. Otherwise it is the number of threads in the
      * pool, where zero means the pool is disabled and all work runs in the
      * calling thread. Returns zero once the pool has shut down.
      */
      size_t worker_count() const;

      /**
      * Install an executor which runs queued work in place of the pool's threads
      *
      * May be called at most once; the executor then remains in use for the
      * lifetime of the pool. Any threads already started finish their queued
      * work and exit.
      *
      * Throws Invalid_State if an executor is already set, or if called from
      * within work run by this pool.
      */
      void set_executor(std::shared_ptr<Work_Executor> executor);

      Thread_Pool(const Thread_Pool&) = delete;
      Thread_Pool& operator=(const Thread_Pool&) = delete;

      Thread_Pool(Thread_Pool&&) = delete;
      Thread_Pool& operator=(Thread_Pool&&) = delete;

      /*
      * Enqueue some work; the thunk must not throw
      *
      * @warning depending on pool state, the work may be executed directly
      * in the calling thread.
      */
      void queue_thunk(const std::function<void()>& work);

      /**
      * Queue fork-join work which will be executed in arbitrary order
      */
      template <class F, class... Args>
      auto run(F&& f, Args&&... args) -> Joining_Future<std::invoke_result_t<F, Args...>> {
         using return_type = std::invoke_result_t<F, Args...>;

         const auto future_work = std::bind(std::forward<F>(f), std::forward<Args>(args)...);  // NOLINT(*-avoid-bind)
         const auto task = std::make_shared<std::packaged_task<return_type()>>(future_work);
         auto future_result = task->get_future();
         queue_thunk([task]() { (*task)(); });
         // Wrapped only once queued; otherwise unwinding would wait on a task
         // still owned by this frame
         return Joining_Future<return_type>(std::move(future_result));
      }

   private:
      mutable std::mutex m_mutex;
      // The library's own pool until set_executor replaces it; null once shut down
      std::shared_ptr<Work_Executor> m_executor;
      size_t m_worker_count;
      bool m_executor_was_set;
};

}  // namespace Botan

#endif
