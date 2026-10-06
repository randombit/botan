/*
* (C) 2019,2021,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/thread_pool.h>

#include <botan/assert.h>
#include <botan/exceptn.h>
#include <botan/internal/os_utils.h>
#include <botan/internal/parsing.h>
#include <botan/internal/target_info.h>
#include <algorithm>
#include <condition_variable>
#include <deque>
#include <thread>
#include <vector>

namespace Botan {

namespace {

/**
* The library's own thread pool, which runs the work unless the application
* provides an executor
*/
class Internal_Thread_Pool final : public Work_Executor {
   public:
      /// Nullopt disables the pool; all work then runs in the calling thread
      explicit Internal_Thread_Pool(std::optional<size_t> pool_size) :
            m_pool_size(resolve_pool_size(pool_size)), m_shutdown(false) {}

      /// The workers drain the queue and exit
      ~Internal_Thread_Pool() override {
         {
            const std::scoped_lock lock(m_mutex);
            m_shutdown = true;
         }
         m_more_tasks.notify_all();

         for(auto& worker : m_workers) {
            worker.join();
         }
      }

      Internal_Thread_Pool(const Internal_Thread_Pool&) = delete;
      Internal_Thread_Pool& operator=(const Internal_Thread_Pool&) = delete;
      Internal_Thread_Pool(Internal_Thread_Pool&&) = delete;
      Internal_Thread_Pool& operator=(Internal_Thread_Pool&&) = delete;

      void queue_work(std::function<void()> work) override;

      size_t max_concurrency() const override { return m_pool_size; }

   private:
      static size_t resolve_pool_size(std::optional<size_t> pool_size);

      void start_workers();
      void worker_thread();
      std::function<void()> next_task();

      const size_t m_pool_size;

      std::mutex m_mutex;
      std::condition_variable m_more_tasks;
      std::deque<std::function<void()>> m_tasks;
      std::vector<std::thread> m_workers;
      bool m_shutdown;
};

//static
size_t Internal_Thread_Pool::resolve_pool_size(std::optional<size_t> pool_size) {
   if(!pool_size.has_value()) {
      return 0;  // disabled
   } else if(pool_size.value() == 0) {
      // For large machines don't create too many threads, unless explicitly asked
      return std::clamp<size_t>(OS::get_cpu_available(), 2, 16);
   } else {
      return pool_size.value();
   }
}

void Internal_Thread_Pool::queue_work(std::function<void()> work) {
   // Work queued by a worker of this pool never arrives here, since the
   // Thread_Pool runs it directly

   if(m_pool_size == 0) {
      return work();
   }

   const std::scoped_lock lock(m_mutex);

   if(m_workers.empty()) {
      start_workers();
   }

   m_tasks.push_back(std::move(work));
   m_more_tasks.notify_one();
}

// Requires that m_mutex is held
void Internal_Thread_Pool::start_workers() {
   // On Linux, it is 16 length max, including terminator
   const std::string tname = "Botan thread";

   m_workers.reserve(m_pool_size);

   // Added one at a time so that if creating a thread fails, every thread in
   // m_workers is joinable and the ones already started still serve the queue
   for(size_t i = 0; i != m_pool_size; ++i) {
      m_workers.emplace_back(&Internal_Thread_Pool::worker_thread, this);
      OS::set_thread_name(m_workers.back(), tname);
   }
}

void Internal_Thread_Pool::worker_thread() {
   while(const auto task = next_task()) {
      task();
   }
}

std::function<void()> Internal_Thread_Pool::next_task() {
   std::unique_lock<std::mutex> lock(m_mutex);
   m_more_tasks.wait(lock, [this] { return m_shutdown || !m_tasks.empty(); });

   // Empty, which ends the worker, only once the queue is drained
   if(m_tasks.empty()) {
      return nullptr;
   }

   auto task = std::move(m_tasks.front());
   m_tasks.pop_front();
   return task;
}

class Running_Pool_Work;

/// The innermost pool work this thread is running, if any
thread_local const Running_Pool_Work* g_innermost_pool_work = nullptr;  // NOLINT(*-avoid-non-const-global-variables)

/**
* Marks the current thread as running work on behalf of a pool
*
* Work of one pool can run inline within work of another (a disabled pool, an
* inline executor), so the markers form a chain and a pool is found at any depth
*/
class Running_Pool_Work final {
   public:
      explicit Running_Pool_Work(const Thread_Pool* pool) : m_pool(pool), m_outer(g_innermost_pool_work) {
         g_innermost_pool_work = this;
      }

      ~Running_Pool_Work() { g_innermost_pool_work = m_outer; }

      Running_Pool_Work(const Running_Pool_Work&) = delete;
      Running_Pool_Work& operator=(const Running_Pool_Work&) = delete;
      Running_Pool_Work(Running_Pool_Work&&) = delete;
      Running_Pool_Work& operator=(Running_Pool_Work&&) = delete;

      /// True if the current thread is running work of this pool, at any nesting depth
      static bool active_for(const Thread_Pool* pool) {
         for(const auto* work = g_innermost_pool_work; work != nullptr; work = work->m_outer) {
            if(work->m_pool == pool) {
               return true;
            }
         }
         return false;
      }

   private:
      const Thread_Pool* m_pool;
      const Running_Pool_Work* m_outer;
};

std::optional<size_t> global_thread_pool_size() {
   std::string var;
   if(OS::read_env_variable(var, "BOTAN_THREAD_POOL_SIZE")) {
      if(var == "none") {
         return std::nullopt;
      }

      // Try to convert to an integer if possible:
      if(const auto sz = parse_sz(var)) {
         return sz;
      }

      // If it was neither a number nor a special value, then ignore the env
   }

   /*
   * On a few platforms, disable the thread pool by default; it is only
   * used if a size is set explicitly in the environment.
   */

#if defined(BOTAN_TARGET_OS_IS_MINGW)
   // MinGW seems to have bugs causing deadlock on application exit.
   // See https://github.com/randombit/botan/issues/2582 for background.
   return std::nullopt;
#elif defined(BOTAN_TARGET_OS_IS_EMSCRIPTEN)
   // Emscripten's threads are reportedly problematic
   // See https://github.com/randombit/botan/issues/4195
   return std::nullopt;
#else
   // Some(0) means choose based on CPU count
   return std::optional<size_t>(0);
#endif
}

}  // namespace

//static
Thread_Pool& Thread_Pool::global_instance() {
   static Thread_Pool g_thread_pool(global_thread_pool_size());
   return g_thread_pool;
}

//static
void Work_Executor::set_global(std::shared_ptr<Work_Executor> executor) {
   Thread_Pool::global_instance().set_executor(std::move(executor));
}

Thread_Pool::Thread_Pool(std::optional<size_t> opt_pool_size) :
      m_executor(std::make_shared<Internal_Thread_Pool>(opt_pool_size)),
      m_worker_count(m_executor->max_concurrency()),
      m_executor_was_set(false) {}

size_t Thread_Pool::worker_count() const {
   const std::scoped_lock lock(m_mutex);
   return m_worker_count;
}

void Thread_Pool::set_executor(std::shared_ptr<Work_Executor> executor) {
   BOTAN_ARG_CHECK(executor != nullptr, "Thread_Pool::set_executor executor must not be null");

   // Would join the thread this is running on
   if(Running_Pool_Work::active_for(this)) {
      throw Invalid_State("Cannot set the executor from within work run by the thread pool");
   }

   // Queried outside the lock, since the executor may itself use the library
   const size_t concurrency = executor->max_concurrency();

   // Releasing the internal pool drains its queue and joins its threads, so
   // it is held until after the lock is dropped
   const auto internal_pool = [&]() {
      const std::scoped_lock lock(m_mutex);

      if(m_executor_was_set) {
         throw Invalid_State("Thread pool executor has already been set");
      }

      if(!m_executor) {
         throw Invalid_State("Cannot set the executor after the thread pool has shut down");
      }

      m_executor_was_set = true;
      m_worker_count = concurrency;
      return std::exchange(m_executor, std::move(executor));
   }();
}

void Thread_Pool::shutdown() {
   // Releasing the internal pool drains its queue and joins its threads, so
   // it is held until after the lock is dropped
   const auto executor = [this]() {
      const std::scoped_lock lock(m_mutex);
      m_worker_count = 0;
      return std::exchange(m_executor, nullptr);
   }();
}

void Thread_Pool::queue_thunk(const std::function<void()>& work) {
   /*
   * Immediately execute tasks which are queued from within work this pool is
   * already running. Otherwise there is risk of deadlock.
   *
   * This holds even during shutdown: the nested task is part of work that is
   * already running, and rejecting it would only cause that work to fail.
   *
   * This could be improved, with a bit more complexity, by a "helping join";
   * instead of just blocking, the thread runs any queued tasks until the one it
   * is waiting on has completed.
   */
   if(Running_Pool_Work::active_for(this)) {
      return work();
   }

   // The copy keeps the executor alive until the work has been handed over
   const auto executor = [this]() {
      const std::scoped_lock lock(m_mutex);

      if(!m_executor) {
         throw Invalid_State("Cannot add work after thread pool has shut down");
      }

      return m_executor;
   }();

   // Only the pointer value is used, as the marker; in-flight work never
   // touches the pool itself, so an executor may finish it after shutdown
   const auto wrapped = [this, work]() {
      const Running_Pool_Work scope(this);
      work();
   };

   try {
      executor->queue_work(wrapped);
   } catch(...) {
      // The executor refused the work, so run it here instead
      wrapped();
   }
}

}  // namespace Botan
