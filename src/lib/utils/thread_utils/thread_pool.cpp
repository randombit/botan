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
#include <thread>

namespace Botan {

namespace {

/// The pool whose work this thread is currently running, if any
thread_local Thread_Pool* g_pool_of_this_worker = nullptr;  // NOLINT(*-avoid-non-const-global-variables)

/// Marks the current thread as running work on behalf of a pool
class Running_Pool_Work final {
   public:
      explicit Running_Pool_Work(Thread_Pool* pool) : m_prev(g_pool_of_this_worker) { g_pool_of_this_worker = pool; }

      ~Running_Pool_Work() { g_pool_of_this_worker = m_prev; }

      Running_Pool_Work(const Running_Pool_Work&) = delete;
      Running_Pool_Work& operator=(const Running_Pool_Work&) = delete;
      Running_Pool_Work(Running_Pool_Work&&) = delete;
      Running_Pool_Work& operator=(Running_Pool_Work&&) = delete;

   private:
      Thread_Pool* m_prev;
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

size_t resolve_pool_size(std::optional<size_t> opt_pool_size) {
   if(!opt_pool_size.has_value()) {
      return 0;
   }

   if(opt_pool_size.value() == 0) {
      /*
      * For large machines don't create too many threads, unless
      * explicitly asked to by the caller.
      */
      const size_t cores = OS::get_cpu_available();
      return std::clamp<size_t>(cores, 2, 16);
   }

   return opt_pool_size.value();
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
      m_pool_size(resolve_pool_size(opt_pool_size)), m_shutdown(false) {}

size_t Thread_Pool::worker_count() const {
   std::unique_lock<std::mutex> lock(m_mutex);

   // Once set the executor is never changed or released, so it is safe to
   // use outside of the lock
   if(Work_Executor* executor = m_executor.get()) {
      lock.unlock();
      return executor->max_concurrency();
   }

   return m_pool_size;
}

void Thread_Pool::set_executor(std::shared_ptr<Work_Executor> executor) {
   BOTAN_ARG_CHECK(executor != nullptr, "Thread_Pool::set_executor executor must not be null");

   // Would join the thread this is running on
   if(g_pool_of_this_worker == this) {
      throw Invalid_State("Cannot set the executor from within work run by the thread pool");
   }

   std::vector<std::thread> workers;

   {
      const std::scoped_lock lock(m_mutex);

      if(m_executor) {
         throw Invalid_State("Thread pool executor has already been set");
      }

      m_executor = std::move(executor);

      // The executor takes over, so any workers drain the queue and exit
      workers.swap(m_workers);
      m_more_tasks.notify_all();
   }

   for(auto& worker : workers) {
      worker.join();
   }
}

void Thread_Pool::shutdown() {
   std::vector<std::thread> workers;

   {
      const std::scoped_lock lock(m_mutex);

      if(m_shutdown) {
         return;
      }

      m_shutdown = true;
      workers.swap(m_workers);
      m_more_tasks.notify_all();
   }

   for(auto& worker : workers) {
      worker.join();
   }
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
   if(g_pool_of_this_worker == this) {
      return work();
   }

   std::unique_lock<std::mutex> lock(m_mutex);

   if(m_shutdown) {
      throw Invalid_State("Cannot add work after thread pool has shut down");
   }

   if(Work_Executor* executor = m_executor.get()) {
      lock.unlock();

      // Only the pointer value is used, as the marker; in-flight work never
      // touches the pool itself, which is why shutdown does not wait for it
      auto wrapped = [this, work]() {
         const Running_Pool_Work scope(this);
         work();
      };

      try {
         executor->queue_work(wrapped);
      } catch(...) {
         // The executor refused the work, so run it here instead
         wrapped();
      }
      return;
   }

   if(m_pool_size == 0) {
      lock.unlock();
      return work();
   }

   if(m_workers.empty()) {
      start_workers();
   }

   m_tasks.push_back(work);
   m_more_tasks.notify_one();
}

// Requires that m_mutex is held
void Thread_Pool::start_workers() {
   // On Linux, it is 16 length max, including terminator
   const std::string tname = "Botan thread";

   m_workers.reserve(m_pool_size);

   // Added one at a time so that if creating a thread fails, every thread in
   // m_workers is joinable and the ones already started still serve the queue
   for(size_t i = 0; i != m_pool_size; ++i) {
      m_workers.emplace_back(&Thread_Pool::worker_thread, this);
      OS::set_thread_name(m_workers.back(), tname);
   }
}

void Thread_Pool::worker_thread() {
   const Running_Pool_Work scope(this);

   for(;;) {
      std::function<void()> task;

      {
         std::unique_lock<std::mutex> lock(m_mutex);
         m_more_tasks.wait(lock, [this] { return m_shutdown || m_executor != nullptr || !m_tasks.empty(); });

         // Exit only once the queue is drained, which here means either the
         // pool is shutting down or an executor has taken over
         if(m_tasks.empty()) {
            return;
         }

         task = std::move(m_tasks.front());
         m_tasks.pop_front();
      }

      task();
   }
}

}  // namespace Botan
