/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_WORK_EXECUTOR_H_
#define BOTAN_WORK_EXECUTOR_H_

#include <botan/types.h>
#include <functional>
#include <memory>

namespace Botan {

/**
* An application provided replacement for the library's thread pool
*
* Some operations split their work across threads. By default this uses a
* thread pool internal to the library. An application can instead route that
* work to threads of its own choosing by installing an implementation of this
* interface with set_global.
*
* All such work is fork-join: the thread which queued the work blocks until it
* has completed. The executor must therefore guarantee forward progress; each
* piece of work must either run on a thread which is not itself blocked waiting
* for it, or be run directly within queue_work. In particular, an executor
* backed by a fixed set of threads should run work directly when queue_work is
* called from one of those threads, since otherwise all of them may end up
* blocked waiting on each other.
*
* The library may call queue_work and max_concurrency from any number of
* threads at once, so both must be thread safe.
*/
class BOTAN_PUBLIC_API(3, 14) Work_Executor {
   public:
      Work_Executor() = default;
      virtual ~Work_Executor() = default;

      Work_Executor(const Work_Executor&) = delete;
      Work_Executor& operator=(const Work_Executor&) = delete;
      Work_Executor(Work_Executor&&) = delete;
      Work_Executor& operator=(Work_Executor&&) = delete;

      /**
      * Queue a piece of work
      *
      * The work must run exactly once, on any thread. Running it directly
      * within this call is permitted. If this call throws, the work is taken
      * to not have been accepted, and is run in the calling thread instead.
      * The work never throws.
      */
      virtual void queue_work(std::function<void()> work) = 0;

      /**
      * Return the number of threads available to run queued work
      *
      * This is a hint used to decide how finely to split divisible work.
      * Returning 1 (or 0) means such work is not split at all, though the
      * executor may still be asked to run work which is parallel by nature.
      */
      virtual size_t max_concurrency() const = 0;

      /**
      * Install an executor which replaces the library's internal thread pool
      *
      * This may be called at most once. The executor then remains in use, and
      * is referenced by the library, for the remainder of the process. That
      * reference is released during static destruction at process exit, so
      * keep a reference of your own to control when the executor is destroyed.
      *
      * Any threads the internal pool has already started finish their queued
      * work and exit. Ideally this is called before any other use of the
      * library, so that those threads are never started at all.
      *
      * Throws Invalid_State if an executor is already installed, or if called
      * from within work queued by the library.
      */
      static void set_global(std::shared_ptr<Work_Executor> executor);
};

}  // namespace Botan

#endif
