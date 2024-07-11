/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_WORK_FN_H_
#define BOTAN_WORK_FN_H_

#include <functional>
#include <memory>

namespace Botan {

/**
* A Work Executor is something capable of executing functions
*
* The library delegates certain work 
*/
class Work_Executor {
   public:
      /**
      * Set the global work executor. This allows for example
      * providing a custom thread pool.
      */
      static void set_global_work_executor(std::shared_ptr<Work_Executor> worker);

      virtual ~Work_Executor() = default;

      /**
      * The work executor promises to eventually call fn
      *
      * The execution may be delayed and in any order
      */
      virtual void run_work(const std::function<void()>& fn) = 0;

      /**
      * Return a best-effort approximation of how much parallelism is
      * possible
      */
      virtual size_t available_parallelism() const = 0;

      worker_count() const { return m_workers.size(); }
};

}

#endif
