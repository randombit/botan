/*
* Barrier
* (C) 2016 Joel Low
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_UTIL_BARRIER_H__
#define BOTAN_UTIL_BARRIER_H__

#include <botan/mutex.h>

#if defined(BOTAN_TARGET_OS_HAS_THREADS)
#include <condition_variable>
#endif

namespace Botan {

#if defined(BOTAN_TARGET_OS_HAS_THREADS)
// Barrier implements a barrier synchronization primitive. wait() will indicate
// how many threads to synchronize; each thread needing synchronization should
// call sync(). When sync() returns, the barrier is reset to zero.
class Barrier
    {
    public:
        explicit Barrier(int value = 0) : m_value(value) {}

        void wait(unsigned delta);

        void sync();

    private:
        int m_value;
        mutex_type m_mutex;
        std::condition_variable m_cond;
    };
#endif

}

#endif
