/*
* Barrier
* (C) 2016 Joel Low
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/barrier.h>

#if defined(BOTAN_TARGET_OS_HAS_THREADS)

namespace Botan {

void Barrier::wait(size_t delta)
    {
    lock_guard_type<mutex_type> lock(m_mutex);
    m_value += delta;
    }

void Barrier::sync()
    {
    std::unique_lock<mutex_type> lock(m_mutex);
    --m_value;
    if(m_value > 0)
        {
        const size_t current_syncs = m_syncs;
        m_cond.wait(lock, [this, &current_syncs] { return m_syncs != current_syncs; });
        }
    else
        {
        m_value = 0;
        ++m_syncs;
        m_cond.notify_all();
        }
    }

}

#endif
