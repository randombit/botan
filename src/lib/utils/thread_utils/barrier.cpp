/*
* Barrier
* (C) 2016 Joel Low
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/barrier.h>

namespace Botan {

void Barrier::wait(size_t delta)
    {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_value += delta;
    }

void Barrier::sync()
    {
    std::unique_lock<std::mutex> lock(m_mutex);

    if(m_value > 1)
        {
        --m_value;
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
