/*
* (C) 2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/rwlock.h>

namespace Botan {

RWLock::RWLock() : m_state(0) {}

void RWLock::lock() {
   std::unique_lock<std::mutex> lock(m_mutex);
   while(m_state & is_writing) {
      m_gate1.wait(lock);
   }
   m_state |= is_writing;
   while(m_state & readers_mask) {
      m_gate2.wait(lock);
   }
}

void RWLock::unlock() {
   std::unique_lock<std::mutex> lock(m_mutex);
   m_state = 0;
   m_gate1.notify_all();
}

void RWLock::lock_shared() {
   std::unique_lock<std::mutex> lock(m_mutex);
   while((m_state & is_writing) || (m_state & readers_mask) == readers_mask) {
      m_gate1.wait(lock);
   }
   const uint32_t num_readers = (m_state & readers_mask) + 1;
   m_state &= ~readers_mask;
   m_state |= num_readers;
}

void RWLock::unlock_shared() {
   std::unique_lock<std::mutex> lock(m_mutex);
   const uint32_t num_readers = (m_state & readers_mask) - 1;
   m_state &= ~readers_mask;
   m_state |= num_readers;
   if(m_state & is_writing) {
      if(num_readers == 0) {
         m_gate2.notify_one();
      }
   } else {
      if(num_readers == readers_mask - 1) {
         m_gate1.notify_one();
      }
   }
}

}  // namespace Botan
