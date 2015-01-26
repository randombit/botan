/*
* Threaded Fork
* (C) 2013 Joel Low
*     2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/basefilt.h>
#include <botan/internal/semaphore.h>

namespace Botan {

struct Threaded_Fork_Data
   {
   /*
   * Semaphore for indicating that there is work to be done (or to
   * quit)
   */
   Semaphore m_input_ready_semaphore;

   /*
   * Ensures that all threads have completed processing data.
   */
   Semaphore m_input_complete_semaphore;

   /*
   * The work that needs to be done. This should be only when the threads
   * are NOT running (i.e. before notifying the work condition, after
   * the input_complete_semaphore is completely reset.)
   */
   const byte* m_input = nullptr;

   /*
   * The length of the work that needs to be done.
   */
   size_t m_input_length = 0;
   };

/*
* Threaded_Fork constructor
*/
Threaded_Fork::Threaded_Fork(Filter* f1, Filter* f2, Filter* f3, Filter* f4) :
   Fork(nullptr, static_cast<size_t>(0)),
   m_thread_data(new Threaded_Fork_Data)
   {
   Filter* filters[4] = { f1, f2, f3, f4 };
   set_next(filters, 4);
   }

/*
* Threaded_Fork constructor
*/
Threaded_Fork::Threaded_Fork(Filter* filters[], size_t count) :
   Fork(nullptr, static_cast<size_t>(0)),
   m_thread_data(new Threaded_Fork_Data)
   {
   set_next(filters, count);
   }

Threaded_Fork::~Threaded_Fork()
   {
   m_thread_data->m_input = nullptr;
   m_thread_data->m_input_length = 0;

   m_thread_data->m_input_ready_semaphore.release(m_threads.size());

   for(auto& thread : m_threads)
     thread->join();
   }

std::string Threaded_Fork::name() const
   {
   return "Threaded Fork";
   }

void Threaded_Fork::set_next(Filter* f[], size_t n)
   {
   Fork::set_next(f, n);
   n = next.size();

   if(n < m_threads.size())
      m_threads.resize(n);
   else
      {
      m_threads.reserve(n);
      for(size_t i = m_threads.size(); i != n; ++i)
         {
         m_threads.push_back(
            std::shared_ptr<std::thread>(
               new std::thread(
                  std::bind(&Threaded_Fork::thread_entry, this, next[i]))));
         }
      }
   }

void Threaded_Fork::send(const byte input[], size_t length)
   {
   if(write_queue.size())
      thread_delegate_work(write_queue.data(), write_queue.size());
   thread_delegate_work(input, length);

   bool nothing_attached = true;
   for(size_t j = 0; j != total_ports(); ++j)
      if(next[j])
         nothing_attached = false;

   if(nothing_attached)
      write_queue += std::make_pair(input, length);
   else
      write_queue.clear();
   }

void Threaded_Fork::thread_delegate_work(const byte input[], size_t length)
   {
   //Set the data to do.
   m_thread_data->m_input = input;
   m_thread_data->m_input_length = length;

   //Let the workers start processing.
   m_thread_data->m_input_ready_semaphore.release(total_ports());

   //Wait for all the filters to finish processing.
   for(size_t i = 0; i != total_ports(); ++i)
      m_thread_data->m_input_complete_semaphore.acquire();

   //Reset the thread data
   m_thread_data->m_input = nullptr;
   m_thread_data->m_input_length = 0;
   }

void Threaded_Fork::thread_entry(Filter* filter)
   {
   while(true)
      {
      m_thread_data->m_input_ready_semaphore.acquire();

      if(!m_thread_data->m_input)
         break;

      filter->write(m_thread_data->m_input, m_thread_data->m_input_length);
      m_thread_data->m_input_complete_semaphore.release();
      }
   }

}
