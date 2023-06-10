/*
* Filter
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/filter.h>

#include <botan/exceptn.h>

namespace Botan {

/*
* Filter Constructor
*/
Filter::Filter() {
   m_next.resize(1);
   m_port_num = 0;
   m_filter_owns = 0;
   m_owned = false;
}

/*
* Send data to all ports
*/
void Filter::send(const uint8_t input[], size_t length) {
   if(!length) {
      return;
   }

   bool nothing_attached = true;
   for(size_t j = 0; j != total_ports(); ++j) {
      if(m_next[j]) {
         if(!m_write_queue.empty()) {
            m_next[j]->write(m_write_queue.data(), m_write_queue.size());
         }
         m_next[j]->write(input, length);
         nothing_attached = false;
      }
   }

   if(nothing_attached) {
      m_write_queue += std::make_pair(input, length);
   } else {
      m_write_queue.clear();
   }
}

/*
* Start a new message
*/
void Filter::new_msg() {
   start_msg();
   for(size_t j = 0; j != total_ports(); ++j) {
      if(m_next[j]) {
         m_next[j]->new_msg();
      }
   }
}

/*
* End the current message
*/
void Filter::finish_msg() {
   end_msg();
   for(size_t j = 0; j != total_ports(); ++j) {
      if(m_next[j]) {
         m_next[j]->finish_msg();
      }
   }
}

/*
* Attach a filter to the current port
*/
void Filter::attach(Filter* new_filter) {
   if(new_filter) {
      Filter* last = this;
      while(last->get_next()) {
         last = last->get_next();
      }
      last->m_next[last->current_port()] = new_filter;
   }
}

/*
* Set the active port on a filter
*/
void Filter::set_port(size_t new_port) {
   if(new_port >= total_ports()) {
      throw Invalid_Argument("Filter: Invalid port number");
   }
   m_port_num = new_port;
}

/*
* Return the next Filter in the logical chain
*/
Filter* Filter::get_next() const {
   if(m_port_num < m_next.size()) {
      return m_next[m_port_num];
   }
   return nullptr;
}

/*
* Set the next Filters
*/
void Filter::set_next(Filter* filters[], size_t size) {
   m_next.clear();

   m_port_num = 0;
   m_filter_owns = 0;

   while(size && filters && (filters[size - 1] == nullptr)) {
      --size;
   }

   if(filters && size) {
      m_next.assign(filters, filters + size);
   }
}

/*
* Return the total number of ports
*/
size_t Filter::total_ports() const {
   return m_next.size();
}

}  // namespace Botan
