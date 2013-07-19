/*
* Filter
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/filter.h>
#include <botan/secqueue.h>
#include <botan/exceptn.h>

namespace Botan {

/*
* Filter Constructor
*/
Filter::Filter()
   {
   next.resize(1);
   port_num = 0;
   filter_owns = 0;
   owned = false;
   }

/*
* Send data to all ports
*/
void Filter::send(const byte input[], size_t length)
   {
   bool nothing_attached = true;
   for(size_t j = 0; j != total_ports(); ++j)
      if(next[j])
         {
         if(write_queue.size())
            next[j]->write(&write_queue[0], write_queue.size());
         next[j]->write(input, length);
         nothing_attached = false;
         }

   if(nothing_attached)
      write_queue += std::make_pair(input, length);
   else
      write_queue.clear();
   }

/*
* Start a new message
*/
void Filter::new_msg()
   {
   start_msg();
   for(size_t j = 0; j != total_ports(); ++j)
      if(next[j])
         next[j]->new_msg();
   }

/*
* End the current message
*/
void Filter::finish_msg()
   {
   end_msg();
   for(size_t j = 0; j != total_ports(); ++j)
      if(next[j])
         next[j]->finish_msg();
   }

/*
* Attach a filter to the current port
*/
void Filter::attach(Filter* new_filter)
   {
   if(new_filter)
      {
      Filter* last = this;
      while(last->get_next())
         last = last->get_next();
      last->next[last->current_port()] = new_filter;
      }
   }

/*
* Set the active port on a filter
*/
void Filter::set_port(size_t new_port)
   {
   if(new_port >= total_ports())
      throw Invalid_Argument("Filter: Invalid port number");
   port_num = new_port;
   }

/*
* Return the next Filter in the logical chain
*/
Filter* Filter::get_next() const
   {
   if(port_num < next.size())
      return next[port_num];
   return 0;
   }

/*
* Set the next Filters
*/
void Filter::set_next(Filter* filters[], size_t size)
   {
   next.clear();

   port_num = 0;
   filter_owns = 0;

   while(size && filters && filters[size-1] == 0)
      --size;

   if(filters && size)
      next.assign(filters, filters + size);
   }

/*
* Return the total number of ports
*/
size_t Filter::total_ports() const
   {
   return next.size();
   }

}
