/*************************************************
* Filter Source File                             *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/filter.h>
#include <botan/secqueue.h>
#include <botan/libstate.h>

namespace Botan {

/*************************************************
* Filter Constructor                             *
*************************************************/
Filter::Filter()
   {
   next.resize(1);
   port_num = 0;
   filter_owns = 0;
   owned = false;
   }

/*************************************************
* Send data to all ports                         *
*************************************************/
void Filter::send(const byte input[], u32bit length)
   {
   global_state().pulse(PIPE_WRITE);

   bool nothing_attached = true;
   for(u32bit j = 0; j != total_ports(); ++j)
      if(next[j])
         {
         if(write_queue.has_items())
            next[j]->write(write_queue, write_queue.size());
         next[j]->write(input, length);
         nothing_attached = false;
         }
   if(nothing_attached)
      write_queue.append(input, length);
   else if(write_queue.has_items())
      write_queue.destroy();
   }

/*************************************************
* Start a new message                            *
*************************************************/
void Filter::new_msg()
   {
   start_msg();
   for(u32bit j = 0; j != total_ports(); ++j)
      if(next[j])
         next[j]->new_msg();
   }

/*************************************************
* End the current message                        *
*************************************************/
void Filter::finish_msg()
   {
   end_msg();
   for(u32bit j = 0; j != total_ports(); ++j)
      if(next[j])
         next[j]->finish_msg();
   }

/*************************************************
* Attach a filter to the current port            *
*************************************************/
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

/*************************************************
* Set the active port on a filter                *
*************************************************/
void Filter::set_port(u32bit new_port)
   {
   if(new_port >= total_ports())
      throw Invalid_Argument("Filter: Invalid port number");
   port_num = new_port;
   }

/*************************************************
* Return the next Filter in the logical chain    *
*************************************************/
Filter* Filter::get_next() const
   {
   if(port_num < next.size())
      return next[port_num];
   return 0;
   }

/*************************************************
* Set the next Filters                           *
*************************************************/
void Filter::set_next(Filter* filters[], u32bit size)
   {
   while(size && filters && filters[size-1] == 0)
      --size;

   next.clear();
   next.resize(size);

   port_num = 0;
   filter_owns = 0;

   for(u32bit j = 0; j != size; ++j)
      next[j] = filters[j];
   }

/*************************************************
* Return the total number of ports               *
*************************************************/
u32bit Filter::total_ports() const
   {
   return next.size();
   }

}
