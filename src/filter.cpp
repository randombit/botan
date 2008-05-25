/*************************************************
* Filter Source File                             *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/filter.h>
#include <botan/secqueue.h>
#include <botan/libstate.h>
#include <iostream>

namespace Botan {

/*************************************************
* Filter Constructor                             *
*************************************************/
Filter::Filter()
   : Freestore(),
     write_queue(),
     next(1),
     port_num(0),
     filter_owns(0),
     owned(false)
   {
   // nothing else to do
   }

/*************************************************
* Send data to all ports                         *
*************************************************/
void Filter::send(const byte input[], u32bit length)
   {
   global_state().pulse(PIPE_WRITE);

   bool nothing_attached = true;
   for(u32bit j = 0; j != total_ports(); ++j)
      if(next[j].get())
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
      if(next[j].get())
         next[j]->finish_msg();
   }

/*************************************************
* Attach a filter to the current port            *
*************************************************/
void Filter::attach(SharedFilterPtrConverter const& new_filter_converter)
   {
   SharedFilterPtr const& new_filter(new_filter_converter.get_shared());
   if(new_filter.get())
      {
      // here it is safe to use raw pointers (and
      // avoids the need for shared_from_this().)
      Filter* last = this;
      while(last->get_next().get())
        last = last->get_next().get();
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
Filter::SharedFilterPtr const Filter::get_next() const
   {
   if(port_num < next.size())
      return next[port_num];
   return Filter::SharedFilterPtr();
   }

/*************************************************
* Return the total number of ports               *
*************************************************/
u32bit Filter::total_ports() const
   {
   return next.size();
   }

}
