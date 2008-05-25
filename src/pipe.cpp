/*************************************************
* Pipe Source File                               *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/pipe.h>
#include <botan/out_buf.h>
#include <botan/secqueue.h>
#include <iostream>

namespace Botan {

namespace {

/*************************************************
* A Filter that does nothing                     *
*************************************************/
class Null_Filter : public Filter
   {
   public:
      void write(const byte input[], u32bit length)
         { send(input, length); }
   };

}

/*************************************************
* Pipe Constructor                               *
*************************************************/
Pipe::Pipe(SharedFilterPtrConverter const& f1,
           SharedFilterPtrConverter const& f2,
           SharedFilterPtrConverter const& f3,
           SharedFilterPtrConverter const& f4)
  : pipe(),
    outputs(),
    default_read(0),
    inside_msg(false)
   {
   init();
   append(f1);
   append(f2);
   append(f3);
   append(f4);
   }

/*************************************************
* Pipe Destructor                                *
*************************************************/
Pipe::~Pipe()
   {
   destruct(pipe);
   }

/*************************************************
* Initialize the Pipe                            *
*************************************************/
void Pipe::init()
   {
     outputs.reset(new Output_Buffers);
     pipe.reset();
     default_read = 0;
     inside_msg = false;
   }

/*************************************************
* Reset the Pipe                                 *
*************************************************/
void Pipe::reset()
   {
   if(inside_msg)
      throw Invalid_State("Pipe cannot be reset while it is processing");
   destruct(pipe);
   inside_msg = false;
   }

/*************************************************
* Destroy the Pipe                               *
*************************************************/
void Pipe::destruct(Filter::SharedFilterPtr& to_kill)
   {
   if(!to_kill.get() || dynamic_cast<SecureQueue*>(to_kill.get()))
      return;
   for(u32bit j = 0; j != to_kill->total_ports(); ++j) {
      destruct(to_kill->next[j]);
   }
   to_kill->owned = false;
   to_kill.reset();
   }

/*************************************************
* Test if the Pipe has any data in it            *
*************************************************/
bool Pipe::end_of_data() const
   {
   return (remaining() == 0); // remaining(u32bit = DEFAULT_MESSAGE)
   }

/*************************************************
* Set the default read message                   *
*************************************************/
void Pipe::set_default_msg(u32bit msg)
   {
   if(msg >= message_count())
      throw Invalid_Argument("Pipe::set_default_msg: msg number is too high");
   default_read = msg;
   }

/*************************************************
* Process a full message at once                 *
*************************************************/
void Pipe::process_msg(const byte input[], u32bit length)
   {
   start_msg();
   write(input, length);
   end_msg();
   }

/*************************************************
* Process a full message at once                 *
*************************************************/
void Pipe::process_msg(const MemoryRegion<byte>& input)
   {
   process_msg(input.begin(), input.size());
   }

/*************************************************
* Process a full message at once                 *
*************************************************/
void Pipe::process_msg(const std::string& input)
   {
   process_msg(reinterpret_cast<const byte*>(input.data()), input.length());
   }

/*************************************************
* Process a full message at once                 *
*************************************************/
void Pipe::process_msg(DataSource& input)
   {
   start_msg();
   write(input);
   end_msg();
   }

/*************************************************
* Start a new message                            *
*************************************************/
void Pipe::start_msg()
   {
   if(inside_msg)
      throw Invalid_State("Pipe::start_msg: Message was already started");
   if(!pipe.get())
      pipe = create_shared_ptr<Null_Filter>();
   find_endpoints(pipe);
   pipe->new_msg();
   inside_msg = true;
   }

/*************************************************
* End the current message                        *
*************************************************/
void Pipe::end_msg()
   {
   if(!inside_msg)
      throw Invalid_State("Pipe::end_msg: Message was already ended");
   pipe->finish_msg();
   clear_endpoints(pipe);
//   if(std::tr1::dynamic_pointer_cast<Null_Filter>(pipe))
   if(dynamic_cast<Null_Filter*>(pipe.get()))
      {
      pipe->owned = false; // really necessary?
      pipe.reset();
      }
   inside_msg = false;

   outputs->retire();
   }

/*************************************************
* Find the endpoints of the Pipe                 *
*************************************************/
void Pipe::find_endpoints(const Filter::SharedFilterPtr& f)
   {
   for(u32bit j = 0; j != f->total_ports(); ++j)
     //if((f->next[j]).get() && !std::tr1::dynamic_pointer_cast<SecureQueue>(f->next[j]))
     if((f->next[j]).get() && !dynamic_cast<SecureQueue*>((f->next[j]).get()))
         find_endpoints(f->next[j]);
      else
         {
         std::tr1::shared_ptr<SecureQueue> q = create_shared_ptr<SecureQueue>();
         f->next[j] = q;
         outputs->add(q);
         }
   }

/*************************************************
* Remove the SecureQueues attached to the Filter *
*************************************************/
void Pipe::clear_endpoints(const Filter::SharedFilterPtr& f)
   {
   if(!f.get()) return;
   for(u32bit j = 0; j != f->total_ports(); ++j)
      {
      //if((f->next[j]).get() && std::tr1::dynamic_pointer_cast<SecureQueue>(f->next[j]))
      if((f->next[j]).get() && dynamic_cast<SecureQueue*>((f->next[j]).get()))
        f->next[j] = Filter::SharedFilterPtr();
      clear_endpoints(f->next[j]);
      }
   }

/*************************************************
* Append a Filter to the Pipe                    *
*************************************************/
void Pipe::append(SharedFilterPtrConverter const& filter_converter)
   {
   SharedFilterPtr filter(filter_converter.get_shared());
   if(inside_msg)
      throw Invalid_State("Cannot append to a Pipe while it is processing");
   if(!filter.get())
      return;
   //if(std::tr1::dynamic_pointer_cast<SecureQueue>(filter))
   if( dynamic_cast<SecureQueue*>(filter.get()))
      throw Invalid_Argument("Pipe::append: SecureQueue cannot be used");
   if(filter->owned)
      throw Invalid_Argument("Filters cannot be shared among multiple Pipes");

   filter->owned = true;

   if(!pipe.get()) pipe = filter;
   else      pipe->attach(filter);
   }

/*************************************************
* Prepend a Filter to the Pipe                   *
*************************************************/
void Pipe::prepend(SharedFilterPtrConverter const& filter_converter)
   {
   SharedFilterPtr filter(filter_converter.get_shared());
   if(inside_msg)
      throw Invalid_State("Cannot prepend to a Pipe while it is processing");
   if(!filter.get())
      return;
   //if(std::tr1::dynamic_pointer_cast<SecureQueue>(filter))
   if( dynamic_cast<SecureQueue*>(filter.get()))
      throw Invalid_Argument("Pipe::prepend: SecureQueue cannot be used");
   if(filter->owned)
      throw Invalid_Argument("Filters cannot be shared among multiple Pipes");

   filter->owned = true;

   if(pipe.get()) filter->attach(pipe);
   pipe = filter;
   }

/*************************************************
* Pop a Filter off the Pipe                      *
*************************************************/
void Pipe::pop()
   {
   if(inside_msg)
      throw Invalid_State("Cannot pop off a Pipe while it is processing");

   if(!pipe.get())
      return;

   if(pipe->total_ports() > 1)
      throw Invalid_State("Cannot pop off a Filter with multiple ports");

   Filter::SharedFilterPtr f = pipe;
   u32bit owns = f->owns();
   pipe = pipe->next[0];
   f->owned = false; // really necessary?

   while(owns--)
      {
      f = pipe;
      pipe = pipe->next[0];
      f->owned = false; // really necessary?
      }
   }

/*************************************************
* Return the number of messages in this Pipe     *
*************************************************/
u32bit Pipe::message_count() const
   {
   return outputs->message_count();
   }

/*************************************************
* Static Member Variables                        *
*************************************************/
const u32bit Pipe::LAST_MESSAGE    = 0xFFFFFFFE;
const u32bit Pipe::DEFAULT_MESSAGE = 0xFFFFFFFF;

}
