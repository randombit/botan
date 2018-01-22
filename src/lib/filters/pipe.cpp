/*
* Pipe
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pipe.h>
#include <botan/internal/out_buf.h>
#include <botan/secqueue.h>

namespace Botan {

namespace {

/*
* A Filter that does nothing
*/
class Null_Filter final : public Filter
   {
   public:
      void write(const uint8_t input[], size_t length) override
         { send(input, length); }

      std::string name() const override { return "Null"; }
   };

}

/*
* Pipe Constructor
*/
Pipe::Pipe(Filter* f1, Filter* f2, Filter* f3, Filter* f4) :
   Pipe({f1,f2,f3,f4})
   {
   }

/*
* Pipe Constructor
*/
Pipe::Pipe(std::initializer_list<Filter*> args)
   {
   m_outputs.reset(new Output_Buffers);
   m_pipe = nullptr;
   m_default_read = 0;
   m_inside_msg = false;

   for(auto i = args.begin(); i != args.end(); ++i)
      do_append(*i);
   }

/*
* Pipe Destructor
*/
Pipe::~Pipe()
   {
   destruct(m_pipe);
   }

/*
* Reset the Pipe
*/
void Pipe::reset()
   {
   destruct(m_pipe);
   m_pipe = nullptr;
   m_inside_msg = false;
   }

/*
* Destroy the Pipe
*/
void Pipe::destruct(Filter* to_kill)
   {
   if(!to_kill || dynamic_cast<SecureQueue*>(to_kill))
      return;
   for(size_t j = 0; j != to_kill->total_ports(); ++j)
      destruct(to_kill->m_next[j]);
   delete to_kill;
   }

/*
* Test if the Pipe has any data in it
*/
bool Pipe::end_of_data() const
   {
   return (remaining() == 0);
   }

/*
* Set the default read message
*/
void Pipe::set_default_msg(message_id msg)
   {
   if(msg >= message_count())
      throw Invalid_Argument("Pipe::set_default_msg: msg number is too high");
   m_default_read = msg;
   }

/*
* Process a full message at once
*/
void Pipe::process_msg(const uint8_t input[], size_t length)
   {
   start_msg();
   write(input, length);
   end_msg();
   }

/*
* Process a full message at once
*/
void Pipe::process_msg(const secure_vector<uint8_t>& input)
   {
   process_msg(input.data(), input.size());
   }

void Pipe::process_msg(const std::vector<uint8_t>& input)
   {
   process_msg(input.data(), input.size());
   }

/*
* Process a full message at once
*/
void Pipe::process_msg(const std::string& input)
   {
   process_msg(cast_char_ptr_to_uint8(input.data()), input.length());
   }

/*
* Process a full message at once
*/
void Pipe::process_msg(DataSource& input)
   {
   start_msg();
   write(input);
   end_msg();
   }

/*
* Start a new message
*/
void Pipe::start_msg()
   {
   if(m_inside_msg)
      throw Invalid_State("Pipe::start_msg: Message was already started");
   if(m_pipe == nullptr)
      m_pipe = new Null_Filter;
   find_endpoints(m_pipe);
   m_pipe->new_msg();
   m_inside_msg = true;
   }

/*
* End the current message
*/
void Pipe::end_msg()
   {
   if(!m_inside_msg)
      throw Invalid_State("Pipe::end_msg: Message was already ended");
   m_pipe->finish_msg();
   clear_endpoints(m_pipe);
   if(dynamic_cast<Null_Filter*>(m_pipe))
      {
      delete m_pipe;
      m_pipe = nullptr;
      }
   m_inside_msg = false;

   m_outputs->retire();
   }

/*
* Find the endpoints of the Pipe
*/
void Pipe::find_endpoints(Filter* f)
   {
   for(size_t j = 0; j != f->total_ports(); ++j)
      if(f->m_next[j] && !dynamic_cast<SecureQueue*>(f->m_next[j]))
         find_endpoints(f->m_next[j]);
      else
         {
         SecureQueue* q = new SecureQueue;
         f->m_next[j] = q;
         m_outputs->add(q);
         }
   }

/*
* Remove the SecureQueues attached to the Filter
*/
void Pipe::clear_endpoints(Filter* f)
   {
   if(!f) return;
   for(size_t j = 0; j != f->total_ports(); ++j)
      {
      if(f->m_next[j] && dynamic_cast<SecureQueue*>(f->m_next[j]))
         f->m_next[j] = nullptr;
      clear_endpoints(f->m_next[j]);
      }
   }

void Pipe::append(Filter* filter)
   {
   do_append(filter);
   }

void Pipe::append_filter(Filter* filter)
   {
   if(m_outputs->message_count() != 0)
      throw Invalid_State("Cannot call Pipe::append_filter after start_msg");

   do_append(filter);
   }

void Pipe::prepend(Filter* filter)
   {
   do_prepend(filter);
   }

void Pipe::prepend_filter(Filter* filter)
   {
   if(m_outputs->message_count() != 0)
      throw Invalid_State("Cannot call Pipe::prepend_filter after start_msg");

   do_prepend(filter);
   }

/*
* Append a Filter to the Pipe
*/
void Pipe::do_append(Filter* filter)
   {
   if(!filter)
      return;
   if(dynamic_cast<SecureQueue*>(filter))
      throw Invalid_Argument("Pipe::append: SecureQueue cannot be used");
   if(filter->m_owned)
      throw Invalid_Argument("Filters cannot be shared among multiple Pipes");

   if(m_inside_msg)
      throw Invalid_State("Cannot append to a Pipe while it is processing");

   filter->m_owned = true;

   if(!m_pipe) m_pipe = filter;
   else      m_pipe->attach(filter);
   }

/*
* Prepend a Filter to the Pipe
*/
void Pipe::do_prepend(Filter* filter)
   {
   if(m_inside_msg)
      throw Invalid_State("Cannot prepend to a Pipe while it is processing");
   if(!filter)
      return;
   if(dynamic_cast<SecureQueue*>(filter))
      throw Invalid_Argument("Pipe::prepend: SecureQueue cannot be used");
   if(filter->m_owned)
      throw Invalid_Argument("Filters cannot be shared among multiple Pipes");

   filter->m_owned = true;

   if(m_pipe) filter->attach(m_pipe);
   m_pipe = filter;
   }

/*
* Pop a Filter off the Pipe
*/
void Pipe::pop()
   {
   if(m_inside_msg)
      throw Invalid_State("Cannot pop off a Pipe while it is processing");

   if(!m_pipe)
      return;

   if(m_pipe->total_ports() > 1)
      throw Invalid_State("Cannot pop off a Filter with multiple ports");

   size_t to_remove = m_pipe->owns() + 1;

   while(to_remove--)
      {
      std::unique_ptr<Filter> to_destroy(m_pipe);
      m_pipe = m_pipe->m_next[0];
      }
   }

/*
* Return the number of messages in this Pipe
*/
Pipe::message_id Pipe::message_count() const
   {
   return m_outputs->message_count();
   }

/*
* Static Member Variables
*/
const Pipe::message_id Pipe::LAST_MESSAGE =
   static_cast<Pipe::message_id>(-2);

const Pipe::message_id Pipe::DEFAULT_MESSAGE =
   static_cast<Pipe::message_id>(-1);

}
