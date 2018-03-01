/*
* Pipe Reading/Writing
* (C) 1999-2007 Jack Lloyd
*     2012 Markus Wanner
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pipe.h>
#include <botan/filter.h>
#include <botan/internal/out_buf.h>

namespace Botan {

/*
* Look up the canonical ID for a queue
*/
Pipe::message_id Pipe::get_message_no(const std::string& func_name,
                                      message_id msg) const
   {
   if(msg == DEFAULT_MESSAGE)
      msg = default_msg();
   else if(msg == LAST_MESSAGE)
      msg = message_count() - 1;

   if(msg >= message_count())
      throw Invalid_Message_Number(func_name, msg);

   return msg;
   }

/*
* Write into a Pipe
*/
void Pipe::write(const uint8_t input[], size_t length)
   {
   if(!m_inside_msg)
      throw Invalid_State("Cannot write to a Pipe while it is not processing");
   m_pipe->write(input, length);
   }

/*
* Write a string into a Pipe
*/
void Pipe::write(const std::string& str)
   {
   write(cast_char_ptr_to_uint8(str.data()), str.size());
   }

/*
* Write a single byte into a Pipe
*/
void Pipe::write(uint8_t input)
   {
   write(&input, 1);
   }

/*
* Write the contents of a DataSource into a Pipe
*/
void Pipe::write(DataSource& source)
   {
   secure_vector<uint8_t> buffer(BOTAN_DEFAULT_BUFFER_SIZE);
   while(!source.end_of_data())
      {
      size_t got = source.read(buffer.data(), buffer.size());
      write(buffer.data(), got);
      }
   }

/*
* Read some data from the pipe
*/
size_t Pipe::read(uint8_t output[], size_t length, message_id msg)
   {
   return m_outputs->read(output, length, get_message_no("read", msg));
   }

/*
* Read some data from the pipe
*/
size_t Pipe::read(uint8_t output[], size_t length)
   {
   return read(output, length, DEFAULT_MESSAGE);
   }

/*
* Read a single byte from the pipe
*/
size_t Pipe::read(uint8_t& out, message_id msg)
   {
   return read(&out, 1, msg);
   }

/*
* Return all data in the pipe
*/
secure_vector<uint8_t> Pipe::read_all(message_id msg)
   {
   msg = ((msg != DEFAULT_MESSAGE) ? msg : default_msg());
   secure_vector<uint8_t> buffer(remaining(msg));
   size_t got = read(buffer.data(), buffer.size(), msg);
   buffer.resize(got);
   return buffer;
   }

/*
* Return all data in the pipe as a string
*/
std::string Pipe::read_all_as_string(message_id msg)
   {
   msg = ((msg != DEFAULT_MESSAGE) ? msg : default_msg());
   secure_vector<uint8_t> buffer(BOTAN_DEFAULT_BUFFER_SIZE);
   std::string str;
   str.reserve(remaining(msg));

   while(true)
      {
      size_t got = read(buffer.data(), buffer.size(), msg);
      if(got == 0)
         break;
      str.append(cast_uint8_ptr_to_char(buffer.data()), got);
      }

   return str;
   }

/*
* Find out how many bytes are ready to read
*/
size_t Pipe::remaining(message_id msg) const
   {
   return m_outputs->remaining(get_message_no("remaining", msg));
   }

/*
* Peek at some data in the pipe
*/
size_t Pipe::peek(uint8_t output[], size_t length,
                  size_t offset, message_id msg) const
   {
   return m_outputs->peek(output, length, offset, get_message_no("peek", msg));
   }

/*
* Peek at some data in the pipe
*/
size_t Pipe::peek(uint8_t output[], size_t length, size_t offset) const
   {
   return peek(output, length, offset, DEFAULT_MESSAGE);
   }

/*
* Peek at a byte in the pipe
*/
size_t Pipe::peek(uint8_t& out, size_t offset, message_id msg) const
   {
   return peek(&out, 1, offset, msg);
   }

size_t Pipe::get_bytes_read() const
   {
   return m_outputs->get_bytes_read(default_msg());
   }

size_t Pipe::get_bytes_read(message_id msg) const
   {
   return m_outputs->get_bytes_read(msg);
   }

bool Pipe::check_available(size_t n)
   {
   return (n <= remaining(default_msg()));
   }

bool Pipe::check_available_msg(size_t n, message_id msg)
   {
   return (n <= remaining(msg));
   }

}
