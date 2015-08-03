/*
* Pipe Reading/Writing
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/pipe.h>
#include <botan/internal/out_buf.h>
#include <botan/secqueue.h>

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
void Pipe::write(const byte input[], size_t length)
   {
   if(!inside_msg)
      throw Invalid_State("Cannot write to a Pipe while it is not processing");
   pipe->write(input, length);
   }

/*
* Write into a Pipe
*/
void Pipe::write(const MemoryRegion<byte>& input)
   {
   write(&input[0], input.size());
   }

/*
* Write a string into a Pipe
*/
void Pipe::write(const std::string& str)
   {
   write(reinterpret_cast<const byte*>(str.data()), str.size());
   }

/*
* Write a single byte into a Pipe
*/
void Pipe::write(byte input)
   {
   write(&input, 1);
   }

/*
* Write the contents of a DataSource into a Pipe
*/
void Pipe::write(DataSource& source)
   {
   SecureVector<byte> buffer(DEFAULT_BUFFERSIZE);
   while(!source.end_of_data())
      {
      size_t got = source.read(&buffer[0], buffer.size());
      write(&buffer[0], got);
      }
   }

/*
* Read some data from the pipe
*/
size_t Pipe::read(byte output[], size_t length, message_id msg)
   {
   return outputs->read(output, length, get_message_no("read", msg));
   }

/*
* Read some data from the pipe
*/
size_t Pipe::read(byte output[], size_t length)
   {
   return read(output, length, DEFAULT_MESSAGE);
   }

/*
* Read a single byte from the pipe
*/
size_t Pipe::read(byte& out, message_id msg)
   {
   return read(&out, 1, msg);
   }

/*
* Return all data in the pipe
*/
SecureVector<byte> Pipe::read_all(message_id msg)
   {
   msg = ((msg != DEFAULT_MESSAGE) ? msg : default_msg());
   SecureVector<byte> buffer(remaining(msg));
   size_t got = read(&buffer[0], buffer.size(), msg);
   buffer.resize(got);
   return buffer;
   }

/*
* Return all data in the pipe as a string
*/
std::string Pipe::read_all_as_string(message_id msg)
   {
   msg = ((msg != DEFAULT_MESSAGE) ? msg : default_msg());
   SecureVector<byte> buffer(DEFAULT_BUFFERSIZE);
   std::string str;
   str.reserve(remaining(msg));

   while(true)
      {
      size_t got = read(&buffer[0], buffer.size(), msg);
      if(got == 0)
         break;
      str.append(reinterpret_cast<const char*>(&buffer[0]), got);
      }

   return str;
   }

/*
* Find out how many bytes are ready to read
*/
size_t Pipe::remaining(message_id msg) const
   {
   return outputs->remaining(get_message_no("remaining", msg));
   }

bool Pipe::check_available(size_t n)
   {
   return (n <= remaining(DEFAULT_MESSAGE));
   }

bool Pipe::check_available_msg(size_t n, message_id msg)
   {
   return (n <= remaining(msg));
   }

/*
* Peek at some data in the pipe
*/
size_t Pipe::peek(byte output[], size_t length,
                  size_t offset, message_id msg) const
   {
   return outputs->peek(output, length, offset, get_message_no("peek", msg));
   }

/*
* Peek at some data in the pipe
*/
size_t Pipe::peek(byte output[], size_t length, size_t offset) const
   {
   return peek(output, length, offset, DEFAULT_MESSAGE);
   }

/*
* Peek at a byte in the pipe
*/
size_t Pipe::peek(byte& out, size_t offset, message_id msg) const
   {
   return peek(&out, 1, offset, msg);
   }

}
