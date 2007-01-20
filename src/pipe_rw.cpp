/*************************************************
* Pipe Reading/Writing Source File               *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/pipe.h>
#include <botan/out_buf.h>
#include <botan/secqueue.h>

namespace Botan {

/*************************************************
* Look up the canonical ID for a queue           *
*************************************************/
u32bit Pipe::get_message_no(const std::string& func_name, u32bit msg) const
   {
   if(msg == DEFAULT_MESSAGE)
      msg = default_msg();
   else if(msg == LAST_MESSAGE)
      msg = message_count() - 1;

   if(msg >= message_count())
      throw Invalid_Message_Number(func_name, msg);

   return msg;
   }

/*************************************************
* Write into a Pipe                              *
*************************************************/
void Pipe::write(const byte input[], u32bit length)
   {
   if(!inside_msg)
      throw Exception("Cannot write to a Pipe while it is not processing");
   pipe->write(input, length);
   }

/*************************************************
* Write into a Pipe                              *
*************************************************/
void Pipe::write(const MemoryRegion<byte>& input)
   {
   write(input.begin(), input.size());
   }

/*************************************************
* Write a string into a Pipe                     *
*************************************************/
void Pipe::write(const std::string& str)
   {
   write((const byte*)str.c_str(), str.size());
   }

/*************************************************
* Write a single byte into a Pipe                *
*************************************************/
void Pipe::write(byte input)
   {
   write(&input, 1);
   }

/*************************************************
* Write the contents of a DataSource into a Pipe *
*************************************************/
void Pipe::write(DataSource& source)
   {
   SecureVector<byte> buffer(DEFAULT_BUFFERSIZE);
   while(!source.end_of_data())
      {
      u32bit got = source.read(buffer, buffer.size());
      write(buffer, got);
      }
   }

/*************************************************
* Read some data from the pipe                   *
*************************************************/
u32bit Pipe::read(byte output[], u32bit length, u32bit msg)
   {
   return outputs->read(output, length, get_message_no("read", msg));
   }

/*************************************************
* Read some data from the pipe                   *
*************************************************/
u32bit Pipe::read(byte output[], u32bit length)
   {
   return read(output, length, DEFAULT_MESSAGE);
   }

/*************************************************
* Read a single byte from the pipe               *
*************************************************/
u32bit Pipe::read(byte& out, u32bit msg)
   {
   return read(&out, 1, msg);
   }

/*************************************************
* Return all data in the pipe                    *
*************************************************/
SecureVector<byte> Pipe::read_all(u32bit msg)
   {
   msg = ((msg != DEFAULT_MESSAGE) ? msg : default_msg());
   SecureVector<byte> buffer(remaining(msg));
   read(buffer, buffer.size(), msg);
   return buffer;
   }

/*************************************************
* Return all data in the pipe as a string        *
*************************************************/
std::string Pipe::read_all_as_string(u32bit msg)
   {
   msg = ((msg != DEFAULT_MESSAGE) ? msg : default_msg());
   SecureVector<byte> buffer(DEFAULT_BUFFERSIZE);
   std::string str;
   str.reserve(remaining(msg));

   while(true)
      {
      u32bit got = read(buffer, buffer.size(), msg);
      if(got == 0)
         break;
      str.append((const char*)buffer.begin(), got);
      }

   return str;
   }

/*************************************************
* Find out how many bytes are ready to read      *
*************************************************/
u32bit Pipe::remaining(u32bit msg) const
   {
   return outputs->remaining(get_message_no("remaining", msg));
   }

/*************************************************
* Peek at some data in the pipe                  *
*************************************************/
u32bit Pipe::peek(byte output[], u32bit length,
                  u32bit offset, u32bit msg) const
   {
   return outputs->peek(output, length, offset, get_message_no("peek", msg));
   }

/*************************************************
* Peek at some data in the pipe                  *
*************************************************/
u32bit Pipe::peek(byte output[], u32bit length, u32bit offset) const
   {
   return peek(output, length, offset, DEFAULT_MESSAGE);
   }

/*************************************************
* Peek at a byte in the pipe                     *
*************************************************/
u32bit Pipe::peek(byte& out, u32bit offset, u32bit msg) const
   {
   return peek(&out, 1, offset, msg);
   }

}
