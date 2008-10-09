/*************************************************
* SWIG Interface for Botan Pipe API              *
* (C) 1999-2003 Jack Lloyd                       *
*************************************************/

#include "base.h"
#include <botan/pipe.h>

#include <stdio.h>

/*************************************************
* Write the contents of a file into a Pipe       *
*************************************************/
void Pipe::write_file(const char* filename)
   {
   Botan::DataSource_Stream in(filename);
   pipe->write(in);
   }

/*************************************************
* Write the contents of a string into a Pipe     *
*************************************************/
void Pipe::write_string(const char* string)
   {
   pipe->write(string);
   }

/*************************************************
* Read the contents of a Pipe into a buffer      *
*************************************************/
u32bit Pipe::read(byte* buf, u32bit length, u32bit msg)
   {
   printf("read %p %d\n", buf, length);
   return 0;
   //return pipe->read(buf, length, msg);
   }

/*************************************************
* Read the contents of a Pipe as a string        *
*************************************************/
std::string Pipe::read_all_as_string(u32bit msg)
   {
   return pipe->read_all_as_string(msg);
   }

/*************************************************
* Find out how much stuff the Pipe still has     *
*************************************************/
u32bit Pipe::remaining(u32bit msg)
   {
   return pipe->remaining();
   }

/*************************************************
* Start a new message                            *
*************************************************/
void Pipe::start_msg()
   {
   pipe->start_msg();
   }

/*************************************************
* End the current msessage                       *
*************************************************/
void Pipe::end_msg()
   {
   pipe->end_msg();
   }

/*************************************************
* Create a new Pipe                              *
*************************************************/
Pipe::Pipe(Filter* f1, Filter* f2, Filter* f3, Filter* f4)
   {
   pipe = new Botan::Pipe();

   if(f1) { pipe->append(f1->filter); f1->pipe_owns = true; }
   if(f2) { pipe->append(f2->filter); f2->pipe_owns = true; }
   if(f3) { pipe->append(f3->filter); f3->pipe_owns = true; }
   if(f4) { pipe->append(f4->filter); f4->pipe_owns = true; }
   }

/*************************************************
* Destroy this Pipe                              *
*************************************************/
Pipe::~Pipe()
   {
   delete pipe;
   }
