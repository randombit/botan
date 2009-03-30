/*
* Unix EntropySource
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/es_unix.h>
#include <botan/unix_cmd.h>
#include <botan/parsing.h>
#include <algorithm>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <unistd.h>

namespace Botan {

namespace {

/**
* Sort ordering by priority
*/
bool Unix_Program_Cmp(const Unix_Program& a, const Unix_Program& b)
   { return (a.priority < b.priority); }

}

/**
* Unix_EntropySource Constructor
*/
Unix_EntropySource::Unix_EntropySource(const std::vector<std::string>& path) :
   PATH(path)
   {
   add_default_sources(sources);
   }

/**
* Add sources to the list
*/
void Unix_EntropySource::add_sources(const Unix_Program srcs[], u32bit count)
   {
   sources.insert(sources.end(), srcs, srcs + count);
   std::sort(sources.begin(), sources.end(), Unix_Program_Cmp);
   }

/**
* Poll for entropy on a generic Unix system, first by grabbing various
* statistics (stat on common files, getrusage, etc), and then, if more
* is required, by exec'ing various programs like uname and rpcinfo and
* reading the output.
*/
void Unix_EntropySource::poll(Entropy_Accumulator& accum)
   {
   const char* stat_targets[] = {
      "/",
      "/tmp",
      "/var/tmp",
      "/usr",
      "/home",
      "/etc/passwd",
      ".",
      "..",
      0 };

   for(u32bit j = 0; stat_targets[j]; j++)
      {
      struct stat statbuf;
      clear_mem(&statbuf, 1);
      ::stat(stat_targets[j], &statbuf);
      accum.add(&statbuf, sizeof(statbuf), .005);
      }

   accum.add(::getpid(),  0);
   accum.add(::getppid(), 0);
   accum.add(::getuid(),  0);
   accum.add(::geteuid(), 0);
   accum.add(::getegid(), 0);
   accum.add(::getpgrp(), 0);
   accum.add(::getsid(0), 0);

   struct ::rusage usage;
   ::getrusage(RUSAGE_SELF, &usage);
   accum.add(usage, .005);

   ::getrusage(RUSAGE_CHILDREN, &usage);
   accum.add(usage, .005);

   const u32bit MINIMAL_WORKING = 16;

   MemoryRegion<byte>& io_buffer = accum.get_io_buffer(DEFAULT_BUFFERSIZE);

   for(u32bit j = 0; j != sources.size(); j++)
      {
      DataSource_Command pipe(sources[j].name_and_args, PATH);

      u32bit got_from_src = 0;

      while(!pipe.end_of_data())
         {
         u32bit got_this_loop = pipe.read(io_buffer, io_buffer.size());
         got_from_src += got_this_loop;

         accum.add(io_buffer.begin(), got_this_loop, .005);
         }

      sources[j].working = (got_from_src >= MINIMAL_WORKING) ? true : false;

      if(accum.polling_goal_achieved())
         break;
      }
   }

}
