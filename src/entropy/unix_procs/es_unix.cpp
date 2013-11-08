/*
* Unix EntropySource
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/es_unix.h>
#include <botan/internal/unix_cmd.h>
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
   {
   if(a.priority == b.priority)
      return (a.name_and_args < b.name_and_args);

   return (a.priority < b.priority);
   }

}

/**
* Unix_EntropySource Constructor
*/
Unix_EntropySource::Unix_EntropySource(const std::vector<std::string>& path) :
   PATH(path)
   {
   std::vector<Unix_Program> default_sources = get_default_sources();
   add_sources(&default_sources[0], default_sources.size());
   }

/**
* Add sources to the list
*/
void Unix_EntropySource::add_sources(const Unix_Program srcs[], size_t count)
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
      nullptr };

   for(size_t i = 0; stat_targets[i]; i++)
      {
      struct stat statbuf;
      clear_mem(&statbuf, 1);
      ::stat(stat_targets[i], &statbuf);
      accum.add(&statbuf, sizeof(statbuf), .005);
      }

   accum.add(::getpid(),  0);
   accum.add(::getppid(), 0);
   accum.add(::getuid(),  0);
   accum.add(::getgid(), 0);
   accum.add(::getpgrp(), 0);

   struct ::rusage usage;
   ::getrusage(RUSAGE_SELF, &usage);
   accum.add(usage, .005);

   ::getrusage(RUSAGE_CHILDREN, &usage);
   accum.add(usage, .005);

   const size_t MINIMAL_WORKING = 16;

   secure_vector<byte>& io_buffer = accum.get_io_buffer(4*1024);

   for(size_t i = 0; i != sources.size(); i++)
      {
      DataSource_Command pipe(sources[i].name_and_args, PATH);

      size_t got_from_src = 0;

      while(!pipe.end_of_data())
         {
         size_t got_this_loop = pipe.read(&io_buffer[0], io_buffer.size());
         got_from_src += got_this_loop;

         accum.add(&io_buffer[0], got_this_loop, .005);
         }

      sources[i].working = (got_from_src >= MINIMAL_WORKING) ? true : false;

      if(accum.polling_goal_achieved())
         break;
      }
   }

}
