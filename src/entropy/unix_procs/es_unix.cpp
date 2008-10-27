/*************************************************
* Unix EntropySource Source File                 *
* (C) 1999-2008 Jack Lloyd                       *
*************************************************/

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

/*************************************************
* Sort ordering by priority                      *
*************************************************/
bool Unix_Program_Cmp(const Unix_Program& a, const Unix_Program& b)
   { return (a.priority < b.priority); }

}

/*************************************************
* Unix_EntropySource Constructor                 *
*************************************************/
Unix_EntropySource::Unix_EntropySource(const std::vector<std::string>& path) :
   PATH(path)
   {
   add_default_sources(sources);
   }

/*************************************************
* Add sources to the list                        *
*************************************************/
void Unix_EntropySource::add_sources(const Unix_Program srcs[], u32bit count)
   {
   sources.insert(sources.end(), srcs, srcs + count);
   std::sort(sources.begin(), sources.end(), Unix_Program_Cmp);
   }

/*************************************************
* Unix Fast Poll                                 *
*************************************************/
void Unix_EntropySource::do_fast_poll()
   {
   const char* STAT_TARGETS[] = { "/", "/tmp", "/etc/passwd", ".", "..", 0 };

   for(u32bit j = 0; STAT_TARGETS[j]; j++)
      {
      struct stat statbuf;
      clear_mem(&statbuf, 1);
      ::stat(STAT_TARGETS[j], &statbuf);
      add_bytes(&statbuf, sizeof(statbuf));
      }

   add_bytes(::getpid());
   add_bytes(::getppid());

   add_bytes(::getuid());
   add_bytes(::getgid());
   add_bytes(::geteuid());
   add_bytes(::getegid());

   add_bytes(::getpgrp());
   add_bytes(::getsid(0));

   struct ::rusage usage;

   clear_mem(&usage, 1);
   ::getrusage(RUSAGE_SELF, &usage);
   add_bytes(&usage, sizeof(usage));

   ::getrusage(RUSAGE_CHILDREN, &usage);
   add_bytes(&usage, sizeof(usage));
   }

/*************************************************
* Unix Slow Poll                                 *
*************************************************/
void Unix_EntropySource::do_slow_poll()
   {
   const u32bit TRY_TO_GET = 16 * 1024;
   const u32bit MINIMAL_WORKING = 32;

   u32bit got = 0;
   for(u32bit j = 0; j != sources.size(); j++)
      {
      DataSource_Command pipe(sources[j].name_and_args, PATH);
      SecureVector<byte> buffer(DEFAULT_BUFFERSIZE);

      u32bit got_from_src = 0;

      while(!pipe.end_of_data())
         {
         u32bit this_loop = pipe.read(buffer, buffer.size());
         add_bytes(buffer, this_loop);
         got_from_src += this_loop;
         }

      sources[j].working = (got_from_src >= MINIMAL_WORKING) ? true : false;
      got += got_from_src;

      if(got >= TRY_TO_GET)
         break;
      }
   }

}
