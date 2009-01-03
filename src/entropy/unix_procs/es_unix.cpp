/*************************************************
* Unix EntropySource Source File                 *
* (C) 1999-2008 Jack Lloyd                       *
*************************************************/

#include <botan/es_unix.h>
#include <botan/unix_cmd.h>
#include <botan/parsing.h>
#include <botan/xor_buf.h>
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
u32bit Unix_EntropySource::fast_poll(byte buf[], u32bit length)
   {
   if(length == 0)
      return 0;
   length = std::min<u32bit>(length, 32);

   u32bit buf_i = 0;

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
      buf_i = xor_into_buf(buf, buf_i, length, statbuf);
      }

   u32bit ids[] = {
      ::getpid(),
      ::getppid(),
      ::getuid(),
      ::geteuid(),
      ::getegid(),
      ::getpgrp(),
      ::getsid(0)
   };

   for(u32bit i = 0; i != sizeof(ids) / sizeof(ids[0]); ++i)
      buf_i = xor_into_buf(buf, buf_i, length, ids[i]);

   struct ::rusage usage;
   ::getrusage(RUSAGE_SELF, &usage);
   buf_i = xor_into_buf(buf, buf_i, length, usage);

   ::getrusage(RUSAGE_CHILDREN, &usage);
   buf_i = xor_into_buf(buf, buf_i, length, usage);

   return length;
   }

/*************************************************
* Unix Slow Poll                                 *
*************************************************/
u32bit Unix_EntropySource::slow_poll(byte buf[], u32bit length)
   {
   if(length == 0)
      return 0;

   const u32bit MINIMAL_WORKING = 32;

   u32bit total_got = 0;
   u32bit buf_i = 0;

   for(u32bit j = 0; j != sources.size(); j++)
      {
      DataSource_Command pipe(sources[j].name_and_args, PATH);
      SecureVector<byte> buffer(DEFAULT_BUFFERSIZE);

      u32bit got_from_src = 0;

      while(!pipe.end_of_data())
         {
         u32bit this_loop = pipe.read(buffer, buffer.size());
         buf_i = xor_into_buf(buf, buf_i, length, buffer, this_loop);
         got_from_src += this_loop;
         }

      sources[j].working = (got_from_src >= MINIMAL_WORKING) ? true : false;
      total_got += got_from_src;

      if(total_got >= 128*length)
         break;
      }

   return length;
   }

}
