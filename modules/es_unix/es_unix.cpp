/*************************************************
* Unix EntropySource Source File                 *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/es_unix.h>
#include <botan/unix_cmd.h>
#include <botan/parsing.h>
#include <botan/config.h>
#include <algorithm>

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
Unix_EntropySource::Unix_EntropySource()
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
   gather(2*1024);
   }

/*************************************************
* Unix Slow Poll                                 *
*************************************************/
void Unix_EntropySource::do_slow_poll()
   {
   gather(16*1024);
   }

/*************************************************
* Gather Entropy From Several Unix_Programs      *
*************************************************/
void Unix_EntropySource::gather(u32bit target_amount)
   {
   const u32bit MINIMAL_WORKING = 32;

   u32bit got = 0;
   for(u32bit j = 0; j != sources.size(); j++)
      {
      add_timestamp();

      got += gather_from(sources[j]);
      sources[j].working = (got >= MINIMAL_WORKING) ? true : false;

      if(got >= target_amount)
         break;
      }
   }

/*************************************************
* Gather entropy from a Unix program             *
*************************************************/
u32bit Unix_EntropySource::gather_from(const Unix_Program& prog)
   {
   const std::string BASE_PATH = "/bin:/sbin:/usr/bin:/usr/sbin";
   const std::string EXTRA_PATH = global_config().option("rng/unix_path");

   std::string PATH = BASE_PATH;
   if(EXTRA_PATH != "")
      PATH += ':' + EXTRA_PATH;

   DataSource_Command pipe(prog.name_and_args, PATH);
   if(pipe.end_of_data())
      return 0;

   u32bit got = 0;
   SecureVector<byte> buffer(DEFAULT_BUFFERSIZE);

   while(!pipe.end_of_data())
      {
      u32bit this_loop = pipe.read(buffer, buffer.size());
      add_bytes(buffer, this_loop);
      got += this_loop;
      }

   return got;
   }

}
