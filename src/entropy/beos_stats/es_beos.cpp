/**
* BeOS EntropySource Source File
* (C) 1999-2008 Jack Lloyd
*/

#include <botan/es_beos.h>
#include <botan/xor_buf.h>

#include <kernel/OS.h>
#include <kernel/image.h>
#include <interface/InterfaceDefs.h>

namespace Botan {

/**
* BeOS Fast Poll
*/
u32bit BeOS_EntropySource::fast_poll(byte buf[], u32bit length)
   {
   if(length == 0)
      return 0;
   length = std::min<u32bit>(length, 32);

   u32bit buf_i = 0;

   system_info info_sys;
   get_system_info(&info_sys);
   buf_i = xor_into_buf(buf, buf_i, length, info_sys);

   key_info info_key;
   get_key_info(&info_key);
   buf_i = xor_into_buf(buf, buf_i, length, key_info);

   buf_i = xor_into_buf(buf, buf_i, length, idle_time());

   return length;
   }

/**
* BeOS slow poll
*/
u32bit BeOS_EntropySource::slow_poll(byte buf[], u32bit length)
   {
   if(length == 0)
      return 0;

   u32bit buf_i = 0;
   team_info info_team;
   int32 cookie_team = 0;

   while(get_next_team_info(&cookie_team, &info_team) == B_OK)
      {
      buf_i = xor_into_buf(buf, buf_i, length, info_team);

      team_id id = info_team.team;
      int32 cookie = 0;

      thread_info info_thr;
      while(get_next_thread_info(id, &cookie, &info_thr) == B_OK)
         buf_i = xor_into_buf(buf, buf_i, length, info_thr);

      cookie = 0;
      image_info info_img;
      while(get_next_image_info(id, &cookie, &info_img) == B_OK)
         buf_i = xor_into_buf(buf, buf_i, length, info_img);

      cookie = 0;
      sem_info info_sem;
      while(get_next_sem_info(id, &cookie, &info_sem) == B_OK)
         buf_i = xor_into_buf(buf, buf_i, length, info_sem);

      cookie = 0;
      area_info info_area;
      while(get_next_area_info(id, &cookie, &info_area) == B_OK)
         buf_i = xor_into_buf(buf, buf_i, length, info_area);
      }

   return length;
   }

}
