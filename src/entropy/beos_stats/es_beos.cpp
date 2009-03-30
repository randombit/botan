/**
* BeOS EntropySource
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/es_beos.h>

#include <kernel/OS.h>
#include <kernel/image.h>
#include <interface/InterfaceDefs.h>

namespace Botan {

/**
* BeOS entropy poll
*/
void BeOS_EntropySource::poll(Entropy_Accumulator& accum)
   {
   system_info info_sys;
   get_system_info(&info_sys);
   accum.add(info_sys, 2);

   key_info info_key; // current state of the keyboard
   get_key_info(&info_key);
   accum.add(info_key, 0);

   accum.add(idle_time(), 0);

   team_info info_team;
   int32 cookie_team = 0;

   while(get_next_team_info(&cookie_team, &info_team) == B_OK)
      {
      accum.add(info_team, 2);

      team_id id = info_team.team;
      int32 cookie = 0;

      thread_info info_thr;
      while(get_next_thread_info(id, &cookie, &info_thr) == B_OK)
         accum.add(info_thr, 1);

      cookie = 0;
      image_info info_img;
      while(get_next_image_info(id, &cookie, &info_img) == B_OK)
         accum.add(info_img, 1);

      cookie = 0;
      sem_info info_sem;
      while(get_next_sem_info(id, &cookie, &info_sem) == B_OK)
         accum.add(info_sem, 1);

      cookie = 0;
      area_info info_area;
      while(get_next_area_info(id, &cookie, &info_area) == B_OK)
         accum.add(info_area, 2);

      if(accum.polling_goal_achieved())
         break;
      }
   }

}
