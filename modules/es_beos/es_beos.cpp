/*************************************************
* BeOS EntropySource Source File                 *
* (C) 1999-2008 The Botan Project                *
*************************************************/

#include <botan/es_beos.h>
#include <kernel/OS.h>
#include <kernel/image.h>
#include <interface/InterfaceDefs.h>

namespace Botan {

/*************************************************
* BeOS Fast Poll                                 *
*************************************************/
void BeOS_EntropySource::do_fast_poll()
   {
   system_info info_sys;
   get_system_info(&info_sys);
   add_bytes(&info_sys, sizeof(system_info));

   key_info info_key;
   get_key_info(&info_key);
   add_bytes(&info_key, sizeof(key_info));

   add_bytes(idle_time());
   }

/*************************************************
* BeOS Slow Poll                                 *
*************************************************/
void BeOS_EntropySource::do_slow_poll()
   {
   team_info info_team;
   int32 cookie_team = 0;

   while(get_next_team_info(&cookie_team, &info_team) == B_OK)
      {
      add_bytes(&info_team, sizeof(team_info));

      team_id id = info_team.team;
      int32 cookie = 0;

      thread_info info_thr;
      while(get_next_thread_info(id, &cookie, &info_thr) == B_OK)
         add_bytes(&info_thr, sizeof(thread_info));

      cookie = 0;
      image_info info_img;
      while(get_next_image_info(id, &cookie, &info_img) == B_OK)
         add_bytes(&info_img, sizeof(image_info));

      cookie = 0;
      sem_info info_sem;
      while(get_next_sem_info(id, &cookie, &info_sem) == B_OK)
         add_bytes(&info_sem, sizeof(sem_info));

      cookie = 0;
      area_info info_area;
      while(get_next_area_info(id, &cookie, &info_area) == B_OK)
         add_bytes(&info_area, sizeof(area_info));
      }
   }

}
