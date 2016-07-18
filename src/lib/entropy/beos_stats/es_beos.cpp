/*
* BeOS EntropySource
* (C) 1999-2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/es_beos.h>

#include <kernel/OS.h>
#include <kernel/image.h>
#include <interface/InterfaceDefs.h>

namespace Botan {

/**
* BeOS entropy poll
*/
size_t BeOS_EntropySource::poll(RandomNumberGenerator& rng)
   {
   size_t bits = 0;

   system_info info_sys;
   get_system_info(&info_sys);
   rng.add_entropy_T(info_sys);

   key_info info_key; // current state of the keyboard
   get_key_info(&info_key);
   rng.add_entropy_T(info_key);

   team_info info_team;
   int32 cookie_team = 0;

   while(get_next_team_info(&cookie_team, &info_team) == B_OK)
      {
      rng.add_entropy_T(info_team);

      team_id id = info_team.team;
      int32 cookie = 0;

      thread_info info_thr;
      while(get_next_thread_info(id, &cookie, &info_thr) == B_OK)
         rng.add_entropy_T(info_thr);

      cookie = 0;
      image_info info_img;
      while(get_next_image_info(id, &cookie, &info_img) == B_OK)
         rng.add_entropy_T(info_img);

      cookie = 0;
      sem_info info_sem;
      while(get_next_sem_info(id, &cookie, &info_sem) == B_OK)
         rng.add_entropy_T(info_sem);

      cookie = 0;
      area_info info_area;
      while(get_next_area_info(id, &cookie, &info_area) == B_OK)
         rng.add_entropy_T(info_area);

      bits += 32;
      }

   return bits;
   }

}
