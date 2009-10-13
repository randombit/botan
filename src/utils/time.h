/*
* Time Functions
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_TIME_OPS_H__
#define BOTAN_TIME_OPS_H__

#include <ctime>

namespace Botan {

/*
* Convert a time_t value to a struct tm
*/
inline std::tm time_t_to_tm(u64bit time_int)
   {
   std::time_t time_val = static_cast<std::time_t>(time_int);

   std::tm* tm_p = std::gmtime(&time_val);
   if (tm_p == 0)
      throw Encoding_Error("time_t_to_tm could not convert");
   return (*tm_p);
   }

/**
* Get the system clock
*/
inline u64bit system_time()
   {
   return static_cast<u64bit>(std::time(0));
   }

}


#endif
