/*************************************************
* Win32 Mutex Header File                        *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_EXT_MUTEX_WIN32_H__
#define BOTAN_EXT_MUTEX_WIN32_H__

#include <botan/mutex.h>

namespace Botan {

/*************************************************
* Win32 Mutex Factory                            *
*************************************************/
class Win32_Mutex_Factory : public Mutex_Factory
   {
   public:
      Mutex* make();
   };
}

#endif
