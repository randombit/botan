/*
* Win32 Mutex
* (C) 2006 Luca Piccarreta
*     2006-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_MUTEX_WIN32_H__
#define BOTAN_MUTEX_WIN32_H__

#include <botan/internal/mutex.h>

namespace Botan {

/**
* Win32 Mutex Factory
*/
class Win32_Mutex_Factory : public Mutex_Factory
   {
   public:
      Mutex* make();
   };
}

#endif
