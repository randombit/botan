/*
* Qt Mutex
* (C) 2004-2007 Justin Karneges
*     2004-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_MUTEX_QT_H__
#define BOTAN_MUTEX_QT_H__

#include <botan/mutex.h>

namespace Botan {

/*
* Qt Mutex
*/
class BOTAN_DLL Qt_Mutex_Factory : public Mutex_Factory
   {
   public:
      Mutex* make();
   };

}

#endif
