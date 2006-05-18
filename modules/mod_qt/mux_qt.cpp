/*************************************************
* Qt Thread Mutex Source File                    *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/mux_qt.h>
#include <botan/exceptn.h>
#include <qmutex.h>

#if !defined(QT_THREAD_SUPPORT)
   #error Your version of Qt does not support threads or mutexes
#endif

namespace Botan {

/*************************************************
* Wrapper Type for Qt Thread Mutex               *
*************************************************/
struct mutex_wrapper
   {
   QMutex m;
   };

/*************************************************
* Constructor                                    *
*************************************************/
Qt_Mutex::Qt_Mutex()
   {
   mutex = new mutex_wrapper;
   }

/*************************************************
* Destructor                                     *
*************************************************/
Qt_Mutex::~Qt_Mutex()
   {
   delete mutex;
   }

/*************************************************
* Lock the Mutex                                 *
*************************************************/
void Qt_Mutex::lock()
   {
   mutex->m.lock();
   }

/*************************************************
* Unlock the Mutex                               *
*************************************************/
void Qt_Mutex::unlock()
   {
   mutex->m.unlock();
   }

}
