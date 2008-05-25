/*************************************************
* Qt Thread Mutex Source File                    *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/mux_qt.h>
#include <qmutex.h>

#if !defined(QT_THREAD_SUPPORT)
   #error Your version of Qt does not support threads or mutexes
#endif

namespace Botan {

/*************************************************
* Qt Mutex Factory                               *
*************************************************/
std::auto_ptr<Mutex> Qt_Mutex_Factory::make()
   {
   class Qt_Mutex : public Mutex
      {
      public:
         void lock() { mutex.lock(); }
         void unlock() { mutex.unlock(); }
      private:
         QMutex mutex;
      };

   return std::auto_ptr<Mutex>(new Qt_Mutex());
   }

}
