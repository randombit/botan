/*************************************************
* Module Factory Source File                     *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/modules.h>
#include <botan/es_file.h>

#if defined(BOTAN_EXT_MUTEX_PTHREAD)
  #include <botan/mux_pthr.h>
#elif defined(BOTAN_EXT_MUTEX_WIN32)
  #include <botan/mux_win32.h>
#elif defined(BOTAN_EXT_MUTEX_QT)
  #include <botan/mux_qt.h>
#endif

#if defined(BOTAN_EXT_ALLOC_MMAP)
  #include <botan/mmap_mem.h>
#endif

#if defined(BOTAN_EXT_TIMER_HARDWARE)
  #include <botan/tm_hard.h>
#elif defined(BOTAN_EXT_TIMER_POSIX)
  #include <botan/tm_posix.h>
#elif defined(BOTAN_EXT_TIMER_UNIX)
  #include <botan/tm_unix.h>
#elif defined(BOTAN_EXT_TIMER_WIN32)
  #include <botan/tm_win32.h>
#endif

#if defined(BOTAN_EXT_ENGINE_AEP)
  #include <botan/eng_aep.h>
#endif

#if defined(BOTAN_EXT_ENGINE_GNU_MP)
  #include <botan/eng_gmp.h>
#endif

#if defined(BOTAN_EXT_ENGINE_OPENSSL)
  #include <botan/eng_ossl.h>
#endif

#if defined(BOTAN_EXT_ENTROPY_SRC_AEP)
  #include <botan/es_aep.h>
#endif

#if defined(BOTAN_EXT_ENTROPY_SRC_EGD)
  #include <botan/es_egd.h>
#endif

#if defined(BOTAN_EXT_ENTROPY_SRC_UNIX)
  #include <botan/es_unix.h>
#endif

#if defined(BOTAN_EXT_ENTROPY_SRC_BEOS)
  #include <botan/es_beos.h>
#endif

#if defined(BOTAN_EXT_ENTROPY_SRC_CAPI)
  #include <botan/es_capi.h>
#endif

#if defined(BOTAN_EXT_ENTROPY_SRC_WIN32)
  #include <botan/es_win32.h>
#endif

#if defined(BOTAN_EXT_ENTROPY_SRC_FTW)
  #include <botan/es_ftw.h>
#endif

namespace Botan {

namespace Modules {

/*************************************************
* Register a mutex type, if possible             *
*************************************************/
Mutex_Factory* get_mutex_factory()
   {
#if defined(BOTAN_EXT_MUTEX_PTHREAD)
   return new Pthread_Mutex_Factory;
#elif defined(BOTAN_EXT_MUTEX_WIN32)
   return new Win32_Mutex_Factory;
#elif defined(BOTAN_EXT_MUTEX_QT)
   return new Qt_Mutex_Factory;
#endif

   return 0;
   }

/*************************************************
* Find a high resolution timer, if possible      *
*************************************************/
Timer* get_timer()
   {
#if defined(BOTAN_EXT_TIMER_HARDWARE)
   return new Hardware_Timer;
#elif defined(BOTAN_EXT_TIMER_POSIX)
   return new POSIX_Timer;
#elif defined(BOTAN_EXT_TIMER_UNIX)
   return new Unix_Timer;
#elif defined(BOTAN_EXT_TIMER_WIN32)
   return new Win32_Timer;
#endif

   return 0;
   }

/*************************************************
* Find any usable allocators                     *
*************************************************/
std::map<std::string, Allocator*> get_allocators()
   {
   std::map<std::string, Allocator*> allocators;

#if defined(BOTAN_EXT_ALLOC_MMAP)
   allocators["mmap"] = new MemoryMapping_Allocator;
#endif

   return allocators;
   }

/*************************************************
* Register any usable entropy sources            *
*************************************************/
std::vector<EntropySource*> get_entropy_sources()
   {
   std::vector<EntropySource*> sources;

   sources.push_back(new File_EntropySource);

#if defined(BOTAN_EXT_ENTROPY_SRC_AEP)
   sources.push_back(new AEP_EntropySource);
#endif

#if defined(BOTAN_EXT_ENTROPY_SRC_EGD)
   sources.push_back(new EGD_EntropySource);
#endif

#if defined(BOTAN_EXT_ENTROPY_SRC_CAPI)
   sources.push_back(new Win32_CAPI_EntropySource);
#endif

#if defined(BOTAN_EXT_ENTROPY_SRC_WIN32)
   sources.push_back(new Win32_EntropySource);
#endif

#if defined(BOTAN_EXT_ENTROPY_SRC_UNIX)
   sources.push_back(new Unix_EntropySource);
#endif

#if defined(BOTAN_EXT_ENTROPY_SRC_BEOS)
   sources.push_back(new BeOS_EntropySource);
#endif

#if defined(BOTAN_EXT_ENTROPY_SRC_FTW)
   sources.push_back(new FTW_EntropySource);
#endif

   return sources;
   }

/*************************************************
* Find any usable engines                        *
*************************************************/
std::vector<Engine*> get_engines()
   {
   std::vector<Engine*> engines;

#if defined(BOTAN_EXT_ENGINE_AEP)
   engines.push_back(new AEP_Engine);
#endif

#if defined(BOTAN_EXT_ENGINE_GNU_MP)
   engines.push_back(new GMP_Engine);
#endif

#if defined(BOTAN_EXT_ENGINE_OPENSSL)
   engines.push_back(new OpenSSL_Engine);
#endif

   return engines;
   }

}

}
