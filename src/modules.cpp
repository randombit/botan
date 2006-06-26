/*************************************************
* Module Factory Source File                     *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/modules.h>
#include <botan/libstate.h>
#include <botan/defalloc.h>
#include <botan/eng_def.h>
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

/*************************************************
* Return a mutex factory, if available           *
*************************************************/
Mutex_Factory* Builtin_Modules::mutex_factory() const
   {
#if defined(BOTAN_EXT_MUTEX_PTHREAD)
   return new Pthread_Mutex_Factory;
#elif defined(BOTAN_EXT_MUTEX_WIN32)
   return new Win32_Mutex_Factory;
#elif defined(BOTAN_EXT_MUTEX_QT)
   return new Qt_Mutex_Factory;
#else
   return 0;
#endif
   }

/*************************************************
* Find a high resolution timer, if possible      *
*************************************************/
Timer* Builtin_Modules::timer() const
   {
#if defined(BOTAN_EXT_TIMER_HARDWARE)
   return new Hardware_Timer;
#elif defined(BOTAN_EXT_TIMER_POSIX)
   return new POSIX_Timer;
#elif defined(BOTAN_EXT_TIMER_UNIX)
   return new Unix_Timer;
#elif defined(BOTAN_EXT_TIMER_WIN32)
   return new Win32_Timer;
#else
   return 0;
#endif
   }

/*************************************************
* Set any usable allocators                      *
*************************************************/
void Builtin_Modules::set_allocators(Library_State& state,
                                     bool secure_mem) const
   {
   state.add_allocator(new Malloc_Allocator, !secure_mem);

   state.add_allocator(new Locking_Allocator, secure_mem);

#if defined(BOTAN_EXT_ALLOC_MMAP)
   state.add_allocator(new MemoryMapping_Allocator, secure_mem);
#endif
   }

/*************************************************
* Register any usable entropy sources            *
*************************************************/
void Builtin_Modules::set_entropy_sources(Library_State& state) const
   {
   state.add_entropy_source(new File_EntropySource);

#if defined(BOTAN_EXT_ENTROPY_SRC_AEP)
   state.add_entropy_source(new AEP_EntropySource);
#endif

#if defined(BOTAN_EXT_ENTROPY_SRC_EGD)
   state.add_entropy_source(new EGD_EntropySource);
#endif

#if defined(BOTAN_EXT_ENTROPY_SRC_CAPI)
   state.add_entropy_source(new Win32_CAPI_EntropySource);
#endif

#if defined(BOTAN_EXT_ENTROPY_SRC_WIN32)
   state.add_entropy_source(new Win32_EntropySource);
#endif

#if defined(BOTAN_EXT_ENTROPY_SRC_UNIX)
   state.add_entropy_source(new Unix_EntropySource);
#endif

#if defined(BOTAN_EXT_ENTROPY_SRC_BEOS)
   state.add_entropy_source(new BeOS_EntropySource);
#endif

#if defined(BOTAN_EXT_ENTROPY_SRC_FTW)
   state.add_entropy_source(new FTW_EntropySource);
#endif
   }

/*************************************************
* Find any usable engines                        *
*************************************************/
void Builtin_Modules::set_engines(Library_State& state,
                                  bool use_engines) const
   {
   if(use_engines)
      {
#if defined(BOTAN_EXT_ENGINE_AEP)
      state.add_engine(new AEP_Engine);
#endif

#if defined(BOTAN_EXT_ENGINE_GNU_MP)
      state.add_engine(new GMP_Engine);
#endif

#if defined(BOTAN_EXT_ENGINE_OPENSSL)
      state.add_engine(new OpenSSL_Engine);
#endif
      }

   state.add_engine(new Default_Engine);
   }

}
