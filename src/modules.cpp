/*************************************************
* Module Factory Source File                     *
* (C) 1999-2008 Jack Lloyd                       *
*************************************************/

#include <botan/modules.h>
#include <botan/defalloc.h>
#include <botan/eng_def.h>
#include <botan/timers.h>
#include <botan/parsing.h>

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

#if defined(BOTAN_EXT_ENGINE_GNU_MP)
  #include <botan/eng_gmp.h>
#endif

#if defined(BOTAN_EXT_ENGINE_OPENSSL)
  #include <botan/eng_ossl.h>
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
* Find any usable allocators                     *
*************************************************/
std::vector<Allocator*> Builtin_Modules::allocators() const
   {
   std::vector<Allocator*> allocators;

#if defined(BOTAN_EXT_ALLOC_MMAP)
   allocators.push_back(new MemoryMapping_Allocator);
#endif

   allocators.push_back(new Locking_Allocator);
   allocators.push_back(new Malloc_Allocator);

   return allocators;
   }

/*************************************************
* Return the default allocator                   *
*************************************************/
std::string Builtin_Modules::default_allocator() const
   {
   if(should_lock)
      {
#if defined(BOTAN_EXT_ALLOC_MMAP)
      return "mmap";
#else
      return "locking";
#endif
      }
   else
      return "malloc";
   }

/*************************************************
* Find any usable engines                        *
*************************************************/
std::vector<Engine*> Builtin_Modules::engines() const
   {
   std::vector<Engine*> engines;

   if(use_engines)
      {
#if defined(BOTAN_EXT_ENGINE_GNU_MP)
      engines.push_back(new GMP_Engine);
#endif

#if defined(BOTAN_EXT_ENGINE_OPENSSL)
      engines.push_back(new OpenSSL_Engine);
#endif
      }

   engines.push_back(new Default_Engine);

   return engines;
   }

/*************************************************
* Builtin_Modules Constructor                    *
*************************************************/
Builtin_Modules::Builtin_Modules(const InitializerOptions& args) :
   should_lock(args.secure_memory()),
   use_engines(args.use_engines())
   {
   }

}
