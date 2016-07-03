/*
* Entropy Source Polling
* (C) 2008-2010,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/entropy_src.h>
#include <botan/rng.h>

#if defined(BOTAN_HAS_ENTROPY_SRC_HIGH_RESOLUTION_TIMER)
  #include <botan/internal/hres_timer.h>
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_RDRAND)
  #include <botan/internal/rdrand.h>
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_RDSEED)
  #include <botan/internal/rdseed.h>
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_DEV_RANDOM)
  #include <botan/internal/dev_random.h>
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_EGD)
  #include <botan/internal/es_egd.h>
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_UNIX_PROCESS_RUNNER)
  #include <botan/internal/unix_procs.h>
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_BEOS)
  #include <botan/internal/es_beos.h>
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_CAPI)
  #include <botan/internal/es_capi.h>
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_WIN32)
  #include <botan/internal/es_win32.h>
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_PROC_WALKER)
  #include <botan/internal/proc_walk.h>
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_DARWIN_SECRANDOM)
  #include <botan/internal/darwin_secrandom.h>
#endif

namespace Botan {

std::unique_ptr<Entropy_Source> Entropy_Source::create(const std::string& name)
   {
   if(name == "timestamp")
      {
#if defined(BOTAN_HAS_ENTROPY_SRC_HIGH_RESOLUTION_TIMER)
   return std::unique_ptr<Entropy_Source>(new High_Resolution_Timestamp);
#endif
      }

   if(name == "rdrand")
      {
#if defined(BOTAN_HAS_ENTROPY_SRC_RDRAND)
      return std::unique_ptr<Entropy_Source>(new Intel_Rdrand);
#endif
      }

   if(name == "rdseed")
      {
#if defined(BOTAN_HAS_ENTROPY_SRC_RDSEED)
      return std::unique_ptr<Entropy_Source>(new Intel_Rdseed);
#endif
      }

   if(name == "proc_info")
      {
#if defined(BOTAN_HAS_ENTROPY_SRC_UNIX_PROCESS_RUNNER)
   return std::unique_ptr<Entropy_Source>(new UnixProcessInfo_EntropySource);
#endif
      }

   if(name == "darwin_secrandom")
      {
#if defined(BOTAN_HAS_ENTROPY_SRC_DARWIN_SECRANDOM)
      return std::unique_ptr<Entropy_Source>(new Darwin_SecRandom);
#endif
      }

   if(name == "dev_random")
      {
#if defined(BOTAN_HAS_ENTROPY_SRC_DEV_RANDOM)
      return std::unique_ptr<Entropy_Source>(new Device_EntropySource(BOTAN_SYSTEM_RNG_POLL_DEVICES));
      }

   if(name == "win32_cryptoapi")
      {
#elif defined(BOTAN_HAS_ENTROPY_SRC_CAPI)
      return std::unique_ptr<Entropy_Source>(new Win32_CAPI_EntropySource);
#endif
      }

   if(name == "proc_walk")
      {
#if defined(BOTAN_HAS_ENTROPY_SRC_PROC_WALKER)
      return std::unique_ptr<Entropy_Source>(new ProcWalking_EntropySource("/proc"));
#endif
      }

   if(name == "system_stats")
      {
#if defined(BOTAN_HAS_ENTROPY_SRC_WIN32)
      return std::unique_ptr<Entropy_Source>(new Win32_EntropySource);
#elif defined(BOTAN_HAS_ENTROPY_SRC_BEOS)
   return std::unique_ptr<Entropy_Source>(new BeOS_EntropySource);
#endif
      }

   if(name == "unix_procs")
      {
#if defined(BOTAN_HAS_ENTROPY_SRC_UNIX_PROCESS_RUNNER)
      return std::unique_ptr<Entropy_Source>(new Unix_EntropySource(BOTAN_ENTROPY_SAFE_PATHS));
#endif
      }

   if(name == "egd")
      {
#if defined(BOTAN_HAS_ENTROPY_SRC_EGD)
      return std::unique_ptr<Entropy_Source>(new EGD_EntropySource(BOTAN_ENTROPY_EGD_PATHS));
#endif
      }

   return std::unique_ptr<Entropy_Source>();
   }

void Entropy_Sources::add_source(std::unique_ptr<Entropy_Source> src)
   {
   if(src.get())
      {
      m_srcs.push_back(src.release());
      }
   }

std::vector<std::string> Entropy_Sources::enabled_sources() const
   {
   std::vector<std::string> sources;
   for(size_t i = 0; i != m_srcs.size(); ++i)
      {
      sources.push_back(m_srcs[i]->name());
      }
   return sources;
   }

size_t Entropy_Sources::poll(RandomNumberGenerator& rng,
                             size_t poll_bits,
                             std::chrono::milliseconds timeout)
   {
   typedef std::chrono::system_clock clock;

   auto deadline = clock::now() + timeout;

   size_t bits_collected = 0;

   for(Entropy_Source* src : m_srcs)
      {
      bits_collected += src->poll(rng);

      if (bits_collected >= poll_bits || clock::now() > deadline)
         break;
      }

   return bits_collected;
   }

size_t Entropy_Sources::poll_just(RandomNumberGenerator& rng, const std::string& the_src)
   {
   for(size_t i = 0; i != m_srcs.size(); ++i)
      {
      if(m_srcs[i]->name() == the_src)
         {
         return m_srcs[i]->poll(rng);
         }
      }

   return 0;
   }

Entropy_Sources::Entropy_Sources(const std::vector<std::string>& sources)
   {
   for(auto&& src_name : sources)
      {
      add_source(Entropy_Source::create(src_name));
      }
   }

Entropy_Sources::~Entropy_Sources()
   {
   for(size_t i = 0; i != m_srcs.size(); ++i)
      {
      delete m_srcs[i];
      m_srcs[i] = nullptr;
      }
   m_srcs.clear();
   }

Entropy_Sources& Entropy_Sources::global_sources()
   {
   static Entropy_Sources global_entropy_sources(BOTAN_ENTROPY_DEFAULT_SOURCES);

   return global_entropy_sources;
   }

}

