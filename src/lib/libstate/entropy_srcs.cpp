/*
* Global PRNG
* (C) 2008-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/libstate.h>

#if defined(BOTAN_HAS_ENTROPY_SRC_HIGH_RESOLUTION_TIMER)
  #include <botan/internal/hres_timer.h>
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_RDRAND)
  #include <botan/internal/rdrand.h>
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

namespace Botan {

std::vector<std::unique_ptr<EntropySource>> Library_State::entropy_sources()
   {
   std::vector<std::unique_ptr<EntropySource>> sources;

#if defined(BOTAN_HAS_ENTROPY_SRC_HIGH_RESOLUTION_TIMER)
   sources.push_back(std::unique_ptr<EntropySource>(new High_Resolution_Timestamp));
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_RDRAND)
   sources.push_back(std::unique_ptr<EntropySource>(new Intel_Rdrand));
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_UNIX_PROCESS_RUNNER)
   sources.push_back(std::unique_ptr<EntropySource>(new UnixProcessInfo_EntropySource));
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_DEV_RANDOM)
   sources.push_back(std::unique_ptr<EntropySource>(new Device_EntropySource(
      { "/dev/random", "/dev/srandom", "/dev/urandom" }
   )));
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_CAPI)
   sources.push_back(std::unique_ptr<EntropySource>(new Win32_CAPI_EntropySource));
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_PROC_WALKER)
   sources.push_back(std::unique_ptr<EntropySource>(
      new ProcWalking_EntropySource("/proc")));
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_WIN32)
   sources.push_back(std::unique_ptr<EntropySource>(new Win32_EntropySource));
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_BEOS)
   sources.push_back(std::unique_ptr<EntropySource>(new BeOS_EntropySource));
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_UNIX_PROCESS_RUNNER)
   sources.push_back(std::unique_ptr<EntropySource>(
      new Unix_EntropySource(
         { "/bin", "/sbin", "/usr/bin", "/usr/sbin" }
      )));
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_EGD)
   sources.push_back(std::unique_ptr<EntropySource>(
      new EGD_EntropySource({ "/var/run/egd-pool", "/dev/egd-pool" })
      ));
#endif

   return sources;
   }

void Library_State::poll_available_sources(class Entropy_Accumulator& accum)
   {
   std::lock_guard<std::mutex> lock(m_entropy_src_mutex);

   const size_t poll_bits = accum.desired_remaining_bits();

   if(m_sources.empty())
      throw std::runtime_error("No entropy sources enabled at build time, poll failed");

   size_t poll_attempt = 0;

   while(!accum.polling_goal_achieved() && poll_attempt < poll_bits)
      {
      const size_t src_idx = poll_attempt % m_sources.size();
      m_sources[src_idx]->poll(accum);
      ++poll_attempt;
      }
   }

}

