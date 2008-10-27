/*************************************************
* Auto Seeded RNG Source File                    *
* (C) 2008 Jack Lloyd                            *
*************************************************/

#include <botan/auto_rng.h>
#include <botan/randpool.h>
#include <botan/parsing.h>
#include <botan/timers.h>
#include <botan/aes.h>
#include <botan/hmac.h>
#include <botan/sha2_32.h>

#if defined(BOTAN_HAS_X931_RNG)
  #include <botan/x931_rng.h>
#endif

#if defined(BOTAN_HAS_TIMER_HARDWARE)
  #include <botan/tm_hard.h>
#endif

#if defined(BOTAN_HAS_TIMER_POSIX)
  #include <botan/tm_posix.h>
#endif

#if defined(BOTAN_HAS_TIMER_UNIX)
  #include <botan/tm_unix.h>
#endif

#if defined(BOTAN_HAS_TIMER_WIN32)
  #include <botan/tm_win32.h>
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_DEVICE)
  #include <botan/es_dev.h>
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_EGD)
  #include <botan/es_egd.h>
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_UNIX)
  #include <botan/es_unix.h>
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_BEOS)
  #include <botan/es_beos.h>
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_CAPI)
  #include <botan/es_capi.h>
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_WIN32)
  #include <botan/es_win32.h>
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_FTW)
  #include <botan/es_ftw.h>
#endif

namespace Botan {

namespace {

/**
* Add any known entropy sources to this RNG
*/
void add_entropy_sources(RandomNumberGenerator* rng)
   {
#if defined(BOTAN_HAS_TIMER_HARDWARE)
   rng->add_entropy_source(new Hardware_Timer);
#endif

#if defined(BOTAN_HAS_TIMER_POSIX)
   rng->add_entropy_source(new POSIX_Timer);
#endif

#if defined(BOTAN_HAS_TIMER_UNIX)
   rng->add_entropy_source(new Unix_Timer);
#endif

#if defined(BOTAN_HAS_TIMER_WIN32)
   rng->add_entropy_source(new Win32_Timer);
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_DEVICE)
   rng->add_entropy_source(
      new Device_EntropySource(
         split_on("/dev/random:/dev/srandom:/dev/urandom", ':')
         )
      );
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_EGD)
   rng->add_entropy_source(
      new EGD_EntropySource(split_on("/var/run/egd-pool:/dev/egd-pool", ':'))
      );
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_CAPI)
   rng->add_entropy_source(new Win32_CAPI_EntropySource);
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_FTW)
   rng->add_entropy_source(new FTW_EntropySource("/proc"));
#endif


#if defined(BOTAN_HAS_ENTROPY_SRC_WIN32)
   rng->add_entropy_source(new Win32_EntropySource);
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_BEOS)
   rng->add_entropy_source(new BeOS_EntropySource);
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_UNIX)
   rng->add_entropy_source(
      new Unix_EntropySource(split_on("/bin:/sbin:/usr/bin:/usr/sbin", ':'))
      );
#endif
   }

}

AutoSeeded_RNG::AutoSeeded_RNG()
   {
   /* Randpool is required for make_rng to work */
   rng = new Randpool(new AES_256, new HMAC(new SHA_256));

   /* If X9.31 is available, wrap the Randpool algorithm in it */
#if defined(BOTAN_HAS_X931_RNG)
   rng = new ANSI_X931_RNG(new AES_256, rng);
#endif

   add_entropy_sources(rng);

   rng->reseed();
   }

}
