/*
* Auto Seeded RNG
* (C) 2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/auto_rng.h>
#include <botan/parsing.h>
#include <botan/timer.h>
#include <botan/hmac.h>
#include <botan/sha2_32.h>
#include <botan/sha2_64.h>

#if defined(BOTAN_HAS_RANDPOOL)
  #include <botan/randpool.h>
#endif

#if defined(BOTAN_HAS_HMAC_RNG)
  #include <botan/hmac_rng.h>
#endif

#if defined(BOTAN_HAS_X931_RNG)
  #include <botan/x931_rng.h>
#endif

#if defined(BOTAN_HAS_AES)
  #include <botan/aes.h>
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

   // Add a high resolution timer, if available
#if defined(BOTAN_HAS_TIMER_HARDWARE)
   rng->add_entropy_source(new Hardware_Timer);
#elif defined(BOTAN_HAS_TIMER_POSIX)
   rng->add_entropy_source(new POSIX_Timer);
#elif defined(BOTAN_HAS_TIMER_UNIX)
   rng->add_entropy_source(new Unix_Timer);
#elif defined(BOTAN_HAS_TIMER_WIN32)
   rng->add_entropy_source(new Win32_Timer);
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_DEVICE)
   rng->add_entropy_source(
      new Device_EntropySource(
         split_on("/dev/urandom:/dev/random:/dev/srandom", ':')
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

AutoSeeded_RNG::AutoSeeded_RNG(u32bit poll_bits)
   {
   rng = 0;

#if defined(BOTAN_HAS_HMAC_RNG)
   rng = new HMAC_RNG(new HMAC(new SHA_512), new HMAC(new SHA_256));
#elif defined(BOTAN_HAS_RANDPOOL) && defined(BOTAN_HAS_AES)
   rng = new Randpool(new AES_256, new HMAC(new SHA_256));
#endif

   if(!rng)
      throw Algorithm_Not_Found("No usable RNG found enabled in build");

   /* If X9.31 is available, use it to wrap the other RNG as a failsafe */
#if defined(BOTAN_HAS_X931_RNG) && defined(BOTAN_HAS_AES)
   rng = new ANSI_X931_RNG(new AES_256, rng);
#endif

   add_entropy_sources(rng);

   rng->reseed(poll_bits);
   }

}
