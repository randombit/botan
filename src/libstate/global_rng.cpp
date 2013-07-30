/*
* Global PRNG
* (C) 2008-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/libstate.h>
#include <botan/internal/mutex.h>

#if defined(BOTAN_HAS_RANDPOOL)
  #include <botan/randpool.h>
#endif

#if defined(BOTAN_HAS_HMAC_RNG)
  #include <botan/hmac_rng.h>
#endif

#if defined(BOTAN_HAS_X931_RNG)
  #include <botan/x931_rng.h>
#endif

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

#if defined(BOTAN_HAS_ENTROPY_SRC_UNIX)
  #include <botan/internal/es_unix.h>
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

#if defined(BOTAN_HAS_ENTROPY_SRC_FTW)
  #include <botan/internal/es_ftw.h>
#endif

namespace Botan {

namespace {

/**
* Add any known entropy sources to this RNG
*/
void add_entropy_sources(RandomNumberGenerator* rng)
   {
#if defined(BOTAN_HAS_ENTROPY_SRC_HIGH_RESOLUTION_TIMER)
   rng->add_entropy_source(new High_Resolution_Timestamp);
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_RDRAND)
   rng->add_entropy_source(new Intel_Rdrand);
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_DEV_RANDOM)
   rng->add_entropy_source(
      new Device_EntropySource(
         split_on("/dev/urandom:/dev/srandom:/dev/random", ':')
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

class Serialized_PRNG : public RandomNumberGenerator
   {
   public:
      void randomize(byte out[], size_t len)
         {
         Mutex_Holder lock(mutex);
         rng->randomize(out, len);
         }

      bool is_seeded() const
         {
         Mutex_Holder lock(mutex);
         return rng->is_seeded();
         }

      void clear()
         {
         Mutex_Holder lock(mutex);
         rng->clear();
         }

      std::string name() const
         {
         Mutex_Holder lock(mutex);
         return rng->name();
         }

      void reseed(size_t poll_bits)
         {
         Mutex_Holder lock(mutex);
         rng->reseed(poll_bits);
         }

      void add_entropy_source(EntropySource* es)
         {
         Mutex_Holder lock(mutex);
         rng->add_entropy_source(es);
         }

      void add_entropy(const byte in[], size_t len)
         {
         Mutex_Holder lock(mutex);
         rng->add_entropy(in, len);
         }

      // We do not own the mutex; Library_State does
      Serialized_PRNG(RandomNumberGenerator* r, Mutex* m) :
         mutex(m), rng(r) {}

      ~Serialized_PRNG() { delete rng; }
   private:
      Mutex* mutex;
      RandomNumberGenerator* rng;
   };

}

RandomNumberGenerator* Library_State::make_global_rng(Algorithm_Factory& af,
                                                      Mutex* mutex)
   {
   RandomNumberGenerator* rng = 0;

#if defined(BOTAN_HAS_HMAC_RNG)

   rng = new HMAC_RNG(af.make_mac("HMAC(SHA-512)"),
                      af.make_mac("HMAC(SHA-256)"));

#elif defined(BOTAN_HAS_RANDPOOL)

   rng = new Randpool(af.make_block_cipher("AES-256"),
                      af.make_mac("HMAC(SHA-256)"));

#endif

   if(!rng)
      throw Internal_Error("No usable RNG found enabled in build");

   /* If X9.31 is available, use it to wrap the other RNG as a failsafe */
#if defined(BOTAN_HAS_X931_RNG)

   rng = new ANSI_X931_RNG(af.make_block_cipher("AES-256"), rng);

#endif

   add_entropy_sources(rng);

   rng->reseed(256);

   return new Serialized_PRNG(rng, mutex);
   }

}
