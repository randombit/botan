#include <botan/botan.h>
#include <stdio.h>

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


using namespace Botan;

void test_entropy_source(EntropySource* es)
   {
   // sometimes iostreams really is just a pain

   // upper buffer size of 96 to match HMAC_RNG's
   byte buf[96] = { 0 };

   printf("Polling '%s':\n", es->name().c_str());

   printf("  Fast poll... ");
   u32bit fast_poll_got = es->fast_poll(buf, sizeof(buf));
   printf("got %d bytes: ", fast_poll_got);
   for(u32bit i = 0; i != fast_poll_got; ++i)
      printf("%02X", buf[i]);
   printf("\n");

   printf("  Slow poll... ");
   u32bit slow_poll_got = es->slow_poll(buf, sizeof(buf));
   printf("got %d bytes: ", slow_poll_got);
   for(u32bit i = 0; i != slow_poll_got; ++i)
      printf("%02X", buf[i]);
   printf("\n");

   delete es;
   }

int main()
   {
   LibraryInitializer init;

#if defined(BOTAN_HAS_ENTROPY_SRC_DEVICE)
   test_entropy_source(
      new Device_EntropySource(
         split_on("/dev/random:/dev/srandom:/dev/urandom", ':')
         )
      );
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_EGD)
   test_entropy_source(
      new EGD_EntropySource(split_on("/var/run/egd-pool:/dev/egd-pool", ':'))
      );
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_CAPI)
   test_entropy_source(new Win32_CAPI_EntropySource);
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_FTW)
   test_entropy_source(new FTW_EntropySource("/proc"));
#endif


#if defined(BOTAN_HAS_ENTROPY_SRC_WIN32)
   test_entropy_source(new Win32_EntropySource);
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_BEOS)
   test_entropy_source(new BeOS_EntropySource);
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_UNIX)
   test_entropy_source(
      new Unix_EntropySource(split_on("/bin:/sbin:/usr/bin:/usr/sbin", ':'))
      );
#endif
   }
