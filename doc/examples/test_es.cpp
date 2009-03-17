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

class Saver_Of_Bytes : public Entropy_Accumulator
   {
   public:
      Saver_Of_Bytes(u32bit bits) :
         Entropy_Accumulator(bits), outbuf(64), written(0) {}

      void add_bytes(const byte in[], u32bit length)
         {
         for(size_t i = 0; i != length; ++i)
            outbuf[i % outbuf.size()] ^= in[i];

         written += length;
         }

      void trunc() { if(written < 64) outbuf.resize(written); }

      std::vector<byte> outbuf;
      u32bit written;
   };

void test_entropy_source(EntropySource* es)
   {
   // sometimes iostreams really is just a pain

   printf("Polling '%s':\n", es->name().c_str());

   Saver_Of_Bytes accum(128);

   es->poll(accum);

   accum.trunc();

   printf("Got %d bytes\n", accum.written);
   for(size_t i = 0; i != accum.outbuf.size(); ++i)
      printf("%02X", accum.outbuf[i]);
   printf("\n");

   delete es;
   }

int main()
   {
   Botan::LibraryInitializer init;

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
