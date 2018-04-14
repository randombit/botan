/*
 * XMSS Tools
 * (C) 2017 Matthias Gierlings
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/xmss_tools.h>

namespace Botan {

#if defined(BOTAN_TARGET_OS_HAS_THREADS)

size_t XMSS_Tools::max_threads()
   {
   static const size_t threads { bench_threads() };
   return threads;
   }

size_t XMSS_Tools::bench_threads()
   {
   const size_t hardware_concurrency = std::thread::hardware_concurrency();

   if(hardware_concurrency <= 1)
      {
      return 1;
      }
   const size_t BENCH_ITERATIONS = 1000;
   std::vector<std::thread> threads;
   threads.reserve(hardware_concurrency);
   std::vector<std::chrono::nanoseconds> durations;

   std::vector<size_t> concurrency { hardware_concurrency,
                                     hardware_concurrency / 2 };

   for(const auto& cc : concurrency)
      {
      std::vector<XMSS_Hash> hash(hardware_concurrency,
                                  XMSS_Hash("SHA-256"));

      const std::vector<uint8_t> buffer(hash[0].output_length());
      std::vector<secure_vector<uint8_t>> data(
          hardware_concurrency,
          secure_vector<uint8_t>(hash[0].output_length()));
      auto start = std::chrono::high_resolution_clock::now();
      for(size_t i = 0; i < cc; ++i)
         {
         auto& hs = hash[i];
         auto& d = data[i];

         const size_t n_iters = BENCH_ITERATIONS * (hardware_concurrency / cc);
         threads.emplace_back(std::thread([n_iters, &hs, &d]()
               {
               for(size_t n = 0; n < n_iters; n++)
                  {
                  hs.h(d, d, d);
                  }
               }
            ));
         }
      durations.emplace_back(std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now() - start));
      for(auto& t : threads)
         {
         t.join();
         }
      threads.clear();
      }

      if(durations[0].count() < durations[1].count())
         {
#if defined(BOTAN_TEST_MODE)
         return 4;
#else
         return concurrency[0];
#endif
         }
      else
         {
#if defined(BOTAN_TEST_MODE)
         return 4;
#else
         return concurrency[1];
#endif
         }
  }

#endif

}

