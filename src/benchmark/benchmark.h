/**
* Runtime benchmarking
* (C) 2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_RUNTIME_BENCHMARK_H__
#define BOTAN_RUNTIME_BENCHMARK_H__

#include <botan/algo_factory.h>
#include <botan/timer.h>
#include <botan/rng.h>
#include <map>
#include <string>

/**
* Choose some sort of default timer implementation to use, since some
* (like hardware tick counters and current Win32 timer) are not
* reliable for benchmarking.
*/
#if defined(BOTAN_HAS_TIMER_POSIX)
  #include <botan/tm_posix.h>
#elif defined(BOTAN_HAS_TIMER_UNIX)
  #include <botan/tm_unix.h>
#endif

namespace Botan {

#if defined(BOTAN_HAS_TIMER_POSIX)
  typedef POSIX_Timer Default_Benchmark_Timer;
#elif defined(BOTAN_HAS_TIMER_UNIX)
  typedef Unix_Timer Default_Benchmark_Timer;
#else
   /* I have not had good success using clock(), the results seem
    * pretty bogus, but as a last resort it works.
    */
  typedef ANSI_Clock_Timer Default_Benchmark_Timer;
#endif

/**
* Algorithm benchmark
* @param name the name of the algorithm to test (cipher, hash, or MAC)
* @param milliseconds total time for the benchmark to run
* @param timer the timer to use
* @param rng the rng to use to generate random inputs
* @param af the algorithm factory used to create objects
* @return results a map from provider to speed in mebibytes per second
*/
std::map<std::string, double>
algorithm_benchmark(const std::string& name,
                    u32bit milliseconds,
                    Timer& timer,
                    RandomNumberGenerator& rng,
                    Algorithm_Factory& af);

}

#endif
