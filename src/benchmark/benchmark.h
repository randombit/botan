/**
* Runtime benchmarking
* (C) 2008-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_RUNTIME_BENCHMARK_H__
#define BOTAN_RUNTIME_BENCHMARK_H__

#include <botan/algo_factory.h>
#include <botan/rng.h>
#include <map>
#include <string>

namespace Botan {

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
BOTAN_DLL algorithm_benchmark(const std::string& name,
                              u32bit milliseconds,
                              RandomNumberGenerator& rng,
                              Algorithm_Factory& af);

}

#endif
