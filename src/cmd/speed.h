/*
* (C) 2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CHECK_BENCHMARK_H__
#define BOTAN_CHECK_BENCHMARK_H__

#include <botan/rng.h>
#include <string>

void bench_pk(Botan::RandomNumberGenerator& rng,
              const std::string& algo, double seconds);

#endif
