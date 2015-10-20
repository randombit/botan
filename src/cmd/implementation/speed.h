/*
* (C) 2014 Jack Lloyd
* (C) 2015 Simon Warta (Kullo GmbH)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CHECK_BENCHMARK_H__
#define BOTAN_CHECK_BENCHMARK_H__

#include <botan/rng.h>
#include <string>
#include <chrono>

void benchmark_public_key(Botan::RandomNumberGenerator& rng,
                          const std::string& algo,
                          const std::string& provider,
                          double seconds);

std::map<std::string, double> benchmark_is_prime(Botan::RandomNumberGenerator &rng,
                                                 const std::chrono::milliseconds runtime);

std::map<std::string, double> benchmark_random_prime(Botan::RandomNumberGenerator &rng,
                                                     const std::chrono::milliseconds runtime);

bool benchmark_transform(Botan::RandomNumberGenerator& rng, const std::string& algo_name,
                         const std::chrono::milliseconds runtime);


#endif
