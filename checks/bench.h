
#ifndef BOTAN_CHECK_BENCHMARK_H__
#define BOTAN_CHECK_BENCHMARK_H__

#include <botan/rng.h>
#include <string>

void benchmark(Botan::RandomNumberGenerator& rng,
               double seconds,
               u32bit buf_size);

bool bench_algo(const std::string& algo_name,
                Botan::RandomNumberGenerator& rng,
                double seconds,
                u32bit buf_size);

void bench_pk(Botan::RandomNumberGenerator&,
              const std::string&, double seconds);

#endif
