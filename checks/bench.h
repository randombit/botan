
#ifndef BOTAN_BENCHMARCH_H__
#define BOTAN_BENCHMARCH_H__

#include <botan/rng.h>
#include <string>

void benchmark(const std::string&, Botan::RandomNumberGenerator&,
               bool html, double seconds);

void bench_pk(Botan::RandomNumberGenerator&,
              const std::string&, bool html, double seconds);

u32bit bench_algo(const std::string&,
                  Botan::RandomNumberGenerator&,
                  double);

#endif
