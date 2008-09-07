
#ifndef BOTAN_BENCHMARCH_H__
#define BOTAN_BENCHMARCH_H__

#include <botan/rng.h>
#include <string>
#include <map>
#include <set>
#include "timer.h"

#include <iostream>

class Benchmark_Report
   {
   public:
      void report(const std::string& name, Timer timer)
         {
         std::cout << name << " " << timer << std::endl;
         data[name].insert(timer);
         }

   private:
      std::map<std::string, std::set<Timer> > data;
   };


void benchmark(const std::string&, Botan::RandomNumberGenerator&,
               bool html, double seconds);

void bench_pk(Botan::RandomNumberGenerator&,
              const std::string&, bool html, double seconds);

u32bit bench_algo(const std::string&,
                  Botan::RandomNumberGenerator&,
                  double);

#endif
