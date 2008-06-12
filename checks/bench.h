
#ifndef BOTAN_BENCHMARCH_H__
#define BOTAN_BENCHMARCH_H__

void benchmark(const std::string&, bool html, double seconds);
void bench_pk(const std::string&, bool html, double seconds);
u32bit bench_algo(const std::string&, double);

#endif
