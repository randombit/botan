#include <stdio.h>

#include <botan/cpuid.h>

using namespace Botan;

int main()
   {
   printf("Cache line size: %d\n", CPUID::cache_line_size());
   printf("RDTSC: %d\n", CPUID::has_rdtsc());
   printf("SSE2 %d\n", CPUID::has_sse2());
   printf("SSSE3 %d\n", CPUID::has_ssse3());
   printf("SSE41 %d\n", CPUID::has_sse41());
   printf("SSE42 %d\n", CPUID::has_sse42());

   printf("AltiVec %d\n", CPUID::has_altivec());
   }
