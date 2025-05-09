#include <botan/internal/simd_4x64.h>
#include <array>
#include <stdio.h>

using namespace Botan;

inline void swap_tops(SIMD_4x64& A, SIMD_4x64& B) {
   SIMD_4x64 T0 = SIMD_4x64(_mm256_permute2x128_si256(A.raw(), B.raw(), 0 + (2 << 4)));
   SIMD_4x64 T1 = SIMD_4x64(_mm256_permute2x128_si256(A.raw(), B.raw(), 1 + (3 << 4)));
   A = T0;
   B = T1;
}

inline void transpose(SIMD_4x64& B0, SIMD_4x64& B1, SIMD_4x64& B2, SIMD_4x64& B3) noexcept {
   auto T0 = SIMD_4x64(_mm256_unpacklo_epi64(B0.raw(), B1.raw()));
   auto T1 = SIMD_4x64(_mm256_unpacklo_epi64(B2.raw(), B3.raw()));
   auto T2 = SIMD_4x64(_mm256_unpackhi_epi64(B0.raw(), B1.raw()));
   auto T3 = SIMD_4x64(_mm256_unpackhi_epi64(B2.raw(), B3.raw()));

   swap_tops(T0, T1);
   swap_tops(T2, T3);

   B0 = T0;
   B1 = T2;
   B2 = T1;
   B3 = T3;
}

inline void transpose(SIMD_4x64& B0, SIMD_4x64& B1, SIMD_4x64& B2, SIMD_4x64& B3,
                      SIMD_4x64& B4, SIMD_4x64& B5, SIMD_4x64& B6, SIMD_4x64& B7,
                      SIMD_4x64& B8, SIMD_4x64& B9, SIMD_4x64& BA, SIMD_4x64& BB,
                      SIMD_4x64& BC, SIMD_4x64& BD, SIMD_4x64& BE, SIMD_4x64& BF) {
   transpose(B0, B4, B8, BC);
   transpose(B1, B5, B9, BD);
   transpose(B2, B6, BA, BE);
   transpose(B3, B7, BB, BF);

   std::swap(B1, B4);
   std::swap(B2, B8);
   std::swap(B3, BC);
   std::swap(B6, B9);
   std::swap(B7, BD);
   std::swap(BB, BE);
}

void dump(const char* s, const SIMD_4x64& v) {
   uint64_t v4[4] = {0};
   v.store_le(v4);
   printf("%s = ", s);
   for(size_t i = 0; i != 4; ++i) {
      printf("%016llX ", v4[i]);
   }
   printf("\n");
}

int main() {

   uint8_t data[128 * 4] = { 0 };
   size_t ctr = 0;
   for(size_t i = 0; i != sizeof(data); ++i) {
      data[i] = (i + 8) / 8;
      //data[i] = static_cast<uint8_t>(ctr >> 9);
      //ctr = ((ctr + i) * 439) % 3758015549;
   }

   // Message 0
   auto M0 = SIMD_4x64::load_be(&data[32*0]);
   auto M1 = SIMD_4x64::load_be(&data[32*1]);
   auto M2 = SIMD_4x64::load_be(&data[32*2]);
   auto M3 = SIMD_4x64::load_be(&data[32*3]);

   // Message 1
   auto M4 = SIMD_4x64::load_be(&data[32*4]);
   auto M5 = SIMD_4x64::load_be(&data[32*5]);
   auto M6 = SIMD_4x64::load_be(&data[32*6]);
   auto M7 = SIMD_4x64::load_be(&data[32*7]);

   // Message 2
   auto M8 = SIMD_4x64::load_be(&data[32*8]);
   auto M9 = SIMD_4x64::load_be(&data[32*9]);
   auto MA = SIMD_4x64::load_be(&data[32*10]);
   auto MB = SIMD_4x64::load_be(&data[32*11]);

   // Message 3
   auto MC = SIMD_4x64::load_be(&data[32*12]);
   auto MD = SIMD_4x64::load_be(&data[32*13]);
   auto ME = SIMD_4x64::load_be(&data[32*14]);
   auto MF = SIMD_4x64::load_be(&data[32 * 15]);

   dump("M0", M0);
   dump("M1", M1);
   dump("M2", M2);
   dump("M3", M3);
   printf("\n");
   dump("M4", M4);
   dump("M5", M5);
   dump("M6", M6);
   dump("M7", M7);
   printf("\n");
   dump("M8", M8);
   dump("M9", M9);
   dump("MA", MA);
   dump("MB", MB);
   printf("\n");
   dump("MC", MC);
   dump("MD", MD);
   dump("ME", ME);
   dump("MF", MF);

   // Goal:
   // W0 = M0[0], M4[0], M8[0], MC[0]
   // W1 = M0[1], M4[1], M8[1], MC[1]
   // W2 = M0[2], M4[2], M8[2], MC[2]
   // W3 = M0[3], M4[3], M8[3], MC[3]
   transpose(M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, MA, MB, MC, MD, ME, MF);

   printf("Transposed\n---------\n");
   dump("M0", M0);
   dump("M1", M1);
   dump("M2", M2);
   dump("M3", M3);
   printf("\n");
   dump("M4", M4);
   dump("M5", M5);
   dump("M6", M6);
   dump("M7", M7);
   printf("\n");
   dump("M8", M8);
   dump("M9", M9);
   dump("MA", MA);
   dump("MB", MB);
   printf("\n");
   dump("MC", MC);
   dump("MD", MD);
   dump("ME", ME);
   dump("MF", MF);
   }
