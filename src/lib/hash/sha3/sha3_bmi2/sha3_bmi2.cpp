/*
* SHA-3
* (C) 2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sha3.h>

#include <botan/internal/sha3_round.h>

namespace Botan {

void SHA_3::permute_bmi2(uint64_t A[25]) {
   static const uint64_t RC[24] = {0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
                                   0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
                                   0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
                                   0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
                                   0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
                                   0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008};

   uint64_t T[25];

   for(size_t i = 0; i != 24; i += 2) {
      SHA3_round(T, A, RC[i + 0]);
      SHA3_round(A, T, RC[i + 1]);
   }
}

}  // namespace Botan
