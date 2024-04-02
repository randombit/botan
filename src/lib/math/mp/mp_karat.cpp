/*
* Multiplication and Squaring
* (C) 1999-2010,2018 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/mp_core.h>

#include <botan/exceptn.h>
#include <botan/mem_ops.h>
#include <botan/internal/ct_utils.h>

namespace Botan {

/*
* Simple O(N^2) Multiplication
*/
void basecase_mul(word z[], size_t z_size, const word x[], size_t x_size, const word y[], size_t y_size) {
   if(z_size < x_size + y_size) {
      throw Invalid_Argument("basecase_mul z_size too small");
   }

   const size_t x_size_8 = x_size - (x_size % 8);

   clear_mem(z, z_size);

   for(size_t i = 0; i != y_size; ++i) {
      const word y_i = y[i];

      word carry = 0;

      for(size_t j = 0; j != x_size_8; j += 8) {
         carry = word8_madd3(z + i + j, x + j, y_i, carry);
      }

      for(size_t j = x_size_8; j != x_size; ++j) {
         z[i + j] = word_madd3(x[j], y_i, z[i + j], &carry);
      }

      z[x_size + i] = carry;
   }
}

void basecase_sqr(word z[], size_t z_size, const word x[], size_t x_size) {
   if(z_size < 2 * x_size) {
      throw Invalid_Argument("basecase_sqr z_size too small");
   }

   const size_t x_size_8 = x_size - (x_size % 8);

   clear_mem(z, z_size);

   for(size_t i = 0; i != x_size; ++i) {
      const word x_i = x[i];

      word carry = 0;

      for(size_t j = 0; j != x_size_8; j += 8) {
         carry = word8_madd3(z + i + j, x + j, x_i, carry);
      }

      for(size_t j = x_size_8; j != x_size; ++j) {
         z[i + j] = word_madd3(x[j], x_i, z[i + j], &carry);
      }

      z[x_size + i] = carry;
   }
}

namespace {

const size_t KARATSUBA_MULTIPLY_THRESHOLD = 32;
const size_t KARATSUBA_SQUARE_THRESHOLD = 32;

/*
* Karatsuba Multiplication Operation
*/
void karatsuba_mul(word z[], const word x[], const word y[], size_t N, word workspace[]) {
   if(N < KARATSUBA_MULTIPLY_THRESHOLD || N % 2) {
      switch(N) {
         case 6:
            return bigint_comba_mul6(z, x, y);
         case 8:
            return bigint_comba_mul8(z, x, y);
         case 9:
            return bigint_comba_mul9(z, x, y);
         case 16:
            return bigint_comba_mul16(z, x, y);
         case 24:
            return bigint_comba_mul24(z, x, y);
         default:
            return basecase_mul(z, 2 * N, x, N, y, N);
      }
   }

   const size_t N2 = N / 2;

   const word* x0 = x;
   const word* x1 = x + N2;
   const word* y0 = y;
   const word* y1 = y + N2;
   word* z0 = z;
   word* z1 = z + N;

   word* ws0 = workspace;
   word* ws1 = workspace + N;

   clear_mem(workspace, 2 * N);

   /*
   * If either of cmp0 or cmp1 is zero then z0 or z1 resp is zero here,
   * resulting in a no-op - z0*z1 will be equal to zero so we don't need to do
   * anything, clear_mem above already set the correct result.
   *
   * However we ignore the result of the comparisons and always perform the
   * subtractions and recursively multiply to avoid the timing channel.
   */

   // First compute (X_lo - X_hi)*(Y_hi - Y_lo)
   const auto cmp0 = bigint_sub_abs(z0, x0, x1, N2, workspace);
   const auto cmp1 = bigint_sub_abs(z1, y1, y0, N2, workspace);
   const auto neg_mask = ~(cmp0 ^ cmp1);

   karatsuba_mul(ws0, z0, z1, N2, ws1);

   // Compute X_lo * Y_lo
   karatsuba_mul(z0, x0, y0, N2, ws1);

   // Compute X_hi * Y_hi
   karatsuba_mul(z1, x1, y1, N2, ws1);

   const word ws_carry = bigint_add3_nc(ws1, z0, N, z1, N);
   word z_carry = bigint_add2_nc(z + N2, N, ws1, N);

   z_carry += bigint_add2_nc(z + N + N2, N2, &ws_carry, 1);
   bigint_add2_nc(z + N + N2, N2, &z_carry, 1);

   clear_mem(workspace + N, N2);

   bigint_cnd_add_or_sub(neg_mask, z + N2, workspace, 2 * N - N2);
}

/*
* Karatsuba Squaring Operation
*/
void karatsuba_sqr(word z[], const word x[], size_t N, word workspace[]) {
   if(N < KARATSUBA_SQUARE_THRESHOLD || N % 2) {
      switch(N) {
         case 6:
            return bigint_comba_sqr6(z, x);
         case 8:
            return bigint_comba_sqr8(z, x);
         case 9:
            return bigint_comba_sqr9(z, x);
         case 16:
            return bigint_comba_sqr16(z, x);
         case 24:
            return bigint_comba_sqr24(z, x);
         default:
            return basecase_sqr(z, 2 * N, x, N);
      }
   }

   const size_t N2 = N / 2;

   const word* x0 = x;
   const word* x1 = x + N2;
   word* z0 = z;
   word* z1 = z + N;

   word* ws0 = workspace;
   word* ws1 = workspace + N;

   clear_mem(workspace, 2 * N);

   // See comment in karatsuba_mul
   bigint_sub_abs(z0, x0, x1, N2, workspace);
   karatsuba_sqr(ws0, z0, N2, ws1);

   karatsuba_sqr(z0, x0, N2, ws1);
   karatsuba_sqr(z1, x1, N2, ws1);

   const word ws_carry = bigint_add3_nc(ws1, z0, N, z1, N);
   word z_carry = bigint_add2_nc(z + N2, N, ws1, N);

   z_carry += bigint_add2_nc(z + N + N2, N2, &ws_carry, 1);
   bigint_add2_nc(z + N + N2, N2, &z_carry, 1);

   /*
   * This is only actually required if cmp (result of bigint_sub_abs) is != 0,
   * however if cmp==0 then ws0[0:N] == 0 and avoiding the jump hides a
   * timing channel.
   */
   bigint_sub2(z + N2, 2 * N - N2, ws0, N);
}

/*
* Pick a good size for the Karatsuba multiply
*/
size_t karatsuba_size(size_t z_size, size_t x_size, size_t x_sw, size_t y_size, size_t y_sw) {
   if(x_sw > x_size || x_sw > y_size || y_sw > x_size || y_sw > y_size) {
      return 0;
   }

   if(((x_size == x_sw) && (x_size % 2)) || ((y_size == y_sw) && (y_size % 2))) {
      return 0;
   }

   const size_t start = (x_sw > y_sw) ? x_sw : y_sw;
   const size_t end = (x_size < y_size) ? x_size : y_size;

   if(start == end) {
      if(start % 2) {
         return 0;
      }
      return start;
   }

   for(size_t j = start; j <= end; ++j) {
      if(j % 2) {
         continue;
      }

      if(2 * j > z_size) {
         return 0;
      }

      if(x_sw <= j && j <= x_size && y_sw <= j && j <= y_size) {
         if(j % 4 == 2 && (j + 2) <= x_size && (j + 2) <= y_size && 2 * (j + 2) <= z_size) {
            return j + 2;
         }
         return j;
      }
   }

   return 0;
}

/*
* Pick a good size for the Karatsuba squaring
*/
size_t karatsuba_size(size_t z_size, size_t x_size, size_t x_sw) {
   if(x_sw == x_size) {
      if(x_sw % 2) {
         return 0;
      }
      return x_sw;
   }

   for(size_t j = x_sw; j <= x_size; ++j) {
      if(j % 2) {
         continue;
      }

      if(2 * j > z_size) {
         return 0;
      }

      if(j % 4 == 2 && (j + 2) <= x_size && 2 * (j + 2) <= z_size) {
         return j + 2;
      }
      return j;
   }

   return 0;
}

template <size_t SZ>
inline bool sized_for_comba_mul(size_t x_sw, size_t x_size, size_t y_sw, size_t y_size, size_t z_size) {
   return (x_sw <= SZ && x_size >= SZ && y_sw <= SZ && y_size >= SZ && z_size >= 2 * SZ);
}

template <size_t SZ>
inline bool sized_for_comba_sqr(size_t x_sw, size_t x_size, size_t z_size) {
   return (x_sw <= SZ && x_size >= SZ && z_size >= 2 * SZ);
}

}  // namespace

void bigint_mul(word z[],
                size_t z_size,
                const word x[],
                size_t x_size,
                size_t x_sw,
                const word y[],
                size_t y_size,
                size_t y_sw,
                word workspace[],
                size_t ws_size) {
   clear_mem(z, z_size);

   if(x_sw == 1) {
      bigint_linmul3(z, y, y_sw, x[0]);
   } else if(y_sw == 1) {
      bigint_linmul3(z, x, x_sw, y[0]);
   } else if(sized_for_comba_mul<4>(x_sw, x_size, y_sw, y_size, z_size)) {
      bigint_comba_mul4(z, x, y);
   } else if(sized_for_comba_mul<6>(x_sw, x_size, y_sw, y_size, z_size)) {
      bigint_comba_mul6(z, x, y);
   } else if(sized_for_comba_mul<8>(x_sw, x_size, y_sw, y_size, z_size)) {
      bigint_comba_mul8(z, x, y);
   } else if(sized_for_comba_mul<9>(x_sw, x_size, y_sw, y_size, z_size)) {
      bigint_comba_mul9(z, x, y);
   } else if(sized_for_comba_mul<16>(x_sw, x_size, y_sw, y_size, z_size)) {
      bigint_comba_mul16(z, x, y);
   } else if(sized_for_comba_mul<24>(x_sw, x_size, y_sw, y_size, z_size)) {
      bigint_comba_mul24(z, x, y);
   } else if(x_sw < KARATSUBA_MULTIPLY_THRESHOLD || y_sw < KARATSUBA_MULTIPLY_THRESHOLD || !workspace) {
      basecase_mul(z, z_size, x, x_sw, y, y_sw);
   } else {
      const size_t N = karatsuba_size(z_size, x_size, x_sw, y_size, y_sw);

      if(N && z_size >= 2 * N && ws_size >= 2 * N) {
         karatsuba_mul(z, x, y, N, workspace);
      } else {
         basecase_mul(z, z_size, x, x_sw, y, y_sw);
      }
   }
}

/*
* Squaring Algorithm Dispatcher
*/
void bigint_sqr(word z[], size_t z_size, const word x[], size_t x_size, size_t x_sw, word workspace[], size_t ws_size) {
   clear_mem(z, z_size);

   BOTAN_ASSERT(z_size / 2 >= x_sw, "Output size is sufficient");

   if(x_sw == 1) {
      bigint_linmul3(z, x, x_sw, x[0]);
   } else if(sized_for_comba_sqr<4>(x_sw, x_size, z_size)) {
      bigint_comba_sqr4(z, x);
   } else if(sized_for_comba_sqr<6>(x_sw, x_size, z_size)) {
      bigint_comba_sqr6(z, x);
   } else if(sized_for_comba_sqr<8>(x_sw, x_size, z_size)) {
      bigint_comba_sqr8(z, x);
   } else if(sized_for_comba_sqr<9>(x_sw, x_size, z_size)) {
      bigint_comba_sqr9(z, x);
   } else if(sized_for_comba_sqr<16>(x_sw, x_size, z_size)) {
      bigint_comba_sqr16(z, x);
   } else if(sized_for_comba_sqr<24>(x_sw, x_size, z_size)) {
      bigint_comba_sqr24(z, x);
   } else if(x_size < KARATSUBA_SQUARE_THRESHOLD || !workspace) {
      basecase_sqr(z, z_size, x, x_sw);
   } else {
      const size_t N = karatsuba_size(z_size, x_size, x_sw);

      if(N && z_size >= 2 * N && ws_size >= 2 * N) {
         karatsuba_sqr(z, x, N, workspace);
      } else {
         basecase_sqr(z, z_size, x, x_sw);
      }
   }
}

}  // namespace Botan
