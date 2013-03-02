/*
* Karatsuba Multiplication/Squaring
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/mp_core.h>
#include <botan/internal/mp_asmi.h>
#include <botan/mem_ops.h>

namespace Botan {

namespace {

/*
* Karatsuba Multiplication Operation
*/
void karatsuba_mul(word z[], const word x[], const word y[], size_t N,
                   word workspace[])
   {
   if(N < BOTAN_KARAT_MUL_THRESHOLD || N % 2)
      {
      if(N == 6)
         return bigint_comba_mul6(z, x, y);
      else if(N == 8)
         return bigint_comba_mul8(z, x, y);
      else if(N == 16)
         return bigint_comba_mul16(z, x, y);
      else
         return bigint_simple_mul(z, x, N, y, N);
      }

   const size_t N2 = N / 2;

   const word* x0 = x;
   const word* x1 = x + N2;
   const word* y0 = y;
   const word* y1 = y + N2;
   word* z0 = z;
   word* z1 = z + N;

   const s32bit cmp0 = bigint_cmp(x0, N2, x1, N2);
   const s32bit cmp1 = bigint_cmp(y1, N2, y0, N2);

   clear_mem(workspace, 2*N);

   //if(cmp0 && cmp1)
      {
      if(cmp0 > 0)
         bigint_sub3(z0, x0, N2, x1, N2);
      else
         bigint_sub3(z0, x1, N2, x0, N2);

      if(cmp1 > 0)
         bigint_sub3(z1, y1, N2, y0, N2);
      else
         bigint_sub3(z1, y0, N2, y1, N2);

      karatsuba_mul(workspace, z0, z1, N2, workspace+N);
      }

   karatsuba_mul(z0, x0, y0, N2, workspace+N);
   karatsuba_mul(z1, x1, y1, N2, workspace+N);

   const size_t blocks_of_8 = N - (N % 8);

   word ws_carry = 0;

   for(size_t j = 0; j != blocks_of_8; j += 8)
      ws_carry = word8_add3(workspace + N + j, z0 + j, z1 + j, ws_carry);

   for(size_t j = blocks_of_8; j != N; ++j)
      workspace[N + j] = word_add(z0[j], z1[j], &ws_carry);

   word z_carry = 0;

   for(size_t j = 0; j != blocks_of_8; j += 8)
      z_carry = word8_add2(z + N2 + j, workspace + N + j, z_carry);

   for(size_t j = blocks_of_8; j != N; ++j)
      z[N2 + j] = word_add(z[N2 + j], workspace[N + j], &z_carry);

   z[N + N2] = word_add(z[N + N2], ws_carry, &z_carry);

   if(z_carry)
      for(size_t j = 1; j != N2; ++j)
         if(++z[N + N2 + j])
            break;

   if((cmp0 == cmp1) || (cmp0 == 0) || (cmp1 == 0))
      bigint_add2(z + N2, 2*N-N2, workspace, N);
   else
      bigint_sub2(z + N2, 2*N-N2, workspace, N);
   }

/*
* Karatsuba Squaring Operation
*/
void karatsuba_sqr(word z[], const word x[], size_t N, word workspace[])
   {
   if(N < BOTAN_KARAT_SQR_THRESHOLD || N % 2)
      {
      if(N == 6)
         return bigint_comba_sqr6(z, x);
      else if(N == 8)
         return bigint_comba_sqr8(z, x);
      else if(N == 16)
         return bigint_comba_sqr16(z, x);
      else
         return bigint_simple_sqr(z, x, N);
      }

   const size_t N2 = N / 2;

   const word* x0 = x;
   const word* x1 = x + N2;
   word* z0 = z;
   word* z1 = z + N;

   const s32bit cmp = bigint_cmp(x0, N2, x1, N2);

   clear_mem(workspace, 2*N);

   //if(cmp)
      {
      if(cmp > 0)
         bigint_sub3(z0, x0, N2, x1, N2);
      else
         bigint_sub3(z0, x1, N2, x0, N2);

      karatsuba_sqr(workspace, z0, N2, workspace+N);
      }

   karatsuba_sqr(z0, x0, N2, workspace+N);
   karatsuba_sqr(z1, x1, N2, workspace+N);

   const size_t blocks_of_8 = N - (N % 8);

   word ws_carry = 0;

   for(size_t j = 0; j != blocks_of_8; j += 8)
      ws_carry = word8_add3(workspace + N + j, z0 + j, z1 + j, ws_carry);

   for(size_t j = blocks_of_8; j != N; ++j)
      workspace[N + j] = word_add(z0[j], z1[j], &ws_carry);

   word z_carry = 0;

   for(size_t j = 0; j != blocks_of_8; j += 8)
      z_carry = word8_add2(z + N2 + j, workspace + N + j, z_carry);

   for(size_t j = blocks_of_8; j != N; ++j)
      z[N2 + j] = word_add(z[N2 + j], workspace[N + j], &z_carry);

   z[N + N2] = word_add(z[N + N2], ws_carry, &z_carry);

   if(z_carry)
      for(size_t j = 1; j != N2; ++j)
         if(++z[N + N2 + j])
            break;

   /*
   * This is only actually required if cmp is != 0, however
   * if cmp==0 then workspace[0:N] == 0 and avoiding the jump
   * hides a timing channel.
   */
   bigint_sub2(z + N2, 2*N-N2, workspace, N);
   }

/*
* Pick a good size for the Karatsuba multiply
*/
size_t karatsuba_size(size_t z_size,
                      size_t x_size, size_t x_sw,
                      size_t y_size, size_t y_sw)
   {
   if(x_sw > x_size || x_sw > y_size || y_sw > x_size || y_sw > y_size)
      return 0;

   if(((x_size == x_sw) && (x_size % 2)) ||
      ((y_size == y_sw) && (y_size % 2)))
      return 0;

   const size_t start = (x_sw > y_sw) ? x_sw : y_sw;
   const size_t end = (x_size < y_size) ? x_size : y_size;

   if(start == end)
      {
      if(start % 2)
         return 0;
      return start;
      }

   for(size_t j = start; j <= end; ++j)
      {
      if(j % 2)
         continue;

      if(2*j > z_size)
         return 0;

      if(x_sw <= j && j <= x_size && y_sw <= j && j <= y_size)
         {
         if(j % 4 == 2 &&
            (j+2) <= x_size && (j+2) <= y_size && 2*(j+2) <= z_size)
            return j+2;
         return j;
         }
      }

   return 0;
   }

/*
* Pick a good size for the Karatsuba squaring
*/
size_t karatsuba_size(size_t z_size, size_t x_size, size_t x_sw)
   {
   if(x_sw == x_size)
      {
      if(x_sw % 2)
         return 0;
      return x_sw;
      }

   for(size_t j = x_sw; j <= x_size; ++j)
      {
      if(j % 2)
         continue;

      if(2*j > z_size)
         return 0;

      if(j % 4 == 2 && (j+2) <= x_size && 2*(j+2) <= z_size)
         return j+2;
      return j;
      }

   return 0;
   }

}

/*
* Multiplication Algorithm Dispatcher
*/
void bigint_mul(word z[], size_t z_size, word workspace[],
                const word x[], size_t x_size, size_t x_sw,
                const word y[], size_t y_size, size_t y_sw)
   {
   if(x_sw == 1)
      {
      bigint_linmul3(z, y, y_sw, x[0]);
      }
   else if(y_sw == 1)
      {
      bigint_linmul3(z, x, x_sw, y[0]);
      }
   else if(x_sw <= 4 && x_size >= 4 &&
           y_sw <= 4 && y_size >= 4 && z_size >= 8)
      {
      bigint_comba_mul4(z, x, y);
      }
   else if(x_sw <= 6 && x_size >= 6 &&
           y_sw <= 6 && y_size >= 6 && z_size >= 12)
      {
      bigint_comba_mul6(z, x, y);
      }
   else if(x_sw <= 8 && x_size >= 8 &&
           y_sw <= 8 && y_size >= 8 && z_size >= 16)
      {
      bigint_comba_mul8(z, x, y);
      }
   else if(x_sw <= 16 && x_size >= 16 &&
           y_sw <= 16 && y_size >= 16 && z_size >= 32)
      {
      bigint_comba_mul16(z, x, y);
      }
   else if(x_sw < BOTAN_KARAT_MUL_THRESHOLD ||
           y_sw < BOTAN_KARAT_MUL_THRESHOLD ||
           !workspace)
      {
      bigint_simple_mul(z, x, x_sw, y, y_sw);
      }
   else
      {
      const size_t N = karatsuba_size(z_size, x_size, x_sw, y_size, y_sw);

      if(N)
         {
         clear_mem(workspace, 2*N);
         karatsuba_mul(z, x, y, N, workspace);
         }
      else
         bigint_simple_mul(z, x, x_sw, y, y_sw);
      }
   }

/*
* Squaring Algorithm Dispatcher
*/
void bigint_sqr(word z[], size_t z_size, word workspace[],
                const word x[], size_t x_size, size_t x_sw)
   {
   if(x_sw == 1)
      {
      bigint_linmul3(z, x, x_sw, x[0]);
      }
   else if(x_sw <= 4 && x_size >= 4 && z_size >= 8)
      {
      bigint_comba_sqr4(z, x);
      }
   else if(x_sw <= 6 && x_size >= 6 && z_size >= 12)
      {
      bigint_comba_sqr6(z, x);
      }
   else if(x_sw <= 8 && x_size >= 8 && z_size >= 16)
      {
      bigint_comba_sqr8(z, x);
      }
   else if(x_sw <= 16 && x_size >= 16 && z_size >= 32)
      {
      bigint_comba_sqr16(z, x);
      }
   else if(x_size < BOTAN_KARAT_SQR_THRESHOLD || !workspace)
      {
      bigint_simple_sqr(z, x, x_sw);
      }
   else
      {
      const size_t N = karatsuba_size(z_size, x_size, x_sw);

      if(N)
         {
         clear_mem(workspace, 2*N);
         karatsuba_sqr(z, x, N, workspace);
         }
      else
         bigint_simple_sqr(z, x, x_sw);
      }
   }

}
