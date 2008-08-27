/*************************************************
* Karatsuba Multiplication/Squaring Source File  *
* (C) 1999-2008 Jack Lloyd                       *
*************************************************/

#include <botan/mp_core.h>
#include <botan/mem_ops.h>

namespace Botan {

namespace {

/*************************************************
* Simple O(N^2) Multiplication                   *
*************************************************/
void bigint_simple_mul(word z[], const word x[], u32bit x_size,
                                 const word y[], u32bit y_size)
   {
   clear_mem(z, x_size + y_size);

   for(u32bit j = 0; j != x_size; ++j)
      z[j+y_size] = bigint_mul_add_words(z + j, y, y_size, x[j]);
   }

/*************************************************
* Simple O(N^2) Squaring                         *
*************************************************/
void bigint_simple_sqr(word z[], const word x[], u32bit x_size)
   {
   clear_mem(z, 2*x_size);

   for(u32bit j = 0; j != x_size; ++j)
      z[j+x_size] = bigint_mul_add_words(z + j, x, x_size, x[j]);
   }

/*************************************************
* Karatsuba Multiplication Operation             *
*************************************************/
void karatsuba_mul(word z[], const word x[], const word y[], u32bit N,
                   word workspace[])
   {
   const u32bit KARATSUBA_MUL_LOWER_SIZE = BOTAN_KARAT_MUL_THRESHOLD;

   if(N == 6)
      bigint_comba_mul6(z, x, y);
   else if(N == 8)
      bigint_comba_mul8(z, x, y);
   else if(N < KARATSUBA_MUL_LOWER_SIZE || N % 2)
      bigint_simple_mul(z, x, N, y, N);
   else
      {
      const u32bit N2 = N / 2;

      const word* x0 = x;
      const word* x1 = x + N2;
      const word* y0 = y;
      const word* y1 = y + N2;
      word* z0 = z;
      word* z1 = z + N;

      const s32bit cmp0 = bigint_cmp(x0, N2, x1, N2);
      const s32bit cmp1 = bigint_cmp(y1, N2, y0, N2);

      clear_mem(workspace, 2*N);

      if(cmp0 && cmp1)
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

      word carry = bigint_add3_nc(workspace+N, z0, N, z1, N);
      carry += bigint_add2_nc(z + N2, N, workspace + N, N);
      bigint_add2_nc(z + N + N2, N2, &carry, 1);

      if((cmp0 == cmp1) || (cmp0 == 0) || (cmp1 == 0))
         bigint_add2(z + N2, 2*N-N2, workspace, N);
      else
         bigint_sub2(z + N2, 2*N-N2, workspace, N);
      }
   }

/*************************************************
* Karatsuba Squaring Operation                   *
*************************************************/
void karatsuba_sqr(word z[], const word x[], u32bit N, word workspace[])
   {
   const u32bit KARATSUBA_SQR_LOWER_SIZE = BOTAN_KARAT_SQR_THRESHOLD;

   if(N == 6)
      bigint_comba_sqr6(z, x);
   else if(N == 8)
      bigint_comba_sqr8(z, x);
   else if(N < KARATSUBA_SQR_LOWER_SIZE || N % 2)
      bigint_simple_sqr(z, x, N);
   else
      {
      const u32bit N2 = N / 2;

      const word* x0 = x;
      const word* x1 = x + N2;
      word* z0 = z;
      word* z1 = z + N;

      const s32bit cmp = bigint_cmp(x0, N2, x1, N2);

      clear_mem(workspace, 2*N);

      if(cmp)
         {
         if(cmp > 0)
            bigint_sub3(z0, x0, N2, x1, N2);
         else
            bigint_sub3(z0, x1, N2, x0, N2);

         karatsuba_sqr(workspace, z0, N2, workspace+N);
         }

      karatsuba_sqr(z0, x0, N2, workspace+N);
      karatsuba_sqr(z1, x1, N2, workspace+N);

      word carry = bigint_add3_nc(workspace+N, z0, N, z1, N);
      carry += bigint_add2_nc(z + N2, N, workspace + N, N);
      bigint_add2_nc(z + N + N2, N2, &carry, 1);

      if(cmp == 0)
         bigint_add2(z + N2, 2*N-N2, workspace, N);
      else
         bigint_sub2(z + N2, 2*N-N2, workspace, N);
      }
   }

/*************************************************
* Pick a good size for the Karatsuba multiply    *
*************************************************/
u32bit karatsuba_size(u32bit z_size,
                      u32bit x_size, u32bit x_sw,
                      u32bit y_size, u32bit y_sw)
   {
   if(x_sw > x_size || x_sw > y_size || y_sw > x_size || y_sw > y_size)
      return 0;

   if(((x_size == x_sw) && (x_size % 2)) ||
      ((y_size == y_sw) && (y_size % 2)))
      return 0;

   const u32bit start = (x_sw > y_sw) ? x_sw : y_sw;
   const u32bit end = (x_size < y_size) ? x_size : y_size;

   if(start == end)
      {
      if(start % 2)
         return 0;
      return start;
      }

   for(u32bit j = start; j <= end; ++j)
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

/*************************************************
* Pick a good size for the Karatsuba squaring    *
*************************************************/
u32bit karatsuba_size(u32bit z_size, u32bit x_size, u32bit x_sw)
   {
   if(x_sw == x_size)
      {
      if(x_sw % 2)
         return 0;
      return x_sw;
      }

   for(u32bit j = x_sw; j <= x_size; ++j)
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

/*************************************************
* Handle small operand multiplies                *
*************************************************/
void handle_small_mul(word z[], u32bit z_size,
                      const word x[], u32bit x_size, u32bit x_sw,
                      const word y[], u32bit y_size, u32bit y_sw)
   {
   if(x_sw == 1)        bigint_linmul3(z, y, y_sw, x[0]);
   else if(y_sw == 1)   bigint_linmul3(z, x, x_sw, y[0]);

   else if(x_sw <= 4 && x_size >= 4 &&
           y_sw <= 4 && y_size >= 4 && z_size >= 8)
      bigint_comba_mul4(z, x, y);

   else if(x_sw <= 6 && x_size >= 6 &&
           y_sw <= 6 && y_size >= 6 && z_size >= 12)
      bigint_comba_mul6(z, x, y);

   else if(x_sw <= 8 && x_size >= 8 &&
           y_sw <= 8 && y_size >= 8 && z_size >= 16)
      bigint_comba_mul8(z, x, y);

   else
      bigint_simple_mul(z, x, x_sw, y, y_sw);
   }

/*************************************************
* Handle small operand squarings                 *
*************************************************/
void handle_small_sqr(word z[], u32bit z_size,
                      const word x[], u32bit x_size, u32bit x_sw)
   {
   if(x_sw == 1)
      bigint_linmul3(z, x, x_sw, x[0]);
   else if(x_sw <= 4 && x_size >= 4 && z_size >= 8)
      bigint_comba_sqr4(z, x);
   else if(x_sw <= 6 && x_size >= 6 && z_size >= 12)
      bigint_comba_sqr6(z, x);
   else if(x_sw <= 8 && x_size >= 8 && z_size >= 16)
      bigint_comba_sqr8(z, x);
   else
      bigint_simple_sqr(z, x, x_sw);
   }

}

/*************************************************
* Multiplication Algorithm Dispatcher            *
*************************************************/
void bigint_mul(word z[], u32bit z_size, word workspace[],
                const word x[], u32bit x_size, u32bit x_sw,
                const word y[], u32bit y_size, u32bit y_sw)
   {
   if(x_size <= 8 || y_size <= 8)
      {
      handle_small_mul(z, z_size, x, x_size, x_sw, y, y_size, y_sw);
      return;
      }

   const u32bit N = karatsuba_size(z_size, x_size, x_sw, y_size, y_sw);

   if(N)
      {
      clear_mem(workspace, 2*N);
      karatsuba_mul(z, x, y, N, workspace);
      }
   else
      bigint_simple_mul(z, x, x_sw, y, y_sw);
   }

/*************************************************
* Squaring Algorithm Dispatcher                  *
*************************************************/
void bigint_sqr(word z[], u32bit z_size, word workspace[],
                const word x[], u32bit x_size, u32bit x_sw)
   {
   if(x_size <= 8 || x_sw <= 8)
      {
      handle_small_sqr(z, z_size, x, x_size, x_sw);
      return;
      }

   const u32bit N = karatsuba_size(z_size, x_size, x_sw);

   if(N)
      {
      clear_mem(workspace, 2*N);
      karatsuba_sqr(z, x, N, workspace);
      }
   else
      bigint_simple_sqr(z, x, x_sw);
   }

}
