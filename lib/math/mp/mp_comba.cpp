/*
* Comba Multiplication and Squaring
* (C) 1999-2007,2011 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/mp_core.h>
#include <botan/internal/mp_asmi.h>

namespace Botan {

extern "C" {

/*
* Comba 4x4 Squaring
*/
void bigint_comba_sqr4(word z[8], const word x[4])
   {
   word w2 = 0, w1 = 0, w0 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 0], x[ 0]);
   z[ 0] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 0], x[ 1]);
   z[ 1] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[ 0], x[ 2]);
   word3_muladd(&w1, &w0, &w2, x[ 1], x[ 1]);
   z[ 2] = w2; w2 = 0;

   word3_muladd_2(&w2, &w1, &w0, x[ 0], x[ 3]);
   word3_muladd_2(&w2, &w1, &w0, x[ 1], x[ 2]);
   z[ 3] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 1], x[ 3]);
   word3_muladd(&w0, &w2, &w1, x[ 2], x[ 2]);
   z[ 4] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[ 2], x[ 3]);
   z[ 5] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 3], x[ 3]);
   z[ 6] = w0;
   z[ 7] = w1;
   }

/*
* Comba 4x4 Multiplication
*/
void bigint_comba_mul4(word z[8], const word x[4], const word y[4])
   {
   word w2 = 0, w1 = 0, w0 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 0], y[ 0]);
   z[ 0] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 0], y[ 1]);
   word3_muladd(&w0, &w2, &w1, x[ 1], y[ 0]);
   z[ 1] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 0], y[ 2]);
   word3_muladd(&w1, &w0, &w2, x[ 1], y[ 1]);
   word3_muladd(&w1, &w0, &w2, x[ 2], y[ 0]);
   z[ 2] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 0], y[ 3]);
   word3_muladd(&w2, &w1, &w0, x[ 1], y[ 2]);
   word3_muladd(&w2, &w1, &w0, x[ 2], y[ 1]);
   word3_muladd(&w2, &w1, &w0, x[ 3], y[ 0]);
   z[ 3] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 1], y[ 3]);
   word3_muladd(&w0, &w2, &w1, x[ 2], y[ 2]);
   word3_muladd(&w0, &w2, &w1, x[ 3], y[ 1]);
   z[ 4] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 2], y[ 3]);
   word3_muladd(&w1, &w0, &w2, x[ 3], y[ 2]);
   z[ 5] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 3], y[ 3]);
   z[ 6] = w0;
   z[ 7] = w1;
   }

/*
* Comba 6x6 Squaring
*/
void bigint_comba_sqr6(word z[12], const word x[6])
   {
   word w2 = 0, w1 = 0, w0 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 0], x[ 0]);
   z[ 0] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 0], x[ 1]);
   z[ 1] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[ 0], x[ 2]);
   word3_muladd(&w1, &w0, &w2, x[ 1], x[ 1]);
   z[ 2] = w2; w2 = 0;

   word3_muladd_2(&w2, &w1, &w0, x[ 0], x[ 3]);
   word3_muladd_2(&w2, &w1, &w0, x[ 1], x[ 2]);
   z[ 3] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 0], x[ 4]);
   word3_muladd_2(&w0, &w2, &w1, x[ 1], x[ 3]);
   word3_muladd(&w0, &w2, &w1, x[ 2], x[ 2]);
   z[ 4] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[ 0], x[ 5]);
   word3_muladd_2(&w1, &w0, &w2, x[ 1], x[ 4]);
   word3_muladd_2(&w1, &w0, &w2, x[ 2], x[ 3]);
   z[ 5] = w2; w2 = 0;

   word3_muladd_2(&w2, &w1, &w0, x[ 1], x[ 5]);
   word3_muladd_2(&w2, &w1, &w0, x[ 2], x[ 4]);
   word3_muladd(&w2, &w1, &w0, x[ 3], x[ 3]);
   z[ 6] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 2], x[ 5]);
   word3_muladd_2(&w0, &w2, &w1, x[ 3], x[ 4]);
   z[ 7] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[ 3], x[ 5]);
   word3_muladd(&w1, &w0, &w2, x[ 4], x[ 4]);
   z[ 8] = w2; w2 = 0;

   word3_muladd_2(&w2, &w1, &w0, x[ 4], x[ 5]);
   z[ 9] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 5], x[ 5]);
   z[10] = w1;
   z[11] = w2;
   }

/*
* Comba 6x6 Multiplication
*/
void bigint_comba_mul6(word z[12], const word x[6], const word y[6])
   {
   word w2 = 0, w1 = 0, w0 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 0], y[ 0]);
   z[ 0] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 0], y[ 1]);
   word3_muladd(&w0, &w2, &w1, x[ 1], y[ 0]);
   z[ 1] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 0], y[ 2]);
   word3_muladd(&w1, &w0, &w2, x[ 1], y[ 1]);
   word3_muladd(&w1, &w0, &w2, x[ 2], y[ 0]);
   z[ 2] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 0], y[ 3]);
   word3_muladd(&w2, &w1, &w0, x[ 1], y[ 2]);
   word3_muladd(&w2, &w1, &w0, x[ 2], y[ 1]);
   word3_muladd(&w2, &w1, &w0, x[ 3], y[ 0]);
   z[ 3] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 0], y[ 4]);
   word3_muladd(&w0, &w2, &w1, x[ 1], y[ 3]);
   word3_muladd(&w0, &w2, &w1, x[ 2], y[ 2]);
   word3_muladd(&w0, &w2, &w1, x[ 3], y[ 1]);
   word3_muladd(&w0, &w2, &w1, x[ 4], y[ 0]);
   z[ 4] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 0], y[ 5]);
   word3_muladd(&w1, &w0, &w2, x[ 1], y[ 4]);
   word3_muladd(&w1, &w0, &w2, x[ 2], y[ 3]);
   word3_muladd(&w1, &w0, &w2, x[ 3], y[ 2]);
   word3_muladd(&w1, &w0, &w2, x[ 4], y[ 1]);
   word3_muladd(&w1, &w0, &w2, x[ 5], y[ 0]);
   z[ 5] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 1], y[ 5]);
   word3_muladd(&w2, &w1, &w0, x[ 2], y[ 4]);
   word3_muladd(&w2, &w1, &w0, x[ 3], y[ 3]);
   word3_muladd(&w2, &w1, &w0, x[ 4], y[ 2]);
   word3_muladd(&w2, &w1, &w0, x[ 5], y[ 1]);
   z[ 6] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 2], y[ 5]);
   word3_muladd(&w0, &w2, &w1, x[ 3], y[ 4]);
   word3_muladd(&w0, &w2, &w1, x[ 4], y[ 3]);
   word3_muladd(&w0, &w2, &w1, x[ 5], y[ 2]);
   z[ 7] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 3], y[ 5]);
   word3_muladd(&w1, &w0, &w2, x[ 4], y[ 4]);
   word3_muladd(&w1, &w0, &w2, x[ 5], y[ 3]);
   z[ 8] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 4], y[ 5]);
   word3_muladd(&w2, &w1, &w0, x[ 5], y[ 4]);
   z[ 9] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 5], y[ 5]);
   z[10] = w1;
   z[11] = w2;
   }

/*
* Comba 8x8 Squaring
*/
void bigint_comba_sqr8(word z[16], const word x[8])
   {
   word w2 = 0, w1 = 0, w0 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 0], x[ 0]);
   z[ 0] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 0], x[ 1]);
   z[ 1] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[ 0], x[ 2]);
   word3_muladd(&w1, &w0, &w2, x[ 1], x[ 1]);
   z[ 2] = w2; w2 = 0;

   word3_muladd_2(&w2, &w1, &w0, x[ 0], x[ 3]);
   word3_muladd_2(&w2, &w1, &w0, x[ 1], x[ 2]);
   z[ 3] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 0], x[ 4]);
   word3_muladd_2(&w0, &w2, &w1, x[ 1], x[ 3]);
   word3_muladd(&w0, &w2, &w1, x[ 2], x[ 2]);
   z[ 4] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[ 0], x[ 5]);
   word3_muladd_2(&w1, &w0, &w2, x[ 1], x[ 4]);
   word3_muladd_2(&w1, &w0, &w2, x[ 2], x[ 3]);
   z[ 5] = w2; w2 = 0;

   word3_muladd_2(&w2, &w1, &w0, x[ 0], x[ 6]);
   word3_muladd_2(&w2, &w1, &w0, x[ 1], x[ 5]);
   word3_muladd_2(&w2, &w1, &w0, x[ 2], x[ 4]);
   word3_muladd(&w2, &w1, &w0, x[ 3], x[ 3]);
   z[ 6] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 0], x[ 7]);
   word3_muladd_2(&w0, &w2, &w1, x[ 1], x[ 6]);
   word3_muladd_2(&w0, &w2, &w1, x[ 2], x[ 5]);
   word3_muladd_2(&w0, &w2, &w1, x[ 3], x[ 4]);
   z[ 7] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[ 1], x[ 7]);
   word3_muladd_2(&w1, &w0, &w2, x[ 2], x[ 6]);
   word3_muladd_2(&w1, &w0, &w2, x[ 3], x[ 5]);
   word3_muladd(&w1, &w0, &w2, x[ 4], x[ 4]);
   z[ 8] = w2; w2 = 0;

   word3_muladd_2(&w2, &w1, &w0, x[ 2], x[ 7]);
   word3_muladd_2(&w2, &w1, &w0, x[ 3], x[ 6]);
   word3_muladd_2(&w2, &w1, &w0, x[ 4], x[ 5]);
   z[ 9] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 3], x[ 7]);
   word3_muladd_2(&w0, &w2, &w1, x[ 4], x[ 6]);
   word3_muladd(&w0, &w2, &w1, x[ 5], x[ 5]);
   z[10] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[ 4], x[ 7]);
   word3_muladd_2(&w1, &w0, &w2, x[ 5], x[ 6]);
   z[11] = w2; w2 = 0;

   word3_muladd_2(&w2, &w1, &w0, x[ 5], x[ 7]);
   word3_muladd(&w2, &w1, &w0, x[ 6], x[ 6]);
   z[12] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 6], x[ 7]);
   z[13] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 7], x[ 7]);
   z[14] = w2;
   z[15] = w0;
   }

/*
* Comba 8x8 Multiplication
*/
void bigint_comba_mul8(word z[16], const word x[8], const word y[8])
   {
   word w2 = 0, w1 = 0, w0 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 0], y[ 0]);
   z[ 0] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 0], y[ 1]);
   word3_muladd(&w0, &w2, &w1, x[ 1], y[ 0]);
   z[ 1] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 0], y[ 2]);
   word3_muladd(&w1, &w0, &w2, x[ 1], y[ 1]);
   word3_muladd(&w1, &w0, &w2, x[ 2], y[ 0]);
   z[ 2] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 0], y[ 3]);
   word3_muladd(&w2, &w1, &w0, x[ 1], y[ 2]);
   word3_muladd(&w2, &w1, &w0, x[ 2], y[ 1]);
   word3_muladd(&w2, &w1, &w0, x[ 3], y[ 0]);
   z[ 3] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 0], y[ 4]);
   word3_muladd(&w0, &w2, &w1, x[ 1], y[ 3]);
   word3_muladd(&w0, &w2, &w1, x[ 2], y[ 2]);
   word3_muladd(&w0, &w2, &w1, x[ 3], y[ 1]);
   word3_muladd(&w0, &w2, &w1, x[ 4], y[ 0]);
   z[ 4] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 0], y[ 5]);
   word3_muladd(&w1, &w0, &w2, x[ 1], y[ 4]);
   word3_muladd(&w1, &w0, &w2, x[ 2], y[ 3]);
   word3_muladd(&w1, &w0, &w2, x[ 3], y[ 2]);
   word3_muladd(&w1, &w0, &w2, x[ 4], y[ 1]);
   word3_muladd(&w1, &w0, &w2, x[ 5], y[ 0]);
   z[ 5] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 0], y[ 6]);
   word3_muladd(&w2, &w1, &w0, x[ 1], y[ 5]);
   word3_muladd(&w2, &w1, &w0, x[ 2], y[ 4]);
   word3_muladd(&w2, &w1, &w0, x[ 3], y[ 3]);
   word3_muladd(&w2, &w1, &w0, x[ 4], y[ 2]);
   word3_muladd(&w2, &w1, &w0, x[ 5], y[ 1]);
   word3_muladd(&w2, &w1, &w0, x[ 6], y[ 0]);
   z[ 6] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 0], y[ 7]);
   word3_muladd(&w0, &w2, &w1, x[ 1], y[ 6]);
   word3_muladd(&w0, &w2, &w1, x[ 2], y[ 5]);
   word3_muladd(&w0, &w2, &w1, x[ 3], y[ 4]);
   word3_muladd(&w0, &w2, &w1, x[ 4], y[ 3]);
   word3_muladd(&w0, &w2, &w1, x[ 5], y[ 2]);
   word3_muladd(&w0, &w2, &w1, x[ 6], y[ 1]);
   word3_muladd(&w0, &w2, &w1, x[ 7], y[ 0]);
   z[ 7] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 1], y[ 7]);
   word3_muladd(&w1, &w0, &w2, x[ 2], y[ 6]);
   word3_muladd(&w1, &w0, &w2, x[ 3], y[ 5]);
   word3_muladd(&w1, &w0, &w2, x[ 4], y[ 4]);
   word3_muladd(&w1, &w0, &w2, x[ 5], y[ 3]);
   word3_muladd(&w1, &w0, &w2, x[ 6], y[ 2]);
   word3_muladd(&w1, &w0, &w2, x[ 7], y[ 1]);
   z[ 8] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 2], y[ 7]);
   word3_muladd(&w2, &w1, &w0, x[ 3], y[ 6]);
   word3_muladd(&w2, &w1, &w0, x[ 4], y[ 5]);
   word3_muladd(&w2, &w1, &w0, x[ 5], y[ 4]);
   word3_muladd(&w2, &w1, &w0, x[ 6], y[ 3]);
   word3_muladd(&w2, &w1, &w0, x[ 7], y[ 2]);
   z[ 9] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 3], y[ 7]);
   word3_muladd(&w0, &w2, &w1, x[ 4], y[ 6]);
   word3_muladd(&w0, &w2, &w1, x[ 5], y[ 5]);
   word3_muladd(&w0, &w2, &w1, x[ 6], y[ 4]);
   word3_muladd(&w0, &w2, &w1, x[ 7], y[ 3]);
   z[10] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 4], y[ 7]);
   word3_muladd(&w1, &w0, &w2, x[ 5], y[ 6]);
   word3_muladd(&w1, &w0, &w2, x[ 6], y[ 5]);
   word3_muladd(&w1, &w0, &w2, x[ 7], y[ 4]);
   z[11] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 5], y[ 7]);
   word3_muladd(&w2, &w1, &w0, x[ 6], y[ 6]);
   word3_muladd(&w2, &w1, &w0, x[ 7], y[ 5]);
   z[12] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 6], y[ 7]);
   word3_muladd(&w0, &w2, &w1, x[ 7], y[ 6]);
   z[13] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 7], y[ 7]);
   z[14] = w2;
   z[15] = w0;
   }

/*
* Comba 16x16 Squaring
*/
void bigint_comba_sqr16(word z[32], const word x[16])
   {
   word w2 = 0, w1 = 0, w0 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 0], x[ 0]);
   z[ 0] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 0], x[ 1]);
   z[ 1] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[ 0], x[ 2]);
   word3_muladd(&w1, &w0, &w2, x[ 1], x[ 1]);
   z[ 2] = w2; w2 = 0;

   word3_muladd_2(&w2, &w1, &w0, x[ 0], x[ 3]);
   word3_muladd_2(&w2, &w1, &w0, x[ 1], x[ 2]);
   z[ 3] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 0], x[ 4]);
   word3_muladd_2(&w0, &w2, &w1, x[ 1], x[ 3]);
   word3_muladd(&w0, &w2, &w1, x[ 2], x[ 2]);
   z[ 4] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[ 0], x[ 5]);
   word3_muladd_2(&w1, &w0, &w2, x[ 1], x[ 4]);
   word3_muladd_2(&w1, &w0, &w2, x[ 2], x[ 3]);
   z[ 5] = w2; w2 = 0;

   word3_muladd_2(&w2, &w1, &w0, x[ 0], x[ 6]);
   word3_muladd_2(&w2, &w1, &w0, x[ 1], x[ 5]);
   word3_muladd_2(&w2, &w1, &w0, x[ 2], x[ 4]);
   word3_muladd(&w2, &w1, &w0, x[ 3], x[ 3]);
   z[ 6] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 0], x[ 7]);
   word3_muladd_2(&w0, &w2, &w1, x[ 1], x[ 6]);
   word3_muladd_2(&w0, &w2, &w1, x[ 2], x[ 5]);
   word3_muladd_2(&w0, &w2, &w1, x[ 3], x[ 4]);
   z[ 7] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[ 0], x[ 8]);
   word3_muladd_2(&w1, &w0, &w2, x[ 1], x[ 7]);
   word3_muladd_2(&w1, &w0, &w2, x[ 2], x[ 6]);
   word3_muladd_2(&w1, &w0, &w2, x[ 3], x[ 5]);
   word3_muladd(&w1, &w0, &w2, x[ 4], x[ 4]);
   z[ 8] = w2; w2 = 0;

   word3_muladd_2(&w2, &w1, &w0, x[ 0], x[ 9]);
   word3_muladd_2(&w2, &w1, &w0, x[ 1], x[ 8]);
   word3_muladd_2(&w2, &w1, &w0, x[ 2], x[ 7]);
   word3_muladd_2(&w2, &w1, &w0, x[ 3], x[ 6]);
   word3_muladd_2(&w2, &w1, &w0, x[ 4], x[ 5]);
   z[ 9] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 0], x[10]);
   word3_muladd_2(&w0, &w2, &w1, x[ 1], x[ 9]);
   word3_muladd_2(&w0, &w2, &w1, x[ 2], x[ 8]);
   word3_muladd_2(&w0, &w2, &w1, x[ 3], x[ 7]);
   word3_muladd_2(&w0, &w2, &w1, x[ 4], x[ 6]);
   word3_muladd(&w0, &w2, &w1, x[ 5], x[ 5]);
   z[10] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[ 0], x[11]);
   word3_muladd_2(&w1, &w0, &w2, x[ 1], x[10]);
   word3_muladd_2(&w1, &w0, &w2, x[ 2], x[ 9]);
   word3_muladd_2(&w1, &w0, &w2, x[ 3], x[ 8]);
   word3_muladd_2(&w1, &w0, &w2, x[ 4], x[ 7]);
   word3_muladd_2(&w1, &w0, &w2, x[ 5], x[ 6]);
   z[11] = w2; w2 = 0;

   word3_muladd_2(&w2, &w1, &w0, x[ 0], x[12]);
   word3_muladd_2(&w2, &w1, &w0, x[ 1], x[11]);
   word3_muladd_2(&w2, &w1, &w0, x[ 2], x[10]);
   word3_muladd_2(&w2, &w1, &w0, x[ 3], x[ 9]);
   word3_muladd_2(&w2, &w1, &w0, x[ 4], x[ 8]);
   word3_muladd_2(&w2, &w1, &w0, x[ 5], x[ 7]);
   word3_muladd(&w2, &w1, &w0, x[ 6], x[ 6]);
   z[12] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 0], x[13]);
   word3_muladd_2(&w0, &w2, &w1, x[ 1], x[12]);
   word3_muladd_2(&w0, &w2, &w1, x[ 2], x[11]);
   word3_muladd_2(&w0, &w2, &w1, x[ 3], x[10]);
   word3_muladd_2(&w0, &w2, &w1, x[ 4], x[ 9]);
   word3_muladd_2(&w0, &w2, &w1, x[ 5], x[ 8]);
   word3_muladd_2(&w0, &w2, &w1, x[ 6], x[ 7]);
   z[13] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[ 0], x[14]);
   word3_muladd_2(&w1, &w0, &w2, x[ 1], x[13]);
   word3_muladd_2(&w1, &w0, &w2, x[ 2], x[12]);
   word3_muladd_2(&w1, &w0, &w2, x[ 3], x[11]);
   word3_muladd_2(&w1, &w0, &w2, x[ 4], x[10]);
   word3_muladd_2(&w1, &w0, &w2, x[ 5], x[ 9]);
   word3_muladd_2(&w1, &w0, &w2, x[ 6], x[ 8]);
   word3_muladd(&w1, &w0, &w2, x[ 7], x[ 7]);
   z[14] = w2; w2 = 0;

   word3_muladd_2(&w2, &w1, &w0, x[ 0], x[15]);
   word3_muladd_2(&w2, &w1, &w0, x[ 1], x[14]);
   word3_muladd_2(&w2, &w1, &w0, x[ 2], x[13]);
   word3_muladd_2(&w2, &w1, &w0, x[ 3], x[12]);
   word3_muladd_2(&w2, &w1, &w0, x[ 4], x[11]);
   word3_muladd_2(&w2, &w1, &w0, x[ 5], x[10]);
   word3_muladd_2(&w2, &w1, &w0, x[ 6], x[ 9]);
   word3_muladd_2(&w2, &w1, &w0, x[ 7], x[ 8]);
   z[15] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 1], x[15]);
   word3_muladd_2(&w0, &w2, &w1, x[ 2], x[14]);
   word3_muladd_2(&w0, &w2, &w1, x[ 3], x[13]);
   word3_muladd_2(&w0, &w2, &w1, x[ 4], x[12]);
   word3_muladd_2(&w0, &w2, &w1, x[ 5], x[11]);
   word3_muladd_2(&w0, &w2, &w1, x[ 6], x[10]);
   word3_muladd_2(&w0, &w2, &w1, x[ 7], x[ 9]);
   word3_muladd(&w0, &w2, &w1, x[ 8], x[ 8]);
   z[16] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[ 2], x[15]);
   word3_muladd_2(&w1, &w0, &w2, x[ 3], x[14]);
   word3_muladd_2(&w1, &w0, &w2, x[ 4], x[13]);
   word3_muladd_2(&w1, &w0, &w2, x[ 5], x[12]);
   word3_muladd_2(&w1, &w0, &w2, x[ 6], x[11]);
   word3_muladd_2(&w1, &w0, &w2, x[ 7], x[10]);
   word3_muladd_2(&w1, &w0, &w2, x[ 8], x[ 9]);
   z[17] = w2; w2 = 0;

   word3_muladd_2(&w2, &w1, &w0, x[ 3], x[15]);
   word3_muladd_2(&w2, &w1, &w0, x[ 4], x[14]);
   word3_muladd_2(&w2, &w1, &w0, x[ 5], x[13]);
   word3_muladd_2(&w2, &w1, &w0, x[ 6], x[12]);
   word3_muladd_2(&w2, &w1, &w0, x[ 7], x[11]);
   word3_muladd_2(&w2, &w1, &w0, x[ 8], x[10]);
   word3_muladd(&w2, &w1, &w0, x[ 9], x[ 9]);
   z[18] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 4], x[15]);
   word3_muladd_2(&w0, &w2, &w1, x[ 5], x[14]);
   word3_muladd_2(&w0, &w2, &w1, x[ 6], x[13]);
   word3_muladd_2(&w0, &w2, &w1, x[ 7], x[12]);
   word3_muladd_2(&w0, &w2, &w1, x[ 8], x[11]);
   word3_muladd_2(&w0, &w2, &w1, x[ 9], x[10]);
   z[19] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[ 5], x[15]);
   word3_muladd_2(&w1, &w0, &w2, x[ 6], x[14]);
   word3_muladd_2(&w1, &w0, &w2, x[ 7], x[13]);
   word3_muladd_2(&w1, &w0, &w2, x[ 8], x[12]);
   word3_muladd_2(&w1, &w0, &w2, x[ 9], x[11]);
   word3_muladd(&w1, &w0, &w2, x[10], x[10]);
   z[20] = w2; w2 = 0;

   word3_muladd_2(&w2, &w1, &w0, x[ 6], x[15]);
   word3_muladd_2(&w2, &w1, &w0, x[ 7], x[14]);
   word3_muladd_2(&w2, &w1, &w0, x[ 8], x[13]);
   word3_muladd_2(&w2, &w1, &w0, x[ 9], x[12]);
   word3_muladd_2(&w2, &w1, &w0, x[10], x[11]);
   z[21] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[ 7], x[15]);
   word3_muladd_2(&w0, &w2, &w1, x[ 8], x[14]);
   word3_muladd_2(&w0, &w2, &w1, x[ 9], x[13]);
   word3_muladd_2(&w0, &w2, &w1, x[10], x[12]);
   word3_muladd(&w0, &w2, &w1, x[11], x[11]);
   z[22] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[ 8], x[15]);
   word3_muladd_2(&w1, &w0, &w2, x[ 9], x[14]);
   word3_muladd_2(&w1, &w0, &w2, x[10], x[13]);
   word3_muladd_2(&w1, &w0, &w2, x[11], x[12]);
   z[23] = w2; w2 = 0;

   word3_muladd_2(&w2, &w1, &w0, x[ 9], x[15]);
   word3_muladd_2(&w2, &w1, &w0, x[10], x[14]);
   word3_muladd_2(&w2, &w1, &w0, x[11], x[13]);
   word3_muladd(&w2, &w1, &w0, x[12], x[12]);
   z[24] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[10], x[15]);
   word3_muladd_2(&w0, &w2, &w1, x[11], x[14]);
   word3_muladd_2(&w0, &w2, &w1, x[12], x[13]);
   z[25] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[11], x[15]);
   word3_muladd_2(&w1, &w0, &w2, x[12], x[14]);
   word3_muladd(&w1, &w0, &w2, x[13], x[13]);
   z[26] = w2; w2 = 0;

   word3_muladd_2(&w2, &w1, &w0, x[12], x[15]);
   word3_muladd_2(&w2, &w1, &w0, x[13], x[14]);
   z[27] = w0; w0 = 0;

   word3_muladd_2(&w0, &w2, &w1, x[13], x[15]);
   word3_muladd(&w0, &w2, &w1, x[14], x[14]);
   z[28] = w1; w1 = 0;

   word3_muladd_2(&w1, &w0, &w2, x[14], x[15]);
   z[29] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[15], x[15]);
   z[30] = w0;
   z[31] = w1;
   }

/*
* Comba 16x16 Multiplication
*/
void bigint_comba_mul16(word z[32], const word x[16], const word y[16])
   {
   word w2 = 0, w1 = 0, w0 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 0], y[ 0]);
   z[ 0] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 0], y[ 1]);
   word3_muladd(&w0, &w2, &w1, x[ 1], y[ 0]);
   z[ 1] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 0], y[ 2]);
   word3_muladd(&w1, &w0, &w2, x[ 1], y[ 1]);
   word3_muladd(&w1, &w0, &w2, x[ 2], y[ 0]);
   z[ 2] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 0], y[ 3]);
   word3_muladd(&w2, &w1, &w0, x[ 1], y[ 2]);
   word3_muladd(&w2, &w1, &w0, x[ 2], y[ 1]);
   word3_muladd(&w2, &w1, &w0, x[ 3], y[ 0]);
   z[ 3] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 0], y[ 4]);
   word3_muladd(&w0, &w2, &w1, x[ 1], y[ 3]);
   word3_muladd(&w0, &w2, &w1, x[ 2], y[ 2]);
   word3_muladd(&w0, &w2, &w1, x[ 3], y[ 1]);
   word3_muladd(&w0, &w2, &w1, x[ 4], y[ 0]);
   z[ 4] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 0], y[ 5]);
   word3_muladd(&w1, &w0, &w2, x[ 1], y[ 4]);
   word3_muladd(&w1, &w0, &w2, x[ 2], y[ 3]);
   word3_muladd(&w1, &w0, &w2, x[ 3], y[ 2]);
   word3_muladd(&w1, &w0, &w2, x[ 4], y[ 1]);
   word3_muladd(&w1, &w0, &w2, x[ 5], y[ 0]);
   z[ 5] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 0], y[ 6]);
   word3_muladd(&w2, &w1, &w0, x[ 1], y[ 5]);
   word3_muladd(&w2, &w1, &w0, x[ 2], y[ 4]);
   word3_muladd(&w2, &w1, &w0, x[ 3], y[ 3]);
   word3_muladd(&w2, &w1, &w0, x[ 4], y[ 2]);
   word3_muladd(&w2, &w1, &w0, x[ 5], y[ 1]);
   word3_muladd(&w2, &w1, &w0, x[ 6], y[ 0]);
   z[ 6] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 0], y[ 7]);
   word3_muladd(&w0, &w2, &w1, x[ 1], y[ 6]);
   word3_muladd(&w0, &w2, &w1, x[ 2], y[ 5]);
   word3_muladd(&w0, &w2, &w1, x[ 3], y[ 4]);
   word3_muladd(&w0, &w2, &w1, x[ 4], y[ 3]);
   word3_muladd(&w0, &w2, &w1, x[ 5], y[ 2]);
   word3_muladd(&w0, &w2, &w1, x[ 6], y[ 1]);
   word3_muladd(&w0, &w2, &w1, x[ 7], y[ 0]);
   z[ 7] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 0], y[ 8]);
   word3_muladd(&w1, &w0, &w2, x[ 1], y[ 7]);
   word3_muladd(&w1, &w0, &w2, x[ 2], y[ 6]);
   word3_muladd(&w1, &w0, &w2, x[ 3], y[ 5]);
   word3_muladd(&w1, &w0, &w2, x[ 4], y[ 4]);
   word3_muladd(&w1, &w0, &w2, x[ 5], y[ 3]);
   word3_muladd(&w1, &w0, &w2, x[ 6], y[ 2]);
   word3_muladd(&w1, &w0, &w2, x[ 7], y[ 1]);
   word3_muladd(&w1, &w0, &w2, x[ 8], y[ 0]);
   z[ 8] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 0], y[ 9]);
   word3_muladd(&w2, &w1, &w0, x[ 1], y[ 8]);
   word3_muladd(&w2, &w1, &w0, x[ 2], y[ 7]);
   word3_muladd(&w2, &w1, &w0, x[ 3], y[ 6]);
   word3_muladd(&w2, &w1, &w0, x[ 4], y[ 5]);
   word3_muladd(&w2, &w1, &w0, x[ 5], y[ 4]);
   word3_muladd(&w2, &w1, &w0, x[ 6], y[ 3]);
   word3_muladd(&w2, &w1, &w0, x[ 7], y[ 2]);
   word3_muladd(&w2, &w1, &w0, x[ 8], y[ 1]);
   word3_muladd(&w2, &w1, &w0, x[ 9], y[ 0]);
   z[ 9] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 0], y[10]);
   word3_muladd(&w0, &w2, &w1, x[ 1], y[ 9]);
   word3_muladd(&w0, &w2, &w1, x[ 2], y[ 8]);
   word3_muladd(&w0, &w2, &w1, x[ 3], y[ 7]);
   word3_muladd(&w0, &w2, &w1, x[ 4], y[ 6]);
   word3_muladd(&w0, &w2, &w1, x[ 5], y[ 5]);
   word3_muladd(&w0, &w2, &w1, x[ 6], y[ 4]);
   word3_muladd(&w0, &w2, &w1, x[ 7], y[ 3]);
   word3_muladd(&w0, &w2, &w1, x[ 8], y[ 2]);
   word3_muladd(&w0, &w2, &w1, x[ 9], y[ 1]);
   word3_muladd(&w0, &w2, &w1, x[10], y[ 0]);
   z[10] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 0], y[11]);
   word3_muladd(&w1, &w0, &w2, x[ 1], y[10]);
   word3_muladd(&w1, &w0, &w2, x[ 2], y[ 9]);
   word3_muladd(&w1, &w0, &w2, x[ 3], y[ 8]);
   word3_muladd(&w1, &w0, &w2, x[ 4], y[ 7]);
   word3_muladd(&w1, &w0, &w2, x[ 5], y[ 6]);
   word3_muladd(&w1, &w0, &w2, x[ 6], y[ 5]);
   word3_muladd(&w1, &w0, &w2, x[ 7], y[ 4]);
   word3_muladd(&w1, &w0, &w2, x[ 8], y[ 3]);
   word3_muladd(&w1, &w0, &w2, x[ 9], y[ 2]);
   word3_muladd(&w1, &w0, &w2, x[10], y[ 1]);
   word3_muladd(&w1, &w0, &w2, x[11], y[ 0]);
   z[11] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 0], y[12]);
   word3_muladd(&w2, &w1, &w0, x[ 1], y[11]);
   word3_muladd(&w2, &w1, &w0, x[ 2], y[10]);
   word3_muladd(&w2, &w1, &w0, x[ 3], y[ 9]);
   word3_muladd(&w2, &w1, &w0, x[ 4], y[ 8]);
   word3_muladd(&w2, &w1, &w0, x[ 5], y[ 7]);
   word3_muladd(&w2, &w1, &w0, x[ 6], y[ 6]);
   word3_muladd(&w2, &w1, &w0, x[ 7], y[ 5]);
   word3_muladd(&w2, &w1, &w0, x[ 8], y[ 4]);
   word3_muladd(&w2, &w1, &w0, x[ 9], y[ 3]);
   word3_muladd(&w2, &w1, &w0, x[10], y[ 2]);
   word3_muladd(&w2, &w1, &w0, x[11], y[ 1]);
   word3_muladd(&w2, &w1, &w0, x[12], y[ 0]);
   z[12] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 0], y[13]);
   word3_muladd(&w0, &w2, &w1, x[ 1], y[12]);
   word3_muladd(&w0, &w2, &w1, x[ 2], y[11]);
   word3_muladd(&w0, &w2, &w1, x[ 3], y[10]);
   word3_muladd(&w0, &w2, &w1, x[ 4], y[ 9]);
   word3_muladd(&w0, &w2, &w1, x[ 5], y[ 8]);
   word3_muladd(&w0, &w2, &w1, x[ 6], y[ 7]);
   word3_muladd(&w0, &w2, &w1, x[ 7], y[ 6]);
   word3_muladd(&w0, &w2, &w1, x[ 8], y[ 5]);
   word3_muladd(&w0, &w2, &w1, x[ 9], y[ 4]);
   word3_muladd(&w0, &w2, &w1, x[10], y[ 3]);
   word3_muladd(&w0, &w2, &w1, x[11], y[ 2]);
   word3_muladd(&w0, &w2, &w1, x[12], y[ 1]);
   word3_muladd(&w0, &w2, &w1, x[13], y[ 0]);
   z[13] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 0], y[14]);
   word3_muladd(&w1, &w0, &w2, x[ 1], y[13]);
   word3_muladd(&w1, &w0, &w2, x[ 2], y[12]);
   word3_muladd(&w1, &w0, &w2, x[ 3], y[11]);
   word3_muladd(&w1, &w0, &w2, x[ 4], y[10]);
   word3_muladd(&w1, &w0, &w2, x[ 5], y[ 9]);
   word3_muladd(&w1, &w0, &w2, x[ 6], y[ 8]);
   word3_muladd(&w1, &w0, &w2, x[ 7], y[ 7]);
   word3_muladd(&w1, &w0, &w2, x[ 8], y[ 6]);
   word3_muladd(&w1, &w0, &w2, x[ 9], y[ 5]);
   word3_muladd(&w1, &w0, &w2, x[10], y[ 4]);
   word3_muladd(&w1, &w0, &w2, x[11], y[ 3]);
   word3_muladd(&w1, &w0, &w2, x[12], y[ 2]);
   word3_muladd(&w1, &w0, &w2, x[13], y[ 1]);
   word3_muladd(&w1, &w0, &w2, x[14], y[ 0]);
   z[14] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 0], y[15]);
   word3_muladd(&w2, &w1, &w0, x[ 1], y[14]);
   word3_muladd(&w2, &w1, &w0, x[ 2], y[13]);
   word3_muladd(&w2, &w1, &w0, x[ 3], y[12]);
   word3_muladd(&w2, &w1, &w0, x[ 4], y[11]);
   word3_muladd(&w2, &w1, &w0, x[ 5], y[10]);
   word3_muladd(&w2, &w1, &w0, x[ 6], y[ 9]);
   word3_muladd(&w2, &w1, &w0, x[ 7], y[ 8]);
   word3_muladd(&w2, &w1, &w0, x[ 8], y[ 7]);
   word3_muladd(&w2, &w1, &w0, x[ 9], y[ 6]);
   word3_muladd(&w2, &w1, &w0, x[10], y[ 5]);
   word3_muladd(&w2, &w1, &w0, x[11], y[ 4]);
   word3_muladd(&w2, &w1, &w0, x[12], y[ 3]);
   word3_muladd(&w2, &w1, &w0, x[13], y[ 2]);
   word3_muladd(&w2, &w1, &w0, x[14], y[ 1]);
   word3_muladd(&w2, &w1, &w0, x[15], y[ 0]);
   z[15] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 1], y[15]);
   word3_muladd(&w0, &w2, &w1, x[ 2], y[14]);
   word3_muladd(&w0, &w2, &w1, x[ 3], y[13]);
   word3_muladd(&w0, &w2, &w1, x[ 4], y[12]);
   word3_muladd(&w0, &w2, &w1, x[ 5], y[11]);
   word3_muladd(&w0, &w2, &w1, x[ 6], y[10]);
   word3_muladd(&w0, &w2, &w1, x[ 7], y[ 9]);
   word3_muladd(&w0, &w2, &w1, x[ 8], y[ 8]);
   word3_muladd(&w0, &w2, &w1, x[ 9], y[ 7]);
   word3_muladd(&w0, &w2, &w1, x[10], y[ 6]);
   word3_muladd(&w0, &w2, &w1, x[11], y[ 5]);
   word3_muladd(&w0, &w2, &w1, x[12], y[ 4]);
   word3_muladd(&w0, &w2, &w1, x[13], y[ 3]);
   word3_muladd(&w0, &w2, &w1, x[14], y[ 2]);
   word3_muladd(&w0, &w2, &w1, x[15], y[ 1]);
   z[16] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 2], y[15]);
   word3_muladd(&w1, &w0, &w2, x[ 3], y[14]);
   word3_muladd(&w1, &w0, &w2, x[ 4], y[13]);
   word3_muladd(&w1, &w0, &w2, x[ 5], y[12]);
   word3_muladd(&w1, &w0, &w2, x[ 6], y[11]);
   word3_muladd(&w1, &w0, &w2, x[ 7], y[10]);
   word3_muladd(&w1, &w0, &w2, x[ 8], y[ 9]);
   word3_muladd(&w1, &w0, &w2, x[ 9], y[ 8]);
   word3_muladd(&w1, &w0, &w2, x[10], y[ 7]);
   word3_muladd(&w1, &w0, &w2, x[11], y[ 6]);
   word3_muladd(&w1, &w0, &w2, x[12], y[ 5]);
   word3_muladd(&w1, &w0, &w2, x[13], y[ 4]);
   word3_muladd(&w1, &w0, &w2, x[14], y[ 3]);
   word3_muladd(&w1, &w0, &w2, x[15], y[ 2]);
   z[17] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 3], y[15]);
   word3_muladd(&w2, &w1, &w0, x[ 4], y[14]);
   word3_muladd(&w2, &w1, &w0, x[ 5], y[13]);
   word3_muladd(&w2, &w1, &w0, x[ 6], y[12]);
   word3_muladd(&w2, &w1, &w0, x[ 7], y[11]);
   word3_muladd(&w2, &w1, &w0, x[ 8], y[10]);
   word3_muladd(&w2, &w1, &w0, x[ 9], y[ 9]);
   word3_muladd(&w2, &w1, &w0, x[10], y[ 8]);
   word3_muladd(&w2, &w1, &w0, x[11], y[ 7]);
   word3_muladd(&w2, &w1, &w0, x[12], y[ 6]);
   word3_muladd(&w2, &w1, &w0, x[13], y[ 5]);
   word3_muladd(&w2, &w1, &w0, x[14], y[ 4]);
   word3_muladd(&w2, &w1, &w0, x[15], y[ 3]);
   z[18] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 4], y[15]);
   word3_muladd(&w0, &w2, &w1, x[ 5], y[14]);
   word3_muladd(&w0, &w2, &w1, x[ 6], y[13]);
   word3_muladd(&w0, &w2, &w1, x[ 7], y[12]);
   word3_muladd(&w0, &w2, &w1, x[ 8], y[11]);
   word3_muladd(&w0, &w2, &w1, x[ 9], y[10]);
   word3_muladd(&w0, &w2, &w1, x[10], y[ 9]);
   word3_muladd(&w0, &w2, &w1, x[11], y[ 8]);
   word3_muladd(&w0, &w2, &w1, x[12], y[ 7]);
   word3_muladd(&w0, &w2, &w1, x[13], y[ 6]);
   word3_muladd(&w0, &w2, &w1, x[14], y[ 5]);
   word3_muladd(&w0, &w2, &w1, x[15], y[ 4]);
   z[19] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 5], y[15]);
   word3_muladd(&w1, &w0, &w2, x[ 6], y[14]);
   word3_muladd(&w1, &w0, &w2, x[ 7], y[13]);
   word3_muladd(&w1, &w0, &w2, x[ 8], y[12]);
   word3_muladd(&w1, &w0, &w2, x[ 9], y[11]);
   word3_muladd(&w1, &w0, &w2, x[10], y[10]);
   word3_muladd(&w1, &w0, &w2, x[11], y[ 9]);
   word3_muladd(&w1, &w0, &w2, x[12], y[ 8]);
   word3_muladd(&w1, &w0, &w2, x[13], y[ 7]);
   word3_muladd(&w1, &w0, &w2, x[14], y[ 6]);
   word3_muladd(&w1, &w0, &w2, x[15], y[ 5]);
   z[20] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 6], y[15]);
   word3_muladd(&w2, &w1, &w0, x[ 7], y[14]);
   word3_muladd(&w2, &w1, &w0, x[ 8], y[13]);
   word3_muladd(&w2, &w1, &w0, x[ 9], y[12]);
   word3_muladd(&w2, &w1, &w0, x[10], y[11]);
   word3_muladd(&w2, &w1, &w0, x[11], y[10]);
   word3_muladd(&w2, &w1, &w0, x[12], y[ 9]);
   word3_muladd(&w2, &w1, &w0, x[13], y[ 8]);
   word3_muladd(&w2, &w1, &w0, x[14], y[ 7]);
   word3_muladd(&w2, &w1, &w0, x[15], y[ 6]);
   z[21] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[ 7], y[15]);
   word3_muladd(&w0, &w2, &w1, x[ 8], y[14]);
   word3_muladd(&w0, &w2, &w1, x[ 9], y[13]);
   word3_muladd(&w0, &w2, &w1, x[10], y[12]);
   word3_muladd(&w0, &w2, &w1, x[11], y[11]);
   word3_muladd(&w0, &w2, &w1, x[12], y[10]);
   word3_muladd(&w0, &w2, &w1, x[13], y[ 9]);
   word3_muladd(&w0, &w2, &w1, x[14], y[ 8]);
   word3_muladd(&w0, &w2, &w1, x[15], y[ 7]);
   z[22] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[ 8], y[15]);
   word3_muladd(&w1, &w0, &w2, x[ 9], y[14]);
   word3_muladd(&w1, &w0, &w2, x[10], y[13]);
   word3_muladd(&w1, &w0, &w2, x[11], y[12]);
   word3_muladd(&w1, &w0, &w2, x[12], y[11]);
   word3_muladd(&w1, &w0, &w2, x[13], y[10]);
   word3_muladd(&w1, &w0, &w2, x[14], y[ 9]);
   word3_muladd(&w1, &w0, &w2, x[15], y[ 8]);
   z[23] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[ 9], y[15]);
   word3_muladd(&w2, &w1, &w0, x[10], y[14]);
   word3_muladd(&w2, &w1, &w0, x[11], y[13]);
   word3_muladd(&w2, &w1, &w0, x[12], y[12]);
   word3_muladd(&w2, &w1, &w0, x[13], y[11]);
   word3_muladd(&w2, &w1, &w0, x[14], y[10]);
   word3_muladd(&w2, &w1, &w0, x[15], y[ 9]);
   z[24] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[10], y[15]);
   word3_muladd(&w0, &w2, &w1, x[11], y[14]);
   word3_muladd(&w0, &w2, &w1, x[12], y[13]);
   word3_muladd(&w0, &w2, &w1, x[13], y[12]);
   word3_muladd(&w0, &w2, &w1, x[14], y[11]);
   word3_muladd(&w0, &w2, &w1, x[15], y[10]);
   z[25] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[11], y[15]);
   word3_muladd(&w1, &w0, &w2, x[12], y[14]);
   word3_muladd(&w1, &w0, &w2, x[13], y[13]);
   word3_muladd(&w1, &w0, &w2, x[14], y[12]);
   word3_muladd(&w1, &w0, &w2, x[15], y[11]);
   z[26] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[12], y[15]);
   word3_muladd(&w2, &w1, &w0, x[13], y[14]);
   word3_muladd(&w2, &w1, &w0, x[14], y[13]);
   word3_muladd(&w2, &w1, &w0, x[15], y[12]);
   z[27] = w0; w0 = 0;

   word3_muladd(&w0, &w2, &w1, x[13], y[15]);
   word3_muladd(&w0, &w2, &w1, x[14], y[14]);
   word3_muladd(&w0, &w2, &w1, x[15], y[13]);
   z[28] = w1; w1 = 0;

   word3_muladd(&w1, &w0, &w2, x[14], y[15]);
   word3_muladd(&w1, &w0, &w2, x[15], y[14]);
   z[29] = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[15], y[15]);
   z[30] = w0;
   z[31] = w1;
   }

}

}
