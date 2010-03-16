/*
* MPI Algorithms
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_MP_CORE_H__
#define BOTAN_MP_CORE_H__

#include <botan/mp_types.h>

namespace Botan {

/*
* The size of the word type, in bits
*/
const u32bit MP_WORD_BITS = BOTAN_MP_WORD_BITS;

extern "C" {

/*
* Addition/Subtraction Operations
*/
void bigint_add2(word x[], u32bit x_size,
                 const word y[], u32bit y_size);

void bigint_add3(word z[],
                 const word x[], u32bit x_size,
                 const word y[], u32bit y_size);

word bigint_add2_nc(word x[], u32bit x_size, const word y[], u32bit y_size);

word bigint_add3_nc(word z[],
                    const word x[], u32bit x_size,
                    const word y[], u32bit y_size);

void bigint_sub2(word x[], u32bit x_size,
                 const word y[], u32bit y_size);

/**
* x = y - x; assumes y >= x
*/
void bigint_sub2_rev(word x[], const word y[], u32bit y_size);

void bigint_sub3(word z[],
                 const word x[], u32bit x_size,
                 const word y[], u32bit y_size);

/*
* Shift Operations
*/
void bigint_shl1(word x[], u32bit x_size,
                 u32bit word_shift, u32bit bit_shift);

void bigint_shr1(word x[], u32bit x_size,
                 u32bit word_shift, u32bit bit_shift);

void bigint_shl2(word y[], const word x[], u32bit x_size,
                 u32bit word_shift, u32bit bit_shift);

void bigint_shr2(word y[], const word x[], u32bit x_size,
                 u32bit word_shift, u32bit bit_shift);

/*
* Simple O(N^2) Multiplication and Squaring
*/
void bigint_simple_mul(word z[],
                       const word x[], u32bit x_size,
                       const word y[], u32bit y_size);

void bigint_simple_sqr(word z[], const word x[], u32bit x_size);

/*
* Linear Multiply
*/
void bigint_linmul2(word x[], u32bit x_size, word y);
void bigint_linmul3(word z[], const word x[], u32bit x_size, word y);

/*
* Montgomery Reduction
*/
void bigint_monty_redc(word z[], u32bit z_size,
                       const word x[], u32bit x_size, word u);

/*
* Misc Utility Operations
*/
u32bit bigint_divcore(word q, word y1, word y2,
                      word x1, word x2, word x3);

/**
* Compare x and y
*/
s32bit bigint_cmp(const word x[], u32bit x_size,
                  const word y[], u32bit y_size);

/**
* Compute ((n1<<bits) + n0) / d
*/
word bigint_divop(word n1, word n0, word d);

/**
* Compute ((n1<<bits) + n0) % d
*/
word bigint_modop(word n1, word n0, word d);

/*
* Comba Multiplication / Squaring
*/
void bigint_comba_mul4(word z[8], const word x[4], const word y[4]);
void bigint_comba_mul6(word z[12], const word x[6], const word y[6]);
void bigint_comba_mul8(word z[16], const word x[8], const word y[8]);
void bigint_comba_mul16(word z[32], const word x[16], const word y[16]);

void bigint_comba_sqr4(word out[8], const word in[4]);
void bigint_comba_sqr6(word out[12], const word in[6]);
void bigint_comba_sqr8(word out[16], const word in[8]);
void bigint_comba_sqr8(word out[32], const word in[16]);
void bigint_comba_sqr16(word out[64], const word in[32]);

}

/*
* High Level Multiplication/Squaring Interfaces
*/
void bigint_mul(word z[], u32bit z_size, word workspace[],
                const word x[], u32bit x_size, u32bit x_sw,
                const word y[], u32bit y_size, u32bit y_sw);

void bigint_sqr(word z[], u32bit z_size, word workspace[],
                const word x[], u32bit x_size, u32bit x_sw);

}

#endif
