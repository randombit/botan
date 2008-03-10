/*************************************************
* MPI Algorithms Header File                     *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_MP_CORE_H__
#define BOTAN_MP_CORE_H__

#include <botan/mp_types.h>

namespace Botan {

/*************************************************
* The size of the word type, in bits             *
*************************************************/
const u32bit MP_WORD_BITS = BOTAN_MP_WORD_BITS;

extern "C" {

/*************************************************
* Addition/Subtraction Operations                *
*************************************************/
void bigint_add2(word[], u32bit, const word[], u32bit);
void bigint_add3(word[], const word[], u32bit, const word[], u32bit);

word bigint_add2_nc(word[], u32bit, const word[], u32bit);
word bigint_add3_nc(word[], const word[], u32bit, const word[], u32bit);

void bigint_sub2(word[], u32bit, const word[], u32bit);
void bigint_sub3(word[], const word[], u32bit, const word[], u32bit);

/*************************************************
* Shift Operations                               *
*************************************************/
void bigint_shl1(word[], u32bit, u32bit, u32bit);
void bigint_shl2(word[], const word[], u32bit, u32bit, u32bit);
void bigint_shr1(word[], u32bit, u32bit, u32bit);
void bigint_shr2(word[], const word[], u32bit, u32bit, u32bit);

/*************************************************
* Multiplication and Squaring Operations         *
*************************************************/
word bigint_mul_add_words(word[], const word[], u32bit, word);

void bigint_linmul2(word[], u32bit, word);
void bigint_linmul3(word[], const word[], u32bit, word);
void bigint_linmul_add(word[], u32bit, const word[], u32bit, word);

/*************************************************
* Montgomery Reduction                           *
*************************************************/
void bigint_monty_redc(word[], u32bit, const word[], u32bit, word);

/*************************************************
* Misc Utility Operations                        *
*************************************************/
u32bit bigint_divcore(word, word, word, word, word, word);
s32bit bigint_cmp(const word[], u32bit, const word[], u32bit);
word bigint_divop(word, word, word);
word bigint_modop(word, word, word);
void bigint_wordmul(word, word, word*, word*);

/*************************************************
* Comba Multiplication / Squaring                *
*************************************************/
void bigint_comba_mul4(word[8], const word[4], const word[4]);
void bigint_comba_mul6(word[12], const word[6], const word[6]);
void bigint_comba_mul8(word[16], const word[8], const word[8]);

void bigint_comba_sqr4(word[8], const word[4]);
void bigint_comba_sqr6(word[12], const word[6]);
void bigint_comba_sqr8(word[16], const word[8]);

}

/*************************************************
* High Level Multiplication/Squaring Interfaces  *
*************************************************/
void bigint_mul(word[], u32bit, word[],
                const word[], u32bit, u32bit,
                const word[], u32bit, u32bit);

void bigint_sqr(word[], u32bit, word[],
                const word[], u32bit, u32bit);

}

#endif
