/*
* Word Rotation Operations
* (C) 1999-2008,2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_WORD_ROTATE_H_
#define BOTAN_WORD_ROTATE_H_

#include <botan/compiler.h>
#include <botan/types.h>

namespace Botan {

/**
* Bit rotation left by a compile-time constant amount
* @param input the input word
* @return input rotated left by ROT bits
*/
template <size_t ROT, typename T>
BOTAN_FORCE_INLINE constexpr T rotl(T input)
   requires(ROT > 0 && ROT < 8 * sizeof(T))
{
   return static_cast<T>((input << ROT) | (input >> (8 * sizeof(T) - ROT)));
}

/**
* Bit rotation right by a compile-time constant amount
* @param input the input word
* @return input rotated right by ROT bits
*/
template <size_t ROT, typename T>
BOTAN_FORCE_INLINE constexpr T rotr(T input)
   requires(ROT > 0 && ROT < 8 * sizeof(T))
{
   return static_cast<T>((input >> ROT) | (input << (8 * sizeof(T) - ROT)));
}

/**
* SHA-2 Sigma style function
*/
template <size_t R1, size_t R2, size_t S, typename T>
BOTAN_FORCE_INLINE constexpr T sigma(T x) {
   return rotr<R1>(x) ^ rotr<R2>(x) ^ (x >> S);
}

/**
* SHA-2 Sigma style function
*/
template <size_t R1, size_t R2, size_t R3, typename T>
BOTAN_FORCE_INLINE constexpr T rho(T x) {
   return rotr<R1>(x) ^ rotr<R2>(x) ^ rotr<R3>(x);
}

/**
* Bit rotation left, variable rotation amount
* @param input the input word
* @param rot the number of bits to rotate, must be between 0 and sizeof(T)*8-1
* @return input rotated left by rot bits
*/
template <typename T>
BOTAN_FORCE_INLINE constexpr T rotl_var(T input, size_t rot) {
   return rot ? static_cast<T>((input << rot) | (input >> (sizeof(T) * 8 - rot))) : input;
}

/**
* Bit rotation right, variable rotation amount
* @param input the input word
* @param rot the number of bits to rotate, must be between 0 and sizeof(T)*8-1
* @return input rotated right by rot bits
*/
template <typename T>
BOTAN_FORCE_INLINE constexpr T rotr_var(T input, size_t rot) {
   return rot ? static_cast<T>((input >> rot) | (input << (sizeof(T) * 8 - rot))) : input;
}

}  // namespace Botan

#endif
