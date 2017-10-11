/*
* Word Rotation Operations
* (C) 1999-2008,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_WORD_ROTATE_H_
#define BOTAN_WORD_ROTATE_H_

#include <botan/types.h>

namespace Botan {

/**
* Bit rotation left by a compile-time constant amount
* @param input the input word
* @return input rotated left by ROT bits
*/
template<size_t ROT, typename T>
inline T rotl(T input)
   {
   static_assert(ROT > 0 && ROT < 8*sizeof(T), "Invalid rotation constant");
   return static_cast<T>((input << ROT) | (input >> (8*sizeof(T) - ROT)));
   }

/**
* Bit rotation right by a compile-time constant amount
* @param input the input word
* @return input rotated right by ROT bits
*/
template<size_t ROT, typename T>
inline T rotr(T input)
   {
   static_assert(ROT > 0 && ROT < 8*sizeof(T), "Invalid rotation constant");
   return static_cast<T>((input >> ROT) | (input << (8*sizeof(T) - ROT)));
   }

/**
* Bit rotation left, variable rotation amount
* @param input the input word
* @param rot the number of bits to rotate, must be between 0 and sizeof(T)*8-1
* @return input rotated left by rot bits
*/
template<typename T>
inline T rotl_var(T input, size_t rot)
   {
   /*
   * This is a strange way of expressing the rotation operation but it
   * so happens that both GCC and Clang will recognize it and turn it
   * into a rotation, which cannot be said for many other forms. See
   * https://gcc.gnu.org/bugzilla/show_bug.cgi?id=82498
   */
   return static_cast<T>((input << rot) | (input >> (-rot % (8*sizeof(T)))));
   }

/**
* Bit rotation right, variable rotation amount
* @param input the input word
* @param rot the number of bits to rotate, must be between 0 and sizeof(T)*8-1
* @return input rotated right by rot bits
*/
template<typename T>
inline T rotr_var(T input, size_t rot)
   {
   return static_cast<T>((input >> rot) | (input << (-rot % (8*sizeof(T)))));
   }

template<typename T>
BOTAN_DEPRECATED("Use rotl<N> or rotl_var")
inline T rotate_left(T input, size_t rot)
   {
   // rotl_var does not reduce
   return rotl_var(input, rot % (8 * sizeof(T)));
   }

template<typename T>
BOTAN_DEPRECATED("Use rotr<N> or rotr_var")
inline T rotate_right(T input, size_t rot)
   {
   // rotr_var does not reduce
   return rotr_var(input, rot % (8 * sizeof(T)));
   }

}

#endif
