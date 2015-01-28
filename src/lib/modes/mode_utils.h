/*
* Helper include for mode implementations
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MODE_UTILS_H__
#define BOTAN_MODE_UTILS_H__

#include <botan/cipher_mode.h>
#include <botan/algo_registry.h>
#include <botan/block_cipher.h>
#include <botan/libstate.h>
#include <botan/loadstor.h>
#include <botan/internal/xor_buf.h>
#include <botan/internal/rounding.h>
#include <botan/internal/bit_ops.h>
#include <algorithm>

namespace Botan {

template<typename T>
T* make_block_cipher_mode(const Transform::Spec& spec)
   {
   Algorithm_Factory& af = global_state().algorithm_factory();

   if(const BlockCipher* bc = af.prototype_block_cipher(spec.arg(0)))
      return new T(bc->clone());
   return nullptr;
   }

template<typename T, size_t LEN1>
T* make_block_cipher_mode_len(const Transform::Spec& spec)
   {
   Algorithm_Factory& af = global_state().algorithm_factory();

   if(const BlockCipher* bc = af.prototype_block_cipher(spec.arg(0)))
      {
      const size_t len1 = spec.arg_as_integer(1, LEN1);
      return new T(bc->clone(), len1);
      }

   return nullptr;
   }

template<typename T, size_t LEN1, size_t LEN2>
T* make_block_cipher_mode_len2(const Transform::Spec& spec)
   {
   Algorithm_Factory& af = global_state().algorithm_factory();

   if(const BlockCipher* bc = af.prototype_block_cipher(spec.arg(0)))
      {
      const size_t len1 = spec.arg_as_integer(1, LEN1);
      const size_t len2 = spec.arg_as_integer(2, LEN2);
      return new T(bc->clone(), len1, len2);
      }

   return nullptr;
   }

#define BOTAN_REGISTER_BLOCK_CIPHER_MODE(E, D) \
   namespace { Algo_Registry<Transform>::Add g_ ## E ## _reg(#E, make_block_cipher_mode<E>); \
               Algo_Registry<Transform>::Add g_ ## D ## _reg(#D, make_block_cipher_mode<D>); }

#define BOTAN_REGISTER_BLOCK_CIPHER_MODE_LEN(E, D, LEN) \
   namespace { Algo_Registry<Transform>::Add g_ ## E ## _reg(#E, make_block_cipher_mode_len<E, LEN>); \
               Algo_Registry<Transform>::Add g_ ## D ## _reg(#D, make_block_cipher_mode_len<D, LEN>); }

#define BOTAN_REGISTER_BLOCK_CIPHER_MODE_LEN2(E, D, LEN1, LEN2)               \
   namespace { Algo_Registry<Transform>::Add g_ ## E ## _reg(#E, make_block_cipher_mode_len2<E, LEN1, LEN2>); \
               Algo_Registry<Transform>::Add g_ ## D ## _reg(#D, make_block_cipher_mode_len2<D, LEN1, LEN2>); }

}

#endif
