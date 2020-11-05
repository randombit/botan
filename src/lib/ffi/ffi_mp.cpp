/*
* (C) 2015,2017 Jack Lloyd
* (C) 2017 Ribose Inc
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>
#include <botan/internal/ffi_util.h>
#include <botan/internal/ffi_rng.h>
#include <botan/internal/ffi_mp.h>
#include <botan/reducer.h>
#include <botan/numthry.h>
#include <botan/divide.h>

extern "C" {

using namespace Botan_FFI;

int botan_mp_init(botan_mp_t* mp_out)
   {
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(mp_out == nullptr)
         return BOTAN_FFI_ERROR_NULL_POINTER;

      *mp_out = new botan_mp_struct(new Botan::BigInt);
      return BOTAN_FFI_SUCCESS;
      });
   }

int botan_mp_clear(botan_mp_t mp)
   {
   return BOTAN_FFI_DO(Botan::BigInt, mp, bn, { bn.clear(); });
   }

int botan_mp_set_from_int(botan_mp_t mp, int initial_value)
   {
   return BOTAN_FFI_DO(Botan::BigInt, mp, bn, {
      if(initial_value >= 0)
         {
         bn = Botan::BigInt(static_cast<uint64_t>(initial_value));
         }
      else
         {
         bn = Botan::BigInt(static_cast<uint64_t>(-initial_value));
         bn.flip_sign();
         }
      });
   }

int botan_mp_set_from_str(botan_mp_t mp, const char* str)
   {
   return BOTAN_FFI_DO(Botan::BigInt, mp, bn, { bn = Botan::BigInt(str); });
   }

int botan_mp_set_from_radix_str(botan_mp_t mp, const char* str, size_t radix)
   {
   return BOTAN_FFI_DO(Botan::BigInt, mp, bn, {
      Botan::BigInt::Base base;
      if(radix == 10)
         base = Botan::BigInt::Decimal;
      else if(radix == 16)
         base = Botan::BigInt::Hexadecimal;
      else
         return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;

      const uint8_t* bytes = Botan::cast_char_ptr_to_uint8(str);
      const size_t len = strlen(str);

      bn = Botan::BigInt(bytes, len, base);
      });
   }

int botan_mp_set_from_mp(botan_mp_t dest, const botan_mp_t source)
   {
   return BOTAN_FFI_DO(Botan::BigInt, dest, bn, { bn = safe_get(source); });
   }

int botan_mp_is_negative(const botan_mp_t mp)
   {
   return BOTAN_FFI_DO(Botan::BigInt, mp, bn, { return bn.is_negative() ? 1 : 0; });
   }

int botan_mp_is_positive(const botan_mp_t mp)
   {
   return BOTAN_FFI_DO(Botan::BigInt, mp, bn, { return bn.is_positive() ? 1 : 0; });
   }

int botan_mp_flip_sign(botan_mp_t mp)
   {
   return BOTAN_FFI_DO(Botan::BigInt, mp, bn, { bn.flip_sign(); });
   }

int botan_mp_from_bin(botan_mp_t mp, const uint8_t bin[], size_t bin_len)
   {
   return BOTAN_FFI_DO(Botan::BigInt, mp, bn, { bn.binary_decode(bin, bin_len); });
   }

int botan_mp_to_hex(const botan_mp_t mp, char* out)
   {
   return BOTAN_FFI_DO(Botan::BigInt, mp, bn, {
      const std::string hex = bn.to_hex_string();
      std::memcpy(out, hex.c_str(), 1 + hex.size());
      });
   }

int botan_mp_to_str(const botan_mp_t mp, uint8_t digit_base, char* out, size_t* out_len)
   {
   return BOTAN_FFI_RETURNING(Botan::BigInt, mp, bn, {

      if(digit_base == 0 || digit_base == 10)
         return write_str_output(out, out_len, bn.to_dec_string());
      else if(digit_base == 16)
         return write_str_output(out, out_len, bn.to_hex_string());
      else
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      });
   }

int botan_mp_to_bin(const botan_mp_t mp, uint8_t vec[])
   {
   return BOTAN_FFI_DO(Botan::BigInt, mp, bn, { bn.binary_encode(vec); });
   }

int botan_mp_to_uint32(const botan_mp_t mp, uint32_t* val)
   {
   if(val == nullptr)
      {
      return BOTAN_FFI_ERROR_NULL_POINTER;
      }
   return BOTAN_FFI_DO(Botan::BigInt, mp, bn, { *val = bn.to_u32bit(); });
   }

int botan_mp_destroy(botan_mp_t mp)
   {
   return BOTAN_FFI_CHECKED_DELETE(mp);
   }

int botan_mp_add(botan_mp_t result, const botan_mp_t x, const botan_mp_t y)
   {
   return BOTAN_FFI_DO(Botan::BigInt, result, res, {
      if(result == x)
         res += safe_get(y);
      else
         res = safe_get(x) + safe_get(y);
      });
   }

int botan_mp_sub(botan_mp_t result, const botan_mp_t x, const botan_mp_t y)
   {
   return BOTAN_FFI_DO(Botan::BigInt, result, res, {
      if(result == x)
         res -= safe_get(y);
      else
         res = safe_get(x) - safe_get(y);
      });
   }

int botan_mp_add_u32(botan_mp_t result, const botan_mp_t x, uint32_t y)
   {
   return BOTAN_FFI_DO(Botan::BigInt, result, res, {
      if(result == x)
         res += static_cast<Botan::word>(y);
      else
         res = safe_get(x) + static_cast<Botan::word>(y);
      });
   }

int botan_mp_sub_u32(botan_mp_t result, const botan_mp_t x, uint32_t y)
   {
   return BOTAN_FFI_DO(Botan::BigInt, result, res, {
      if(result == x)
         res -= static_cast<Botan::word>(y);
      else
         res = safe_get(x) - static_cast<Botan::word>(y);
      });
   }

int botan_mp_mul(botan_mp_t result, const botan_mp_t x, const botan_mp_t y)
   {
   return BOTAN_FFI_DO(Botan::BigInt, result, res, {
      if(result == x)
         res *= safe_get(y);
      else
         res = safe_get(x) * safe_get(y);
      });
   }

int botan_mp_div(botan_mp_t quotient,
                 botan_mp_t remainder,
                 const botan_mp_t x, const botan_mp_t y)
   {
   return BOTAN_FFI_DO(Botan::BigInt, quotient, q, {
      Botan::BigInt r;
      Botan::vartime_divide(safe_get(x), safe_get(y), q, r);
      safe_get(remainder) = r;
      });
   }

int botan_mp_equal(const botan_mp_t x_w, const botan_mp_t y_w)
   {
   return BOTAN_FFI_RETURNING(Botan::BigInt, x_w, x, { return x == safe_get(y_w); });
   }

int botan_mp_is_zero(const botan_mp_t mp)
   {
   return BOTAN_FFI_RETURNING(Botan::BigInt, mp, bn, { return bn.is_zero(); });
   }

int botan_mp_is_odd(const botan_mp_t mp)
   {
   return BOTAN_FFI_RETURNING(Botan::BigInt, mp, bn, { return bn.is_odd(); });
   }

int botan_mp_is_even(const botan_mp_t mp)
   {
   return BOTAN_FFI_RETURNING(Botan::BigInt, mp, bn, { return bn.is_even(); });
   }

int botan_mp_cmp(int* result, const botan_mp_t x_w, const botan_mp_t y_w)
   {
   return BOTAN_FFI_DO(Botan::BigInt, x_w, x, { *result = x.cmp(safe_get(y_w)); });
   }

int botan_mp_swap(botan_mp_t x_w, botan_mp_t y_w)
   {
   return BOTAN_FFI_DO(Botan::BigInt, x_w, x, { x.swap(safe_get(y_w)); });
   }

// Return (base^exponent) % modulus
int botan_mp_powmod(botan_mp_t out, const botan_mp_t base, const botan_mp_t exponent, const botan_mp_t modulus)
   {
   return BOTAN_FFI_DO(Botan::BigInt, out, o,
                       { o = Botan::power_mod(safe_get(base), safe_get(exponent), safe_get(modulus)); });
   }

int botan_mp_lshift(botan_mp_t out, const botan_mp_t in, size_t shift)
   {
   return BOTAN_FFI_DO(Botan::BigInt, out, o, { o = safe_get(in) << shift; });
   }

int botan_mp_rshift(botan_mp_t out, const botan_mp_t in, size_t shift)
   {
   return BOTAN_FFI_DO(Botan::BigInt, out, o, { o = safe_get(in) >> shift; });
   }

int botan_mp_mod_inverse(botan_mp_t out, const botan_mp_t in, const botan_mp_t modulus)
   {
   return BOTAN_FFI_DO(Botan::BigInt, out, o, { o = Botan::inverse_mod(safe_get(in), safe_get(modulus)); });
   }

int botan_mp_mod_mul(botan_mp_t out, const botan_mp_t x, const botan_mp_t y, const botan_mp_t modulus)
   {
   return BOTAN_FFI_DO(Botan::BigInt, out, o, {
      Botan::Modular_Reducer reducer(safe_get(modulus));
      o = reducer.multiply(safe_get(x), safe_get(y));
      });
   }

int botan_mp_rand_bits(botan_mp_t rand_out, botan_rng_t rng, size_t bits)
   {
   return BOTAN_FFI_DO(Botan::RandomNumberGenerator, rng, r, {
      safe_get(rand_out).randomize(r, bits); });
   }

int botan_mp_rand_range(botan_mp_t rand_out,
                        botan_rng_t rng,
                        const botan_mp_t lower,
                        const botan_mp_t upper)
   {
   return BOTAN_FFI_DO(Botan::RandomNumberGenerator, rng, r, {
      safe_get(rand_out) = Botan::BigInt::random_integer(r, safe_get(lower), safe_get(upper)); });
   }

int botan_mp_gcd(botan_mp_t out, const botan_mp_t x, const botan_mp_t y)
   {
   return BOTAN_FFI_DO(Botan::BigInt, out, o, {
      o = Botan::gcd(safe_get(x), safe_get(y)); });
   }

int botan_mp_is_prime(const botan_mp_t mp, botan_rng_t rng, size_t test_prob)
   {
   return BOTAN_FFI_RETURNING(Botan::BigInt, mp, n,
                       { return (Botan::is_prime(n, safe_get(rng), test_prob)) ? 1 : 0; });
   }

int botan_mp_get_bit(const botan_mp_t mp, size_t bit)
   {
   return BOTAN_FFI_RETURNING(Botan::BigInt, mp, n, { return (n.get_bit(bit)); });
   }

int botan_mp_set_bit(botan_mp_t mp, size_t bit)
   {
   return BOTAN_FFI_DO(Botan::BigInt, mp, n, { n.set_bit(bit); });
   }

int botan_mp_clear_bit(botan_mp_t mp, size_t bit)
   {
   return BOTAN_FFI_DO(Botan::BigInt, mp, n, { n.clear_bit(bit); });
   }

int botan_mp_num_bits(const botan_mp_t mp, size_t* bits)
   {
   return BOTAN_FFI_DO(Botan::BigInt, mp, n, { *bits = n.bits(); });
   }

int botan_mp_num_bytes(const botan_mp_t mp, size_t* bytes)
   {
   return BOTAN_FFI_DO(Botan::BigInt, mp, n, { *bytes = n.bytes(); });
   }

}
