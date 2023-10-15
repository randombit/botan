/*
* (C) 2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/sodium.h>

#include <botan/mem_ops.h>
#include <botan/system_rng.h>
#include <botan/internal/chacha.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/os_utils.h>
#include <cstdlib>

namespace Botan {

void Sodium::randombytes_buf(void* buf, size_t len) {
   system_rng().randomize(static_cast<uint8_t*>(buf), len);
}

uint32_t Sodium::randombytes_uniform(uint32_t upper_bound) {
   if(upper_bound <= 1) {
      return 0;
   }

   // Not completely uniform
   uint64_t x;
   randombytes_buf(&x, sizeof(x));
   return x % upper_bound;
}

void Sodium::randombytes_buf_deterministic(void* buf, size_t size, const uint8_t seed[randombytes_SEEDBYTES]) {
   const unsigned char nonce[12] = {'L', 'i', 'b', 's', 'o', 'd', 'i', 'u', 'm', 'D', 'R', 'G'};

   ChaCha chacha(20);
   chacha.set_key(seed, randombytes_SEEDBYTES);
   chacha.set_iv(nonce, sizeof(nonce));
   chacha.write_keystream(static_cast<uint8_t*>(buf), size);
}

int Sodium::crypto_verify_16(const uint8_t x[16], const uint8_t y[16]) {
   return static_cast<int>(CT::is_equal(x, y, 16).select(1, 0));
}

int Sodium::crypto_verify_32(const uint8_t x[32], const uint8_t y[32]) {
   return static_cast<int>(CT::is_equal(x, y, 32).select(1, 0));
}

int Sodium::crypto_verify_64(const uint8_t x[64], const uint8_t y[64]) {
   return static_cast<int>(CT::is_equal(x, y, 64).select(1, 0));
}

void Sodium::sodium_memzero(void* ptr, size_t len) {
   secure_scrub_memory(ptr, len);
}

int Sodium::sodium_memcmp(const void* x, const void* y, size_t len) {
   const auto same = CT::is_equal(static_cast<const uint8_t*>(x), static_cast<const uint8_t*>(y), len);
   // Return 0 if same or -1 if differing
   return static_cast<int>(same.select(1, 0)) - 1;
}

int Sodium::sodium_compare(const uint8_t x[], const uint8_t y[], size_t len) {
   const uint8_t LT = static_cast<uint8_t>(-1);
   const uint8_t EQ = 0;
   const uint8_t GT = 1;

   uint8_t result = EQ;  // until found otherwise

   for(size_t i = 0; i != len; ++i) {
      const auto is_eq = CT::Mask<uint8_t>::is_equal(x[i], y[i]);
      const auto is_lt = CT::Mask<uint8_t>::is_lt(x[i], y[i]);
      result = is_eq.select(result, is_lt.select(LT, GT));
   }

   return static_cast<int8_t>(result);
}

int Sodium::sodium_is_zero(const uint8_t b[], size_t len) {
   uint8_t sum = 0;
   for(size_t i = 0; i != len; ++i) {
      sum |= b[i];
   }
   return static_cast<int>(CT::Mask<uint8_t>::expand(sum).if_not_set_return(1));
}

void Sodium::sodium_increment(uint8_t b[], size_t len) {
   uint8_t carry = 1;
   for(size_t i = 0; i != len; ++i) {
      b[i] += carry;
      carry &= (b[i] == 0);
   }
}

void Sodium::sodium_add(uint8_t a[], const uint8_t b[], size_t len) {
   uint8_t carry = 0;
   for(size_t i = 0; i != len; ++i) {
      a[i] += b[i] + carry;
      carry = (a[i] < b[i]);
   }
}

void* Sodium::sodium_malloc(size_t size) {
   const uint64_t len = size;

   if(size + sizeof(len) < size) {
      return nullptr;
   }

   // NOLINTNEXTLINE(*-no-malloc)
   uint8_t* p = static_cast<uint8_t*>(std::calloc(size + sizeof(len), 1));
   store_le(len, p);
   return p + 8;
}

void Sodium::sodium_free(void* ptr) {
   if(ptr == nullptr) {
      return;
   }

   uint8_t* p = static_cast<uint8_t*>(ptr) - 8;
   const uint64_t len = load_le<uint64_t>(p, 0);
   secure_scrub_memory(ptr, static_cast<size_t>(len));
   // NOLINTNEXTLINE(*-no-malloc)
   std::free(p);
}

void* Sodium::sodium_allocarray(size_t count, size_t size) {
   const size_t bytes = count * size;
   if(bytes < count || bytes < size) {
      return nullptr;
   }
   return sodium_malloc(bytes);
}

int Sodium::sodium_mprotect_noaccess(void* ptr) {
   OS::page_prohibit_access(ptr);
   return 0;
}

int Sodium::sodium_mprotect_readwrite(void* ptr) {
   OS::page_allow_access(ptr);
   return 0;
}

}  // namespace Botan
