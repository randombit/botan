/**
* (C) 2018 Jack Lloyd
* (C) 2018 Ribose Inc
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/scrypt.h>

#include <botan/exceptn.h>
#include <botan/pbkdf2.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/salsa20.h>
#include <botan/internal/timer.h>

namespace Botan {

namespace {

size_t scrypt_memory_usage(size_t N, size_t r, size_t p) {
   return 128 * r * (N + p);
}

}  // namespace

std::string Scrypt_Family::name() const {
   return "Scrypt";
}

std::unique_ptr<PasswordHash> Scrypt_Family::default_params() const {
   return std::make_unique<Scrypt>(32768, 8, 1);
}

std::unique_ptr<PasswordHash> Scrypt_Family::tune(size_t output_length,
                                                  std::chrono::milliseconds msec,
                                                  size_t max_memory_usage_mb,
                                                  std::chrono::milliseconds tune_time) const {
   BOTAN_UNUSED(output_length);

   /*
   * Some rough relations between scrypt parameters and runtime.
   * Denote here by stime(N,r,p) the msec it takes to run scrypt.
   *
   * Emperically for smaller sizes:
   * stime(N,8*r,p) / stime(N,r,p) is ~ 6-7
   * stime(N,r,8*p) / stime(N,r,8*p) is ~ 7
   * stime(2*N,r,p) / stime(N,r,p) is ~ 2
   *
   * Compute stime(8192,1,1) as baseline and extrapolate
   */

   // This is zero if max_memory_usage_mb == 0 (unbounded)
   const size_t max_memory_usage = max_memory_usage_mb * 1024 * 1024;

   // Starting parameters
   size_t N = 8 * 1024;
   size_t r = 1;
   size_t p = 1;

   Timer timer("Scrypt");

   auto pwdhash = this->from_params(N, r, p);

   timer.run_until_elapsed(tune_time, [&]() {
      uint8_t output[32] = {0};
      pwdhash->derive_key(output, sizeof(output), "test", 4, nullptr, 0);
   });

   // No timer events seems strange, perhaps something is wrong - give
   // up on this and just return default params
   if(timer.events() == 0) {
      return default_params();
   }

   // nsec per eval of scrypt with initial params
   const uint64_t measured_time = timer.value() / timer.events();

   const uint64_t target_nsec = msec.count() * static_cast<uint64_t>(1000000);

   uint64_t est_nsec = measured_time;

   // In below code we invoke scrypt_memory_usage with p == 0 as p contributes
   // (very slightly) to memory consumption, but N is the driving factor.
   // Including p leads to using an N half as large as what the user would expect.

   // First increase r by 8x if possible
   if(max_memory_usage == 0 || scrypt_memory_usage(N, r * 8, 0) <= max_memory_usage) {
      if(target_nsec / est_nsec >= 5) {
         r *= 8;
         est_nsec *= 5;
      }
   }

   // Now double N as many times as we can
   while(max_memory_usage == 0 || scrypt_memory_usage(N * 2, r, 0) <= max_memory_usage) {
      if(target_nsec / est_nsec >= 2) {
         N *= 2;
         est_nsec *= 2;
      } else {
         break;
      }
   }

   // If we have extra runtime budget, increment p
   if(target_nsec / est_nsec >= 2) {
      p *= std::min<size_t>(1024, static_cast<size_t>(target_nsec / est_nsec));
   }

   return std::make_unique<Scrypt>(N, r, p);
}

std::unique_ptr<PasswordHash> Scrypt_Family::from_params(size_t N, size_t r, size_t p) const {
   return std::make_unique<Scrypt>(N, r, p);
}

std::unique_ptr<PasswordHash> Scrypt_Family::from_iterations(size_t iter) const {
   const size_t r = 8;
   const size_t p = 1;

   size_t N = 8192;

   if(iter > 50000) {
      N = 16384;
   }
   if(iter > 100000) {
      N = 32768;
   }
   if(iter > 150000) {
      N = 65536;
   }

   return std::make_unique<Scrypt>(N, r, p);
}

Scrypt::Scrypt(size_t N, size_t r, size_t p) : m_N(N), m_r(r), m_p(p) {
   if(!is_power_of_2(N)) {
      throw Invalid_Argument("Scrypt N parameter must be a power of 2");
   }

   if(p == 0 || p > 1024) {
      throw Invalid_Argument("Invalid or unsupported scrypt p");
   }
   if(r == 0 || r > 256) {
      throw Invalid_Argument("Invalid or unsupported scrypt r");
   }
   if(N < 1 || N > 4194304) {
      throw Invalid_Argument("Invalid or unsupported scrypt N");
   }
}

std::string Scrypt::to_string() const {
   return fmt("Scrypt({},{},{})", m_N, m_r, m_p);
}

size_t Scrypt::total_memory_usage() const {
   const size_t N = memory_param();
   const size_t p = parallelism();
   const size_t r = iterations();

   return scrypt_memory_usage(N, r, p);
}

namespace {

void scryptBlockMix(size_t r, uint8_t* B, uint8_t* Y) {
   uint32_t B32[16];
   secure_vector<uint8_t> X(64);
   copy_mem(X.data(), &B[(2 * r - 1) * 64], 64);

   for(size_t i = 0; i != 2 * r; i++) {
      xor_buf(X.data(), &B[64 * i], 64);
      load_le<uint32_t>(B32, X.data(), 16);
      Salsa20::salsa_core(X.data(), B32, 8);
      copy_mem(&Y[64 * i], X.data(), 64);
   }

   for(size_t i = 0; i < r; ++i) {
      copy_mem(&B[i * 64], &Y[(i * 2) * 64], 64);
   }

   for(size_t i = 0; i < r; ++i) {
      copy_mem(&B[(i + r) * 64], &Y[(i * 2 + 1) * 64], 64);
   }
}

void scryptROMmix(size_t r, size_t N, uint8_t* B, secure_vector<uint8_t>& V) {
   const size_t S = 128 * r;

   for(size_t i = 0; i != N; ++i) {
      copy_mem(&V[S * i], B, S);
      scryptBlockMix(r, B, &V[N * S]);
   }

   for(size_t i = 0; i != N; ++i) {
      // compiler doesn't know here that N is power of 2
      const size_t j = load_le<uint32_t>(&B[(2 * r - 1) * 64], 0) & (N - 1);
      xor_buf(B, &V[j * S], S);
      scryptBlockMix(r, B, &V[N * S]);
   }
}

}  // namespace

void Scrypt::derive_key(uint8_t output[],
                        size_t output_len,
                        const char* password,
                        size_t password_len,
                        const uint8_t salt[],
                        size_t salt_len) const {
   const size_t N = memory_param();
   const size_t p = parallelism();
   const size_t r = iterations();

   const size_t S = 128 * r;
   secure_vector<uint8_t> B(p * S);
   // temp space
   secure_vector<uint8_t> V((N + 1) * S);

   auto hmac_sha256 = MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");

   try {
      hmac_sha256->set_key(cast_char_ptr_to_uint8(password), password_len);
   } catch(Invalid_Key_Length&) {
      throw Invalid_Argument("Scrypt cannot accept passphrases of the provided length");
   }

   pbkdf2(*hmac_sha256, B.data(), B.size(), salt, salt_len, 1);

   // these can be parallel
   for(size_t i = 0; i != p; ++i) {
      scryptROMmix(r, N, &B[128 * r * i], V);
   }

   pbkdf2(*hmac_sha256, output, output_len, B.data(), B.size(), 1);
}

}  // namespace Botan
