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
#include <botan/internal/int_utils.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/mem_utils.h>
#include <botan/internal/salsa20.h>
#include <botan/internal/time_utils.h>

namespace Botan {

namespace {

constexpr size_t MAX_SCRYPT_N = 4194304;
constexpr size_t MAX_SCRYPT_MEMORY_GB = sizeof(size_t) == 4 ? 2 : 8;
constexpr size_t MAX_SCRYPT_MEMORY_BYTES = MAX_SCRYPT_MEMORY_GB * 1024 * 1024 * 1024 + 65536;

std::optional<size_t> scrypt_memory_usage(size_t N, size_t r, size_t p) {
   // 128 * r * (N + p) rejecting on overflow
   const auto block_size = checked_mul(static_cast<size_t>(128), r);
   const auto blocks = checked_add(N, p);
   if(block_size && blocks) {
      return checked_mul(block_size.value(), blocks.value());
   } else {
      return {};
   }
}

}  // namespace

std::string Scrypt_Family::name() const {
   return "Scrypt";
}

std::unique_ptr<PasswordHash> Scrypt_Family::default_params() const {
   return std::make_unique<Scrypt>(32768, 8, 1);
}

std::unique_ptr<PasswordHash> Scrypt_Family::tune_params(size_t /*output_length*/,
                                                         uint64_t desired_msec,
                                                         std::optional<size_t> max_memory,
                                                         uint64_t tuning_msec) const {
   /*
   * Some rough relations between scrypt parameters and runtime.
   * Denote here by stime(N,r,p) the msec it takes to run scrypt.
   *
   * Empirically for smaller sizes:
   * stime(N,8*r,p) / stime(N,r,p) is ~ 6-7
   * stime(N,r,8*p) / stime(N,r,8*p) is ~ 7
   * stime(2*N,r,p) / stime(N,r,p) is ~ 2
   *
   * Compute stime(8192,1,1) as baseline and extrapolate
   */

   // If max_memory is nullopt or zero this becomes zero and is ignored
   const size_t max_memory_bytes = std::min(MAX_SCRYPT_MEMORY_BYTES, max_memory.value_or(0) * 1024 * 1024);

   // In below code we invoke scrypt_memory_usage with p == 0 as p contributes
   // (very slightly) to memory consumption, but N is the driving factor.
   // Including p leads to using an N half as large as what the user would expect.

   auto scrypt_parameters_acceptable = [&](size_t N, size_t r) -> bool {
      if(N > MAX_SCRYPT_N) {
         return false;
      }
      if(const auto consumed = scrypt_memory_usage(N, r, 0)) {
         if(max_memory_bytes > 0 && *consumed > max_memory_bytes) {
            return false;
         } else {
            return true;
         }
      } else {
         return false;
      }
   };

   // Starting parameters
   size_t N = 8 * 1024;
   size_t r = 1;
   size_t p = 1;

   auto pwdhash = this->from_params(N, r, p);

   const uint64_t measured_time = measure_cost(tuning_msec, [&]() {
      uint8_t output[32] = {0};
      pwdhash->derive_key(output, sizeof(output), "test", 4, nullptr, 0);
   });

   const uint64_t target_nsec = desired_msec * static_cast<uint64_t>(1000000);

   uint64_t est_nsec = measured_time;

   // First increase r by 8x if possible
   if(scrypt_parameters_acceptable(N, r * 8)) {
      if(target_nsec / est_nsec >= 5) {
         r *= 8;
         est_nsec *= 5;
      }
   }

   // Now double N as many times as we can
   while(scrypt_parameters_acceptable(N * 2, r)) {
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
   if(N < 1 || N > MAX_SCRYPT_N) {
      throw Invalid_Argument("Invalid or unsupported scrypt N");
   }

   if(const auto memory_usage = scrypt_memory_usage(N, r, p)) {
      if(memory_usage > MAX_SCRYPT_MEMORY_BYTES) {
         throw Invalid_Argument("Scrypt parameters exceed maximum allowed memory limit");
      }
   } else {
      throw Invalid_Argument("Scrypt parameters are too large for this platform");
   }
}

std::string Scrypt::to_string() const {
   return fmt("Scrypt({},{},{})", m_N, m_r, m_p);
}

size_t Scrypt::total_memory_usage() const {
   const size_t N = memory_param();
   const size_t p = parallelism();
   const size_t r = iterations();

   const auto consumption = scrypt_memory_usage(N, r, p);
   BOTAN_ASSERT_NOMSG(consumption.has_value());
   return consumption.value();
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

void scryptROMmix(
   size_t r, size_t N, uint8_t* B, secure_vector<uint8_t>& V, const std::optional<std::stop_token>& stop_token) {
   const size_t S = 128 * r;

   for(size_t i = 0; i != N; ++i) {
      if((i & 63) == 0 && stop_token.has_value() && stop_token->stop_requested()) {
         throw Botan::Operation_Canceled("scrypt");
      }
      copy_mem(&V[S * i], B, S);
      scryptBlockMix(r, B, &V[N * S]);
   }

   for(size_t i = 0; i != N; ++i) {
      if((i & 63) == 0 && stop_token.has_value() && stop_token->stop_requested()) {
         throw Botan::Operation_Canceled("scrypt");
      }
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
                        size_t salt_len,
                        const std::optional<std::stop_token>& stop_token) const {
   if(output_len == 0) {
      return;
   }

   const size_t N = memory_param();
   const size_t p = parallelism();
   const size_t r = iterations();

   const size_t S = 128 * r;
   secure_vector<uint8_t> B(p * S);
   // temp space
   secure_vector<uint8_t> V((N + 1) * S);

   auto hmac_sha256 = MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");

   try {
      hmac_sha256->set_key(as_span_of_bytes(password, password_len));
   } catch(Invalid_Key_Length&) {
      throw Invalid_Argument("Scrypt cannot accept passphrases of the provided length");
   }

   pbkdf2(*hmac_sha256, B.data(), B.size(), salt, salt_len, 1);

   // these can be parallel
   for(size_t i = 0; i != p; ++i) {
      scryptROMmix(r, N, &B[128 * r * i], V, stop_token);
   }

   pbkdf2(*hmac_sha256, output, output_len, B.data(), B.size(), 1);
}

}  // namespace Botan
