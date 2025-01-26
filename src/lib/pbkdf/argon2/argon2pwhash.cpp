/**
* (C) 2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/argon2.h>

#include <botan/assert.h>
#include <botan/exceptn.h>
#include <botan/internal/fmt.h>
#include <botan/internal/time_utils.h>
#include <algorithm>
#include <limits>

namespace Botan {

Argon2::Argon2(uint8_t family, size_t M, size_t t, size_t p) : m_family(family), m_M(M), m_t(t), m_p(p) {
   BOTAN_ARG_CHECK(m_p >= 1 && m_p <= 128, "Invalid Argon2 threads parameter");
   BOTAN_ARG_CHECK(m_M >= 8 * m_p && m_M <= 8192 * 1024, "Invalid Argon2 M parameter");
   BOTAN_ARG_CHECK(m_t >= 1 && m_t <= std::numeric_limits<uint32_t>::max(), "Invalid Argon2 t parameter");
}

void Argon2::derive_key(uint8_t output[],
                        size_t output_len,
                        const char* password,
                        size_t password_len,
                        const uint8_t salt[],
                        size_t salt_len) const {
   argon2(output, output_len, password, password_len, salt, salt_len, nullptr, 0, nullptr, 0);
}

void Argon2::derive_key(uint8_t output[],
                        size_t output_len,
                        const char* password,
                        size_t password_len,
                        const uint8_t salt[],
                        size_t salt_len,
                        const uint8_t ad[],
                        size_t ad_len,
                        const uint8_t key[],
                        size_t key_len) const {
   argon2(output, output_len, password, password_len, salt, salt_len, key, key_len, ad, ad_len);
}

namespace {

std::string argon2_family_name(uint8_t f) {
   switch(f) {
      case 0:
         return "Argon2d";
      case 1:
         return "Argon2i";
      case 2:
         return "Argon2id";
      default:
         throw Invalid_Argument("Unknown Argon2 parameter");
   }
}

}  // namespace

std::string Argon2::to_string() const {
   return fmt("{}({},{},{})", argon2_family_name(m_family), m_M, m_t, m_p);
}

Argon2_Family::Argon2_Family(uint8_t family) : m_family(family) {
   if(m_family != 0 && m_family != 1 && m_family != 2) {
      throw Invalid_Argument("Unknown Argon2 family identifier");
   }
}

std::string Argon2_Family::name() const {
   return argon2_family_name(m_family);
}

std::unique_ptr<PasswordHash> Argon2_Family::tune(size_t /*output_length*/,
                                                  std::chrono::milliseconds msec,
                                                  size_t max_memory,
                                                  std::chrono::milliseconds tune_time) const {
   const size_t max_kib = (max_memory == 0) ? 256 * 1024 : max_memory * 1024;

   // Tune with a large memory otherwise we measure cache vs RAM speeds and underestimate
   // costs for larger params. Default is 36 MiB, or use 128 for long times.
   const size_t tune_M = (msec >= std::chrono::milliseconds(200) ? 128 : 36) * 1024;
   const size_t p = 1;
   size_t t = 1;

   size_t M = 4 * 1024;

   auto pwhash = this->from_params(tune_M, t, p);

   auto tune_fn = [&]() {
      uint8_t output[64] = {0};
      pwhash->derive_key(output, sizeof(output), "test", 4, nullptr, 0);
   };

   const uint64_t measured_time = measure_cost(tune_time, tune_fn) / (tune_M / M);

   const uint64_t target_nsec = msec.count() * static_cast<uint64_t>(1000000);

   /*
   * Argon2 scaling rules:
   * k*M, k*t, k*p all increase cost by about k
   *
   * First preference is to increase M up to max allowed value.
   * Any remaining time budget is spent on increasing t.
   */

   uint64_t est_nsec = measured_time;

   if(est_nsec < target_nsec && M < max_kib) {
      const uint64_t desired_cost_increase = (target_nsec + est_nsec - 1) / est_nsec;
      const uint64_t mem_headroom = max_kib / M;

      const uint64_t M_mult = std::min(desired_cost_increase, mem_headroom);
      M *= static_cast<size_t>(M_mult);
      est_nsec *= M_mult;
   }

   if(est_nsec < target_nsec / 2) {
      const uint64_t desired_cost_increase = (target_nsec + est_nsec - 1) / est_nsec;
      t *= static_cast<size_t>(desired_cost_increase);
   }

   return this->from_params(M, t, p);
}

std::unique_ptr<PasswordHash> Argon2_Family::default_params() const {
   return this->from_params(128 * 1024, 1, 1);
}

std::unique_ptr<PasswordHash> Argon2_Family::from_iterations(size_t iter) const {
   /*
   These choices are arbitrary, but should not change in future
   releases since they will break applications expecting deterministic
   mapping from iteration count to params
   */
   const size_t M = iter;
   const size_t t = 1;
   const size_t p = 1;
   return this->from_params(M, t, p);
}

std::unique_ptr<PasswordHash> Argon2_Family::from_params(size_t M, size_t t, size_t p) const {
   return std::make_unique<Argon2>(m_family, M, t, p);
}

}  // namespace Botan
