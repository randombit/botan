/*
* OpenPGP S2K
* (C) 1999-2007,2017 Jack Lloyd
* (C) 2018 Ribose Inc
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pgp_s2k.h>

#include <botan/exceptn.h>
#include <botan/mem_ops.h>
#include <botan/internal/fmt.h>
#include <botan/internal/mem_utils.h>
#include <botan/internal/time_utils.h>
#include <algorithm>

namespace Botan {

namespace {

void pgp_s2k(HashFunction& hash,
             uint8_t output_buf[],
             size_t output_len,
             const char* password,
             const size_t password_size,
             const uint8_t salt[],
             size_t salt_len,
             size_t iterations,
             const std::optional<std::stop_token>& stop_token) {
   if(iterations > 1 && salt_len == 0) {
      throw Invalid_Argument("OpenPGP S2K requires a salt in iterated mode");
   }

   secure_vector<uint8_t> input_buf(salt_len + password_size);
   if(salt_len > 0) {
      copy_mem(input_buf.data(), salt, salt_len);
   }
   if(password_size > 0) {
      copy_mem(std::span(input_buf).subspan(salt_len), as_span_of_bytes(password, password_size));
   }

   secure_vector<uint8_t> hash_buf(hash.output_length());

   size_t pass = 0;
   size_t generated = 0;

   while(generated != output_len) {
      const size_t output_this_pass = std::min(hash_buf.size(), output_len - generated);

      // Preload some number of zero bytes (empty first iteration)
      std::vector<uint8_t> zero_padding(pass);
      hash.update(zero_padding);

      // The input is always fully processed even if iterations is very small
      if(!input_buf.empty()) {
         size_t left = std::max(iterations, input_buf.size());
         size_t iter = 0;
         while(left > 0) {
            if((iter++ & 255) == 0 && stop_token.has_value() && stop_token->stop_requested()) {
               throw Botan::Operation_Canceled("pgp_s2k");
            }
            const size_t input_to_take = std::min(left, input_buf.size());
            hash.update(input_buf.data(), input_to_take);
            left -= input_to_take;
         }
      }

      hash.final(hash_buf.data());
      copy_mem(output_buf + generated, hash_buf.data(), output_this_pass);
      generated += output_this_pass;
      ++pass;
   }
}

}  // namespace

size_t OpenPGP_S2K::pbkdf(uint8_t output_buf[],
                          size_t output_len,
                          std::string_view password,
                          const uint8_t salt[],
                          size_t salt_len,
                          size_t iterations,
                          std::chrono::milliseconds msec) const {
   std::unique_ptr<PasswordHash> pwdhash;

   if(iterations == 0) {
      RFC4880_S2K_Family s2k_params(m_hash->new_object());
      iterations = s2k_params.tune(output_len, msec, 0, std::chrono::milliseconds(10))->iterations();
   }

   pgp_s2k(*m_hash, output_buf, output_len, password.data(), password.size(), salt, salt_len, iterations, std::nullopt);

   return iterations;
}

std::string RFC4880_S2K_Family::name() const {
   return fmt("OpenPGP-S2K({})", m_hash->name());
}

std::unique_ptr<PasswordHash> RFC4880_S2K_Family::tune(size_t output_len,
                                                       std::chrono::milliseconds msec,
                                                       size_t /*max_memory_usage_mb*/,
                                                       std::chrono::milliseconds tune_time) const {
   constexpr size_t buf_size = 1024;
   std::vector<uint8_t> buffer(buf_size);

   const uint64_t measured_nsec = measure_cost(tune_time, [&]() { m_hash->update(buffer); });

   const double hash_bytes_per_second = (buf_size * 1000000000.0) / measured_nsec;
   const uint64_t desired_nsec = msec.count() * 1000000;

   const size_t hash_size = m_hash->output_length();
   const size_t blocks_required = (output_len <= hash_size ? 1 : (output_len + hash_size - 1) / hash_size);

   const double bytes_to_be_hashed = (hash_bytes_per_second * (desired_nsec / 1000000000.0)) / blocks_required;
   const size_t iterations = RFC4880_round_iterations(static_cast<size_t>(bytes_to_be_hashed));

   return std::make_unique<RFC4880_S2K>(m_hash->new_object(), iterations);
}

std::unique_ptr<PasswordHash> RFC4880_S2K_Family::from_params(size_t iterations,
                                                              size_t /*unused*/,
                                                              size_t /*unused*/) const {
   return std::make_unique<RFC4880_S2K>(m_hash->new_object(), iterations);
}

std::unique_ptr<PasswordHash> RFC4880_S2K_Family::default_params() const {
   return std::make_unique<RFC4880_S2K>(m_hash->new_object(), 50331648);
}

std::unique_ptr<PasswordHash> RFC4880_S2K_Family::from_iterations(size_t iterations) const {
   return std::make_unique<RFC4880_S2K>(m_hash->new_object(), iterations);
}

RFC4880_S2K::RFC4880_S2K(std::unique_ptr<HashFunction> hash, size_t iterations) :
      m_hash(std::move(hash)), m_iterations(iterations) {}

std::string RFC4880_S2K::to_string() const {
   return fmt("OpenPGP-S2K({},{})", m_hash->name(), m_iterations);
}

void RFC4880_S2K::derive_key(uint8_t out[],
                             size_t out_len,
                             const char* password,
                             const size_t password_len,
                             const uint8_t salt[],
                             size_t salt_len,
                             const std::optional<std::stop_token>& stop_token) const {
   pgp_s2k(*m_hash, out, out_len, password, password_len, salt, salt_len, m_iterations, stop_token);
}

}  // namespace Botan
