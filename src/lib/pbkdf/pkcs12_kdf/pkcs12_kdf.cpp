/*
* PKCS12 KDF
* (C) 2026 Damiano Mazzella
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pkcs12_kdf.h>

#include <botan/assert.h>
#include <botan/exceptn.h>
#include <botan/hash.h>
#include <botan/mem_ops.h>
#include <botan/internal/charset.h>
#include <botan/internal/fmt.h>
#include <botan/internal/time_utils.h>
#include <algorithm>
#include <array>
#include <limits>

namespace Botan {

namespace {

/*
* Repeat data into buf until buf is filled
*/
void copy_repeat(std::span<uint8_t> buf, std::span<const uint8_t> data) {
   if(data.empty()) {
      clear_mem(buf);
      return;
   }

   size_t pos = 0;
   while(pos < buf.size()) {
      const size_t to_copy = std::min(data.size(), buf.size() - pos);
      copy_mem(buf.subspan(pos, to_copy), data.first(to_copy));
      pos += to_copy;
   }
}

/*
* Big-endian addition: block = (block + addend + 1) mod 2^(len*8)
*/
void bigendian_add_one(std::span<uint8_t> block, std::span<const uint8_t> addend) {
   BOTAN_DEBUG_ASSERT(block.size() == addend.size());

   uint16_t carry = 1;
   for(size_t k = block.size(); k > 0; --k) {
      carry += static_cast<uint16_t>(block[k - 1]) + static_cast<uint16_t>(addend[k - 1]);
      block[k - 1] = static_cast<uint8_t>(carry & 0xFF);
      carry >>= 8;
   }
}

secure_vector<uint8_t> pkcs12_encode_password(std::string_view password) {
   if(password.empty()) {
      return secure_vector<uint8_t>({0, 0});
   }

   std::vector<uint8_t> ucs2 = utf8_to_ucs2(password);
   secure_vector<uint8_t> result(ucs2.begin(), ucs2.end());
   secure_scrub_memory(ucs2.data(), ucs2.size());
   result.push_back(0);
   result.push_back(0);
   return result;
}

void pkcs12_kdf_with_hash(std::span<uint8_t> out,
                          std::span<const uint8_t> pwd_bytes,
                          std::span<const uint8_t> salt,
                          size_t iterations,
                          uint8_t id,
                          HashFunction& hash) {
   if(iterations == 0) {
      throw Invalid_Argument("PKCS12-KDF: Invalid iteration count");
   }
   if(id < 1 || id > 3) {
      throw Invalid_Argument("PKCS12-KDF: Invalid id (must be 1=key, 2=IV, or 3=MAC)");
   }

   // Block size depends on hash algorithm (RFC 7292 uses the hash's block size as v)
   const size_t v = hash.hash_block_size();
   if(v == 0) {
      throw Invalid_Argument(fmt("PKCS12-KDF does not support hash '{}': undefined block size", hash.name()));
   }

   if(out.empty()) {
      return;
   }

   const size_t hash_len = hash.output_length();

   const size_t pwd_len = pwd_bytes.size();
   const size_t salt_len = salt.size();

   // Calculate sizes (must be multiple of v)
   const size_t S_len = salt_len > 0 ? v * ((salt_len + v - 1) / v) : 0;
   const size_t P_len = pwd_len > 0 ? v * ((pwd_len + v - 1) / v) : 0;
   const size_t I_len = S_len + P_len;

   // Create D (diversifier): v bytes of id
   secure_vector<uint8_t> D(v, id);

   // Create I = S || P
   secure_vector<uint8_t> I(I_len);
   if(S_len > 0) {
      copy_repeat(std::span{I}.first(S_len), salt);
   }
   if(P_len > 0) {
      copy_repeat(std::span{I}.last(P_len), pwd_bytes);
   }

   secure_vector<uint8_t> A(hash_len);
   secure_vector<uint8_t> B(v);

   size_t out_offset = 0;
   while(out_offset < out.size()) {
      // Compute A = H^iterations(D || I)
      hash.update(D);
      hash.update(I);
      hash.final(A);

      for(size_t iter = 1; iter < iterations; ++iter) {
         hash.update(A);
         hash.final(A);
      }

      // Copy to output
      const size_t to_copy = std::min(hash_len, out.size() - out_offset);
      copy_mem(out.subspan(out_offset, to_copy), std::span{A}.first(to_copy));
      out_offset += to_copy;

      // Update I for next block: B = A repeated to fill v bytes,
      // then I_j = (I_j + B + 1) mod 2^(v*8)
      copy_repeat(B, A);

      for(size_t j = 0; j < I_len; j += v) {
         bigendian_add_one(std::span{I}.subspan(j, v), B);
      }
   }
}

}  // namespace

PKCS12_KDF::PKCS12_KDF(std::unique_ptr<HashFunction> hash, uint8_t id, size_t iterations) :
      m_hash(std::move(hash)), m_id(id), m_iterations(iterations) {
   BOTAN_ARG_CHECK(m_hash != nullptr, "PKCS12-KDF: hash must not be null");
   BOTAN_ARG_CHECK(m_iterations > 0, "PKCS12-KDF: iterations must be greater than zero");
   BOTAN_ARG_CHECK(m_id >= 1 && m_id <= 3, "PKCS12-KDF: id must be 1 (key), 2 (IV), or 3 (MAC)");
}

std::string PKCS12_KDF::to_string() const {
   return fmt("PKCS12-KDF({},{},{})", m_hash->name(), static_cast<unsigned>(m_id), m_iterations);
}

void PKCS12_KDF::derive_key(uint8_t out[],
                            size_t out_len,
                            const char* password,
                            size_t password_len,
                            const uint8_t salt[],
                            size_t salt_len) const {
   const std::string_view pwd =
      (password != nullptr && password_len > 0) ? std::string_view(password, password_len) : std::string_view{};
   pkcs12_kdf_with_hash({out, out_len}, pkcs12_encode_password(pwd), {salt, salt_len}, m_iterations, m_id, *m_hash);
}

PKCS12_KDF_Family::PKCS12_KDF_Family(std::unique_ptr<HashFunction> hash, size_t id) :
      m_hash(std::move(hash)), m_id(static_cast<uint8_t>(id)) {
   BOTAN_ARG_CHECK(m_hash != nullptr, "PKCS12-KDF: hash must not be null");
   BOTAN_ARG_CHECK(id >= 1 && id <= 3, "PKCS12-KDF: id must be 1 (key), 2 (IV), or 3 (MAC)");
}

std::string PKCS12_KDF_Family::name() const {
   return fmt("PKCS12-KDF({},{})", m_hash->name(), static_cast<unsigned>(m_id));
}

std::unique_ptr<PasswordHash> PKCS12_KDF_Family::tune_params(size_t output_length,
                                                             uint64_t desired_msec,
                                                             std::optional<size_t> /*max_memory*/,
                                                             uint64_t tuning_msec) const {
   // Benchmark the real KDF at a fixed iteration count and target output length,
   // so the measurement captures hash(D || I), the full I-update carry loop, the
   // inner A-rehash loop, and the per-output-block cost.
   const size_t tuning_iterations = 10000;
   const size_t tuning_out_len = std::max<size_t>(output_length, 1);
   const std::array<uint8_t, 16> tuning_salt{};
   const std::array<uint8_t, 16> tuning_pwd{};
   const auto pwd_bytes =
      pkcs12_encode_password(std::string_view(reinterpret_cast<const char*>(tuning_pwd.data()), tuning_pwd.size()));
   std::vector<uint8_t> tuning_out(tuning_out_len);

   auto tuning_hash = m_hash->new_object();
   const uint64_t measured_nsec = measure_cost(tuning_msec, [&]() {
      pkcs12_kdf_with_hash(tuning_out, pwd_bytes, tuning_salt, tuning_iterations, m_id, *tuning_hash);
   });

   // Scale: one benchmark sample = tuning_iterations iterations; target matches desired_msec.
   const double measured = std::max<double>(1.0, static_cast<double>(measured_nsec));
   const double desired = static_cast<double>(desired_msec) * 1'000'000.0;
   const double est = (desired * static_cast<double>(tuning_iterations)) / measured;
   const double est_clamped = std::clamp(est, 1.0, static_cast<double>(std::numeric_limits<size_t>::max()));
   const size_t iterations = static_cast<size_t>(est_clamped);

   return std::make_unique<PKCS12_KDF>(m_hash->new_object(), m_id, iterations);
}

std::unique_ptr<PasswordHash> PKCS12_KDF_Family::default_params() const {
   return std::make_unique<PKCS12_KDF>(m_hash->new_object(), m_id, 2048);
}

std::unique_ptr<PasswordHash> PKCS12_KDF_Family::from_iterations(size_t iterations) const {
   return std::make_unique<PKCS12_KDF>(m_hash->new_object(), m_id, iterations);
}

std::unique_ptr<PasswordHash> PKCS12_KDF_Family::from_params(size_t i1, size_t /*i2*/, size_t /*i3*/) const {
   return std::make_unique<PKCS12_KDF>(m_hash->new_object(), m_id, i1);
}

}  // namespace Botan
