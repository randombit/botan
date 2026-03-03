/*
* PKCS#12 KDF
* (C) 2026 Damiano Mazzella
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pkcs12_kdf.h>


#include <botan/hash.h>
#include <botan/internal/fmt.h>
#include <botan/internal/time_utils.h>
#include <cstring>

namespace Botan {

namespace {

/*
* Convert a password to PKCS#12 format (UTF-16BE with null terminator)
*/
secure_vector<uint8_t> pkcs12_password_to_bytes(std::string_view password) {
   if(password.empty()) {
      return secure_vector<uint8_t>();
   }

   // Convert ASCII/UTF-8 password to UTF-16BE with null terminator
   secure_vector<uint8_t> result;
   result.reserve((password.size() + 1) * 2);

   for(char c : password) {
      result.push_back(0);                       // High byte
      result.push_back(static_cast<uint8_t>(c)); // Low byte
   }
   // Add null terminator
   result.push_back(0);
   result.push_back(0);

   return result;
}

/*
* Repeat data to fill a buffer of size n
*/
void fill_buffer(uint8_t* buf, size_t n, const uint8_t* data, size_t data_len) {
   if(data_len == 0) {
      std::memset(buf, 0, n);
      return;
   }

   for(size_t i = 0; i < n; ++i) {
      buf[i] = data[i % data_len];
   }
}

}  // namespace

PKCS12_KDF::PKCS12_KDF(size_t iterations, uint8_t id) : m_iterations(iterations), m_id(id) {}

std::string PKCS12_KDF::to_string() const {
   return fmt("PKCS12-KDF(SHA-1,{},ID={})", m_iterations, m_id);
}

void PKCS12_KDF::derive_key(uint8_t out[],
                            size_t out_len,
                            const char* password,
                            size_t password_len,
                            const uint8_t salt[],
                            size_t salt_len) const {
   pkcs12_kdf(out, out_len, std::string_view(password, password_len), salt, salt_len, m_iterations, m_id);
}

secure_vector<uint8_t> PKCS12_KDF::derive_key(size_t out_len,
                                              std::string_view password,
                                              std::span<const uint8_t> salt) const {
   secure_vector<uint8_t> result(out_len);
   derive_key(result.data(), out_len, password.data(), password.size(), salt.data(), salt.size());
   return result;
}

PKCS12_KDF_Family::PKCS12_KDF_Family(uint8_t id) : m_id(id) {}

std::string PKCS12_KDF_Family::name() const {
   return fmt("PKCS12-KDF(SHA-1,ID={})", m_id);
}

std::unique_ptr<PasswordHash> PKCS12_KDF_Family::tune_params(size_t /*output_len*/,
                                                             uint64_t desired_runtime_msec,
                                                             std::optional<size_t> /*max_memory*/,
                                                             uint64_t tune_msec) const {
   const size_t starting_iter = 10000;

   uint8_t output[20];
   uint8_t salt[8] = {0};

   const uint64_t duration_nsec = measure_cost(tune_msec, [&]() {
      pkcs12_kdf(output, sizeof(output), "test", salt, sizeof(salt), starting_iter, m_id);
   });

   const uint64_t desired_nsec = desired_runtime_msec * 1000000;

   if(duration_nsec > desired_nsec) {
      return from_iterations(starting_iter);
   }

   const size_t multiplier = static_cast<size_t>(desired_nsec / duration_nsec);
   const size_t iter = std::max<size_t>(starting_iter * multiplier, 1000);

   return from_iterations(iter);
}

std::unique_ptr<PasswordHash> PKCS12_KDF_Family::default_params() const {
   return from_iterations(2048);
}

std::unique_ptr<PasswordHash> PKCS12_KDF_Family::from_iterations(size_t iter) const {
   return std::make_unique<PKCS12_KDF>(iter, m_id);
}

std::unique_ptr<PasswordHash> PKCS12_KDF_Family::from_params(size_t iter, size_t /*unused*/, size_t /*unused*/) const {
   return from_iterations(iter);
}

void pkcs12_kdf(uint8_t out[],
                size_t out_len,
                std::string_view password,
                const uint8_t salt[],
                size_t salt_len,
                size_t iterations,
                uint8_t id,
                std::string_view hash_algo) {
   if(iterations == 0) {
      throw Invalid_Argument("PKCS#12 KDF requires at least 1 iteration");
   }

   auto hash = HashFunction::create_or_throw(std::string(hash_algo));
   const size_t hash_len = hash->output_length();

   // Block size depends on hash algorithm (RFC 7292 uses the hash's block size as v)
   const size_t v = hash->hash_block_size();
   if(v == 0) {
      throw Invalid_Argument(fmt("PKCS#12 KDF does not support hash '{}': undefined block size", hash_algo));
   }

   // Convert password to UTF-16BE
   secure_vector<uint8_t> pwd_bytes = pkcs12_password_to_bytes(password);
   const size_t pwd_len = pwd_bytes.size();

   // Calculate sizes (must be multiple of v)
   const size_t S_len = salt_len > 0 ? v * ((salt_len + v - 1) / v) : 0;
   const size_t P_len = pwd_len > 0 ? v * ((pwd_len + v - 1) / v) : 0;
   const size_t I_len = S_len + P_len;

   // Create D (diversifier): v bytes of id
   secure_vector<uint8_t> D(v, id);

   // Create I = S || P
   secure_vector<uint8_t> I(I_len);
   if(S_len > 0) {
      fill_buffer(I.data(), S_len, salt, salt_len);
   }
   if(P_len > 0) {
      fill_buffer(I.data() + S_len, P_len, pwd_bytes.data(), pwd_len);
   }

   secure_vector<uint8_t> A(hash_len);

   size_t out_offset = 0;
   while(out_offset < out_len) {
      // Compute A = H^iterations(D || I)
      hash->update(D);
      hash->update(I);
      hash->final(A.data());

      for(size_t iter = 1; iter < iterations; ++iter) {
         hash->update(A);
         hash->final(A.data());
      }

      // Copy to output
      const size_t to_copy = std::min(hash_len, out_len - out_offset);
      std::memcpy(out + out_offset, A.data(), to_copy);
      out_offset += to_copy;

      if(out_offset >= out_len) {
         break;
      }

      // Update I for next block
      // B = A repeated to fill v bytes
      secure_vector<uint8_t> B(v);
      fill_buffer(B.data(), v, A.data(), hash_len);

      // I_j = (I_j + B + 1) mod 2^(v*8)
      for(size_t j = 0; j < I_len; j += v) {
         uint16_t carry = 1;
         for(size_t k = v; k > 0; --k) {
            carry += static_cast<uint16_t>(I[j + k - 1]) + static_cast<uint16_t>(B[k - 1]);
            I[j + k - 1] = static_cast<uint8_t>(carry & 0xFF);
            carry >>= 8;
         }
      }
   }
}

}  // namespace Botan
