/*
* PBKDF1
* (C) 2026 Damiano Mazzella
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pbkdf1.h>


#include <botan/hash.h>
#include <botan/internal/charset.h>
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

   // Interpret input bytes as Latin-1, convert to UTF-8 then to UCS-2 (big-endian)
   const std::string utf8 = Botan::latin1_to_utf8(reinterpret_cast<const uint8_t*>(password.data()), password.size());
   const std::vector<uint8_t> ucs2 = Botan::utf8_to_ucs2(utf8);

   secure_vector<uint8_t> result(ucs2.begin(), ucs2.end());
   // Ensure null terminator (UCS-2) appended
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

// PBKDF1/PBKDF1_Family classes were removed; use pbkdf1() and PKCS5_PBKDF1
// adapter instead.

void pbkdf1(uint8_t out[],
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
         hash->clear();
         hash->update(D);
         hash->update(I);
         hash->final(A.data());

         for(size_t iter = 1; iter < iterations; ++iter) {
            hash->clear();
            hash->update(A.data(), A.size());
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

} // namespace Botan