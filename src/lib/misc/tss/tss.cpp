/*
* RTSS (threshold secret sharing)
* (C) 2009,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tss.h>

#include <botan/hash.h>
#include <botan/hex.h>
#include <botan/rng.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/loadstor.h>

namespace Botan {

namespace {

const size_t RTSS_HEADER_SIZE = 20;

/**
Table for GF(2^8) arithmetic (exponentials)
*/
alignas(64) const uint8_t RTSS_EXP[256] = {
   0x01, 0x03, 0x05, 0x0F, 0x11, 0x33, 0x55, 0xFF, 0x1A, 0x2E, 0x72, 0x96, 0xA1, 0xF8, 0x13, 0x35, 0x5F, 0xE1, 0x38,
   0x48, 0xD8, 0x73, 0x95, 0xA4, 0xF7, 0x02, 0x06, 0x0A, 0x1E, 0x22, 0x66, 0xAA, 0xE5, 0x34, 0x5C, 0xE4, 0x37, 0x59,
   0xEB, 0x26, 0x6A, 0xBE, 0xD9, 0x70, 0x90, 0xAB, 0xE6, 0x31, 0x53, 0xF5, 0x04, 0x0C, 0x14, 0x3C, 0x44, 0xCC, 0x4F,
   0xD1, 0x68, 0xB8, 0xD3, 0x6E, 0xB2, 0xCD, 0x4C, 0xD4, 0x67, 0xA9, 0xE0, 0x3B, 0x4D, 0xD7, 0x62, 0xA6, 0xF1, 0x08,
   0x18, 0x28, 0x78, 0x88, 0x83, 0x9E, 0xB9, 0xD0, 0x6B, 0xBD, 0xDC, 0x7F, 0x81, 0x98, 0xB3, 0xCE, 0x49, 0xDB, 0x76,
   0x9A, 0xB5, 0xC4, 0x57, 0xF9, 0x10, 0x30, 0x50, 0xF0, 0x0B, 0x1D, 0x27, 0x69, 0xBB, 0xD6, 0x61, 0xA3, 0xFE, 0x19,
   0x2B, 0x7D, 0x87, 0x92, 0xAD, 0xEC, 0x2F, 0x71, 0x93, 0xAE, 0xE9, 0x20, 0x60, 0xA0, 0xFB, 0x16, 0x3A, 0x4E, 0xD2,
   0x6D, 0xB7, 0xC2, 0x5D, 0xE7, 0x32, 0x56, 0xFA, 0x15, 0x3F, 0x41, 0xC3, 0x5E, 0xE2, 0x3D, 0x47, 0xC9, 0x40, 0xC0,
   0x5B, 0xED, 0x2C, 0x74, 0x9C, 0xBF, 0xDA, 0x75, 0x9F, 0xBA, 0xD5, 0x64, 0xAC, 0xEF, 0x2A, 0x7E, 0x82, 0x9D, 0xBC,
   0xDF, 0x7A, 0x8E, 0x89, 0x80, 0x9B, 0xB6, 0xC1, 0x58, 0xE8, 0x23, 0x65, 0xAF, 0xEA, 0x25, 0x6F, 0xB1, 0xC8, 0x43,
   0xC5, 0x54, 0xFC, 0x1F, 0x21, 0x63, 0xA5, 0xF4, 0x07, 0x09, 0x1B, 0x2D, 0x77, 0x99, 0xB0, 0xCB, 0x46, 0xCA, 0x45,
   0xCF, 0x4A, 0xDE, 0x79, 0x8B, 0x86, 0x91, 0xA8, 0xE3, 0x3E, 0x42, 0xC6, 0x51, 0xF3, 0x0E, 0x12, 0x36, 0x5A, 0xEE,
   0x29, 0x7B, 0x8D, 0x8C, 0x8F, 0x8A, 0x85, 0x94, 0xA7, 0xF2, 0x0D, 0x17, 0x39, 0x4B, 0xDD, 0x7C, 0x84, 0x97, 0xA2,
   0xFD, 0x1C, 0x24, 0x6C, 0xB4, 0xC7, 0x52, 0xF6, 0x01};

/**
Table for GF(2^8) arithmetic (logarithms)
*/
alignas(64) const uint8_t RTSS_LOG[] = {
   0x90, 0x00, 0x19, 0x01, 0x32, 0x02, 0x1A, 0xC6, 0x4B, 0xC7, 0x1B, 0x68, 0x33, 0xEE, 0xDF, 0x03, 0x64, 0x04, 0xE0,
   0x0E, 0x34, 0x8D, 0x81, 0xEF, 0x4C, 0x71, 0x08, 0xC8, 0xF8, 0x69, 0x1C, 0xC1, 0x7D, 0xC2, 0x1D, 0xB5, 0xF9, 0xB9,
   0x27, 0x6A, 0x4D, 0xE4, 0xA6, 0x72, 0x9A, 0xC9, 0x09, 0x78, 0x65, 0x2F, 0x8A, 0x05, 0x21, 0x0F, 0xE1, 0x24, 0x12,
   0xF0, 0x82, 0x45, 0x35, 0x93, 0xDA, 0x8E, 0x96, 0x8F, 0xDB, 0xBD, 0x36, 0xD0, 0xCE, 0x94, 0x13, 0x5C, 0xD2, 0xF1,
   0x40, 0x46, 0x83, 0x38, 0x66, 0xDD, 0xFD, 0x30, 0xBF, 0x06, 0x8B, 0x62, 0xB3, 0x25, 0xE2, 0x98, 0x22, 0x88, 0x91,
   0x10, 0x7E, 0x6E, 0x48, 0xC3, 0xA3, 0xB6, 0x1E, 0x42, 0x3A, 0x6B, 0x28, 0x54, 0xFA, 0x85, 0x3D, 0xBA, 0x2B, 0x79,
   0x0A, 0x15, 0x9B, 0x9F, 0x5E, 0xCA, 0x4E, 0xD4, 0xAC, 0xE5, 0xF3, 0x73, 0xA7, 0x57, 0xAF, 0x58, 0xA8, 0x50, 0xF4,
   0xEA, 0xD6, 0x74, 0x4F, 0xAE, 0xE9, 0xD5, 0xE7, 0xE6, 0xAD, 0xE8, 0x2C, 0xD7, 0x75, 0x7A, 0xEB, 0x16, 0x0B, 0xF5,
   0x59, 0xCB, 0x5F, 0xB0, 0x9C, 0xA9, 0x51, 0xA0, 0x7F, 0x0C, 0xF6, 0x6F, 0x17, 0xC4, 0x49, 0xEC, 0xD8, 0x43, 0x1F,
   0x2D, 0xA4, 0x76, 0x7B, 0xB7, 0xCC, 0xBB, 0x3E, 0x5A, 0xFB, 0x60, 0xB1, 0x86, 0x3B, 0x52, 0xA1, 0x6C, 0xAA, 0x55,
   0x29, 0x9D, 0x97, 0xB2, 0x87, 0x90, 0x61, 0xBE, 0xDC, 0xFC, 0xBC, 0x95, 0xCF, 0xCD, 0x37, 0x3F, 0x5B, 0xD1, 0x53,
   0x39, 0x84, 0x3C, 0x41, 0xA2, 0x6D, 0x47, 0x14, 0x2A, 0x9E, 0x5D, 0x56, 0xF2, 0xD3, 0xAB, 0x44, 0x11, 0x92, 0xD9,
   0x23, 0x20, 0x2E, 0x89, 0xB4, 0x7C, 0xB8, 0x26, 0x77, 0x99, 0xE3, 0xA5, 0x67, 0x4A, 0xED, 0xDE, 0xC5, 0x31, 0xFE,
   0x18, 0x0D, 0x63, 0x8C, 0x80, 0xC0, 0xF7, 0x70, 0x07};

uint8_t gfp_mul(uint8_t x, uint8_t y) {
   if(x == 0 || y == 0) {
      return 0;
   }
   return RTSS_EXP[(RTSS_LOG[x] + RTSS_LOG[y]) % 255];
}

uint8_t rtss_hash_id(std::string_view hash_name) {
   if(hash_name == "None") {
      return 0;
   } else if(hash_name == "SHA-1") {
      return 1;
   } else if(hash_name == "SHA-256") {
      return 2;
   } else {
      throw Invalid_Argument("RTSS only supports SHA-1 and SHA-256");
   }
}

std::unique_ptr<HashFunction> get_rtss_hash_by_id(uint8_t id) {
   if(id == 0) {
      return std::unique_ptr<HashFunction>();
   }
   if(id == 1) {
      return HashFunction::create_or_throw("SHA-1");
   } else if(id == 2) {
      return HashFunction::create_or_throw("SHA-256");
   } else {
      throw Decoding_Error("Unknown RTSS hash identifier");
   }
}

}  // namespace

RTSS_Share::RTSS_Share(std::string_view hex_input) {
   m_contents = hex_decode_locked(hex_input);
}

RTSS_Share::RTSS_Share(const uint8_t bin[], size_t len) {
   m_contents.assign(bin, bin + len);
}

uint8_t RTSS_Share::share_id() const {
   if(!initialized()) {
      throw Invalid_State("RTSS_Share::share_id not initialized");
   }

   if(m_contents.size() < RTSS_HEADER_SIZE + 1) {
      throw Decoding_Error("RTSS_Share::share_id invalid share data");
   }

   return m_contents[20];
}

std::string RTSS_Share::to_string() const {
   return hex_encode(m_contents.data(), m_contents.size());
}

std::vector<RTSS_Share> RTSS_Share::split(
   uint8_t M, uint8_t N, const uint8_t S[], uint16_t S_len, const uint8_t identifier[16], RandomNumberGenerator& rng) {
   return RTSS_Share::split(M, N, S, S_len, std::vector<uint8_t>(identifier, identifier + 16), "SHA-256", rng);
}

std::vector<RTSS_Share> RTSS_Share::split(uint8_t M,
                                          uint8_t N,
                                          const uint8_t S[],
                                          uint16_t S_len,
                                          const std::vector<uint8_t>& identifier,
                                          std::string_view hash_fn,
                                          RandomNumberGenerator& rng) {
   if(M <= 1 || N <= 1 || M > N || N >= 255) {
      throw Invalid_Argument("RTSS_Share::split: Invalid N or M");
   }

   if(identifier.size() > 16) {
      throw Invalid_Argument("RTSS_Share::split Invalid identifier size");
   }

   const uint8_t hash_id = rtss_hash_id(hash_fn);

   std::unique_ptr<HashFunction> hash;
   if(hash_id > 0) {
      hash = HashFunction::create_or_throw(hash_fn);
   }

   // secret = S || H(S)
   secure_vector<uint8_t> secret(S, S + S_len);
   if(hash) {
      secret += hash->process(S, S_len);
   }

   if(secret.size() >= 0xFFFE) {
      throw Encoding_Error("RTSS_Share::split secret too large for TSS format");
   }

   // +1 byte for the share ID
   const uint16_t share_len = static_cast<uint16_t>(secret.size() + 1);

   secure_vector<uint8_t> share_header(RTSS_HEADER_SIZE);
   copy_mem(&share_header[0], identifier.data(), identifier.size());
   share_header[16] = hash_id;
   share_header[17] = M;
   share_header[18] = get_byte<0>(share_len);
   share_header[19] = get_byte<1>(share_len);

   // Create RTSS header in each share
   std::vector<RTSS_Share> shares(N);

   for(uint8_t i = 0; i != N; ++i) {
      shares[i].m_contents.reserve(share_header.size() + share_len);
      shares[i].m_contents = share_header;
   }

   // Choose sequential values for X starting from 1
   for(uint8_t i = 0; i != N; ++i) {
      shares[i].m_contents.push_back(i + 1);
   }

   for(size_t i = 0; i != secret.size(); ++i) {
      std::vector<uint8_t> coefficients(M - 1);
      rng.randomize(coefficients.data(), coefficients.size());

      for(uint8_t j = 0; j != N; ++j) {
         const uint8_t X = j + 1;

         uint8_t sum = secret[i];
         uint8_t X_i = X;

         for(size_t k = 0; k != coefficients.size(); ++k) {
            sum ^= gfp_mul(X_i, coefficients[k]);
            X_i = gfp_mul(X_i, X);
         }

         shares[j].m_contents.push_back(sum);
      }
   }

   return shares;
}

secure_vector<uint8_t> RTSS_Share::reconstruct(const std::vector<RTSS_Share>& shares) {
   if(shares.size() <= 1) {
      throw Decoding_Error("Insufficient shares to do TSS reconstruction");
   }

   for(size_t i = 0; i != shares.size(); ++i) {
      if(shares[i].size() < RTSS_HEADER_SIZE + 1) {
         throw Decoding_Error("Missing or malformed RTSS header");
      }

      if(shares[i].share_id() == 0) {
         throw Decoding_Error("Invalid (id = 0) RTSS share detected");
      }

      if(i > 0) {
         if(shares[i].size() != shares[0].size()) {
            throw Decoding_Error("Different sized RTSS shares detected");
         }

         if(!CT::is_equal(&shares[0].m_contents[0], &shares[i].m_contents[0], RTSS_HEADER_SIZE).as_bool()) {
            throw Decoding_Error("Different RTSS headers detected");
         }
      }
   }

   const uint8_t N = shares[0].m_contents[17];

   if(shares.size() < N) {
      throw Decoding_Error("Insufficient shares to do TSS reconstruction");
   }

   const uint16_t share_len = make_uint16(shares[0].m_contents[18], shares[0].m_contents[19]);

   const uint8_t hash_id = shares[0].m_contents[16];
   auto hash = get_rtss_hash_by_id(hash_id);
   const size_t hash_len = (hash ? hash->output_length() : 0);

   if(shares[0].size() != RTSS_HEADER_SIZE + share_len) {
      /*
      * This second (laxer) check accomodates a bug in TSS that was
      * fixed in 2.9.0 - previous versions used the length of the
      * *secret* here, instead of the length of the *share*, which is
      * precisely 1 + hash_len longer.
      */
      if(shares[0].size() <= RTSS_HEADER_SIZE + 1 + hash_len) {
         throw Decoding_Error("Bad RTSS length field in header");
      }
   }

   std::vector<uint8_t> V(shares.size());
   secure_vector<uint8_t> recovered;

   for(size_t i = RTSS_HEADER_SIZE + 1; i != shares[0].size(); ++i) {
      for(size_t j = 0; j != V.size(); ++j) {
         V[j] = shares[j].m_contents[i];
      }

      uint8_t r = 0;
      for(size_t k = 0; k != shares.size(); ++k) {
         // L_i function:
         uint8_t r2 = 1;
         for(size_t l = 0; l != shares.size(); ++l) {
            if(k == l) {
               continue;
            }

            uint8_t share_k = shares[k].share_id();
            uint8_t share_l = shares[l].share_id();

            if(share_k == share_l) {
               throw Decoding_Error("Duplicate shares found in RTSS recovery");
            }

            uint8_t div = RTSS_EXP[(255 + RTSS_LOG[share_l] - RTSS_LOG[share_k ^ share_l]) % 255];

            r2 = gfp_mul(r2, div);
         }

         r ^= gfp_mul(V[k], r2);
      }
      recovered.push_back(r);
   }

   if(hash) {
      if(recovered.size() < hash->output_length()) {
         throw Decoding_Error("RTSS recovered value too short to be valid");
      }

      const size_t secret_len = recovered.size() - hash->output_length();

      hash->update(recovered.data(), secret_len);
      secure_vector<uint8_t> hash_check = hash->final();

      if(!CT::is_equal(hash_check.data(), &recovered[secret_len], hash->output_length()).as_bool()) {
         throw Decoding_Error("RTSS hash check failed");
      }

      // remove the trailing hash value
      recovered.resize(secret_len);
   }

   return recovered;
}

}  // namespace Botan
