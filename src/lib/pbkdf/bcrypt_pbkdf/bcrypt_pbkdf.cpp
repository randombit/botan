/*
* (C) 2018,2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/bcrypt_pbkdf.h>

#include <botan/hash.h>
#include <botan/internal/blowfish.h>
#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/time_utils.h>

namespace Botan {

Bcrypt_PBKDF::Bcrypt_PBKDF(size_t iterations) : m_iterations(iterations) {
   BOTAN_ARG_CHECK(m_iterations > 0, "Invalid Bcrypt-PBKDF iterations");
}

std::string Bcrypt_PBKDF::to_string() const {
   return fmt("Bcrypt-PBKDF({})", m_iterations);
}

std::string Bcrypt_PBKDF_Family::name() const {
   return "Bcrypt-PBKDF";
}

std::unique_ptr<PasswordHash> Bcrypt_PBKDF_Family::tune(size_t output_length,
                                                        std::chrono::milliseconds msec,
                                                        size_t /*max_memory*/,
                                                        std::chrono::milliseconds tune_time) const {
   const size_t blocks = (output_length + 32 - 1) / 32;

   if(blocks == 0) {
      return default_params();
   }

   const size_t starting_iter = 2;

   auto pwhash = this->from_iterations(starting_iter);

   auto tune_fn = [&]() {
      uint8_t output[32] = {0};
      pwhash->derive_key(output, sizeof(output), "test", 4, nullptr, 0);
   };

   const uint64_t measured_time = measure_cost(tune_time, tune_fn) / blocks;

   const uint64_t target_nsec = msec.count() * static_cast<uint64_t>(1000000);

   const uint64_t desired_increase = target_nsec / measured_time;

   if(desired_increase == 0) {
      return this->from_iterations(starting_iter);
   }

   return this->from_iterations(static_cast<size_t>(desired_increase * starting_iter));
}

std::unique_ptr<PasswordHash> Bcrypt_PBKDF_Family::default_params() const {
   return this->from_iterations(32);  // About 100 ms on fast machine
}

std::unique_ptr<PasswordHash> Bcrypt_PBKDF_Family::from_iterations(size_t iter) const {
   return std::make_unique<Bcrypt_PBKDF>(iter);
}

std::unique_ptr<PasswordHash> Bcrypt_PBKDF_Family::from_params(size_t iter, size_t /*t*/, size_t /*p*/) const {
   return this->from_iterations(iter);
}

namespace {

void bcrypt_round(Blowfish& blowfish,
                  const secure_vector<uint8_t>& pass_hash,
                  const secure_vector<uint8_t>& salt_hash,
                  secure_vector<uint8_t>& out,
                  secure_vector<uint8_t>& tmp) {
   const size_t BCRYPT_PBKDF_OUTPUT = 32;

   // "OxychromaticBlowfishSwatDynamite"
   alignas(64) static const uint8_t BCRYPT_PBKDF_MAGIC[BCRYPT_PBKDF_OUTPUT] = {
      0x4F, 0x78, 0x79, 0x63, 0x68, 0x72, 0x6F, 0x6D, 0x61, 0x74, 0x69, 0x63, 0x42, 0x6C, 0x6F, 0x77,
      0x66, 0x69, 0x73, 0x68, 0x53, 0x77, 0x61, 0x74, 0x44, 0x79, 0x6E, 0x61, 0x6D, 0x69, 0x74, 0x65};

   const size_t BCRYPT_PBKDF_WORKFACTOR = 6;
   const size_t BCRYPT_PBKDF_ROUNDS = 64;

   blowfish.salted_set_key(
      pass_hash.data(), pass_hash.size(), salt_hash.data(), salt_hash.size(), BCRYPT_PBKDF_WORKFACTOR, true);

   copy_mem(tmp.data(), BCRYPT_PBKDF_MAGIC, BCRYPT_PBKDF_OUTPUT);
   for(size_t i = 0; i != BCRYPT_PBKDF_ROUNDS; ++i) {
      blowfish.encrypt(tmp);
   }

   /*
   Bcrypt PBKDF loads the Blowfish output as big endian for no reason
   in particular. We can't just swap everything once at the end
   because the (big-endian) values are fed into SHA-512 to generate
   the salt for the next round
   */
   for(size_t i = 0; i != 32 / 4; ++i) {
      const uint32_t w = load_le<uint32_t>(tmp.data(), i);
      store_be(w, &tmp[sizeof(uint32_t) * i]);
   }

   xor_buf(out.data(), tmp.data(), BCRYPT_PBKDF_OUTPUT);
}

}  // namespace

void Bcrypt_PBKDF::derive_key(uint8_t output[],
                              size_t output_len,
                              const char* password,
                              size_t password_len,
                              const uint8_t salt[],
                              size_t salt_len) const {
   // No output desired, so we are all done already...
   if(output_len == 0) {
      return;
   }

   BOTAN_ARG_CHECK(output_len <= 10 * 1024 * 1024, "Too much output for Bcrypt PBKDF");

   const size_t BCRYPT_BLOCK_SIZE = 32;
   const size_t blocks = (output_len + BCRYPT_BLOCK_SIZE - 1) / BCRYPT_BLOCK_SIZE;

   auto sha512 = HashFunction::create_or_throw("SHA-512");
   const auto pass_hash = sha512->process(reinterpret_cast<const uint8_t*>(password), password_len);

   secure_vector<uint8_t> salt_hash(sha512->output_length());

   Blowfish blowfish;
   secure_vector<uint8_t> out(BCRYPT_BLOCK_SIZE);
   secure_vector<uint8_t> tmp(BCRYPT_BLOCK_SIZE);

   for(size_t block = 0; block != blocks; ++block) {
      clear_mem(out.data(), out.size());

      sha512->update(salt, salt_len);
      sha512->update_be(static_cast<uint32_t>(block + 1));
      sha512->final(salt_hash.data());

      bcrypt_round(blowfish, pass_hash, salt_hash, out, tmp);

      for(size_t r = 1; r < m_iterations; ++r) {
         // Next salt is H(prev_output)
         sha512->update(tmp);
         sha512->final(salt_hash.data());

         bcrypt_round(blowfish, pass_hash, salt_hash, out, tmp);
      }

      for(size_t i = 0; i != BCRYPT_BLOCK_SIZE; ++i) {
         const size_t dest = i * blocks + block;
         if(dest < output_len) {
            output[dest] = out[i];
         }
      }
   }
}

}  // namespace Botan
