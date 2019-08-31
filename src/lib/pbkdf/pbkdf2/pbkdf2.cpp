/*
* PBKDF2
* (C) 1999-2007 Jack Lloyd
* (C) 2018 Ribose Inc
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pbkdf2.h>
#include <botan/exceptn.h>
#include <botan/internal/rounding.h>
#include <botan/internal/timer.h>

namespace Botan {

namespace {

void pbkdf2_set_key(MessageAuthenticationCode& prf,
                    const char* password,
                    size_t password_len)
   {
   try
      {
      prf.set_key(cast_char_ptr_to_uint8(password), password_len);
      }
   catch(Invalid_Key_Length&)
      {
      throw Invalid_Argument("PBKDF2 cannot accept passphrase of the given size");
      }
   }

}

size_t
pbkdf2(MessageAuthenticationCode& prf,
       uint8_t out[],
       size_t out_len,
       const std::string& password,
       const uint8_t salt[], size_t salt_len,
       size_t iterations,
       std::chrono::milliseconds msec)
   {
   if(iterations == 0)
      {
      iterations = PBKDF2(prf, out_len, msec).iterations();
      }

   PBKDF2 pbkdf2(prf, iterations);

   pbkdf2.derive_key(out, out_len,
                     password.c_str(), password.size(),
                     salt, salt_len);

   return iterations;
   }

namespace {

size_t tune_pbkdf2(MessageAuthenticationCode& prf,
                   size_t output_length,
                   uint32_t msec)
   {
   if(output_length == 0)
      output_length = 1;

   const size_t prf_sz = prf.output_length();
   BOTAN_ASSERT_NOMSG(prf_sz > 0);
   secure_vector<uint8_t> U(prf_sz);

   const size_t trial_iterations = 2000;

   // Short output ensures we only need a single PBKDF2 block

   Timer timer("PBKDF2");

   const auto tune_time = BOTAN_PBKDF_TUNING_TIME;

   prf.set_key(nullptr, 0);

   timer.run_until_elapsed(tune_time, [&]() {
      uint8_t out[12] = { 0 };
      uint8_t salt[12] = { 0 };
      pbkdf2(prf, out, sizeof(out), salt, sizeof(salt), trial_iterations);
      });

   if(timer.events() == 0)
      return trial_iterations;

   const uint64_t duration_nsec = timer.value() / timer.events();

   const uint64_t desired_nsec = static_cast<uint64_t>(msec) * 1000000;

   if(duration_nsec > desired_nsec)
      return trial_iterations;

   const size_t blocks_needed = (output_length + prf_sz - 1) / prf_sz;

   const size_t multiplier = static_cast<size_t>(desired_nsec / duration_nsec / blocks_needed);

   if(multiplier == 0)
      return trial_iterations;
   else
      return trial_iterations * multiplier;
   }

}

void pbkdf2(MessageAuthenticationCode& prf,
            uint8_t out[],
            size_t out_len,
            const uint8_t salt[],
            size_t salt_len,
            size_t iterations)
   {
   if(iterations == 0)
      throw Invalid_Argument("PBKDF2: Invalid iteration count");

   clear_mem(out, out_len);

   if(out_len == 0)
      return;

   const size_t prf_sz = prf.output_length();
   BOTAN_ASSERT_NOMSG(prf_sz > 0);

   secure_vector<uint8_t> U(prf_sz);

   uint32_t counter = 1;
   while(out_len)
      {
      const size_t prf_output = std::min<size_t>(prf_sz, out_len);

      prf.update(salt, salt_len);
      prf.update_be(counter++);
      prf.final(U.data());

      xor_buf(out, U.data(), prf_output);

      for(size_t i = 1; i != iterations; ++i)
         {
         prf.update(U);
         prf.final(U.data());
         xor_buf(out, U.data(), prf_output);
         }

      out_len -= prf_output;
      out += prf_output;
      }
   }

// PBKDF interface
size_t
PKCS5_PBKDF2::pbkdf(uint8_t key[], size_t key_len,
                    const std::string& password,
                    const uint8_t salt[], size_t salt_len,
                    size_t iterations,
                    std::chrono::milliseconds msec) const
   {
   if(iterations == 0)
      {
      iterations = PBKDF2(*m_mac, key_len, msec).iterations();
      }

   PBKDF2 pbkdf2(*m_mac, iterations);

   pbkdf2.derive_key(key, key_len,
                     password.c_str(), password.size(),
                     salt, salt_len);

   return iterations;
   }

std::string PKCS5_PBKDF2::name() const
   {
   return "PBKDF2(" + m_mac->name() + ")";
   }

PBKDF* PKCS5_PBKDF2::clone() const
   {
   return new PKCS5_PBKDF2(m_mac->clone());
   }

// PasswordHash interface

PBKDF2::PBKDF2(const MessageAuthenticationCode& prf, size_t olen, std::chrono::milliseconds msec) :
   m_prf(prf.clone()),
   m_iterations(tune_pbkdf2(*m_prf, olen, static_cast<uint32_t>(msec.count())))
   {}

std::string PBKDF2::to_string() const
   {
   return "PBKDF2(" + m_prf->name() + "," + std::to_string(m_iterations) + ")";
   }

void PBKDF2::derive_key(uint8_t out[], size_t out_len,
                        const char* password, const size_t password_len,
                        const uint8_t salt[], size_t salt_len) const
   {
   pbkdf2_set_key(*m_prf, password, password_len);
   pbkdf2(*m_prf, out, out_len, salt, salt_len, m_iterations);
   }

std::string PBKDF2_Family::name() const
   {
   return "PBKDF2(" + m_prf->name() + ")";
   }

std::unique_ptr<PasswordHash> PBKDF2_Family::tune(size_t output_len, std::chrono::milliseconds msec, size_t) const
   {
   return std::unique_ptr<PasswordHash>(new PBKDF2(*m_prf, output_len, msec));
   }

std::unique_ptr<PasswordHash> PBKDF2_Family::default_params() const
   {
   return std::unique_ptr<PasswordHash>(new PBKDF2(*m_prf, 150000));
   }

std::unique_ptr<PasswordHash> PBKDF2_Family::from_params(size_t iter, size_t, size_t) const
   {
   return std::unique_ptr<PasswordHash>(new PBKDF2(*m_prf, iter));
   }

std::unique_ptr<PasswordHash> PBKDF2_Family::from_iterations(size_t iter) const
   {
   return std::unique_ptr<PasswordHash>(new PBKDF2(*m_prf, iter));
   }

}
