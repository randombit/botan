/**
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/scrypt.h>
#include <botan/pbkdf2.h>
#include <botan/salsa20.h>
#include <botan/loadstor.h>
#include <botan/internal/bit_ops.h>

namespace Botan {

namespace {

void scryptBlockMix(size_t r, uint8_t* B, uint8_t* Y)
   {
   uint32_t B32[16];
   secure_vector<uint8_t> X(64);
   copy_mem(X.data(), &B[(2*r-1)*64], 64);

   for(size_t i = 0; i != 2*r; i++)
      {
      xor_buf(X.data(), &B[64*i], 64);
      load_le<uint32_t>(B32, X.data(), 16);
      Salsa20::salsa_core(X.data(), B32, 8);
      copy_mem(&Y[64*i], X.data(), 64);
      }

   for(size_t i = 0; i < r; ++i)
      {
      copy_mem(&B[i*64], &Y[(i * 2) * 64], 64);
      }

   for(size_t i = 0; i < r; ++i)
      {
      copy_mem(&B[(i + r) * 64], &Y[(i * 2 + 1) * 64], 64);
      }
   }

void scryptROMmix(size_t r, size_t N, uint8_t* B, secure_vector<uint8_t>& V)
   {
   const size_t S = 128 * r;

   for(size_t i = 0; i != N; ++i)
      {
      copy_mem(&V[S*i], B, S);
      scryptBlockMix(r, B, &V[N*S]);
      }

   for(size_t i = 0; i != N; ++i)
      {
      // compiler doesn't know here that N is power of 2
      const size_t j = load_le<uint32_t>(&B[(2*r-1)*64], 0) & (N - 1);
      xor_buf(B, &V[j*S], S);
      scryptBlockMix(r, B, &V[N*S]);
      }
   }

}

Scrypt_Params::Scrypt_Params(size_t N, size_t r, size_t p) :
   m_N(N), m_r(r), m_p(p)
   {
   BOTAN_ARG_CHECK(p <= 128, "Invalid scrypt p");
   BOTAN_ARG_CHECK(N <= 4194304 && is_power_of_2(N), "Invalid scrypt N");
   BOTAN_ARG_CHECK(r <= 64, "Invalid scrypt r");
   }

Scrypt_Params::Scrypt_Params(std::chrono::milliseconds msec)
   {
   /*
   This mapping is highly subjective and machine specific
   For simplicity we fix r=8 and p=4
   */
   m_r = 8;
   m_p = 4;

   if(msec.count() <= 10)
      {
      m_N = 4096;
      m_p = 1;
      }
   else if(msec.count() <= 50)
      {
      m_N = 8192;
      }
   else if(msec.count() <= 100)
      {
      m_N = 16384;
      }
   else if(msec.count() <= 500)
      {
      m_N = 32768;
      }
   else
      {
      m_N = 65536;
      }
   }

Scrypt_Params::Scrypt_Params(size_t iterations)
   {
   // This mapping is highly subjective and machine specific
   m_r = 8;
   m_p = 4;

   if(iterations < 1000)
      {
      m_N = 8192;
      }
   else if(iterations < 5000)
      {
      m_N = 16384;
      }
   else if(iterations < 10000)
      {
      m_N = 32768;
      }
   else
      {
      m_N = 65536;
      }
   }

void scrypt(uint8_t output[], size_t output_len,
            const std::string& password,
            const uint8_t salt[], size_t salt_len,
            const Scrypt_Params& params)
   {
   scrypt(output, output_len, password, salt, salt_len,
          params.N(), params.r(), params.p());
   }

void scrypt(uint8_t output[], size_t output_len,
            const std::string& password,
            const uint8_t salt[], size_t salt_len,
            size_t N, size_t r, size_t p)
   {
   // Upper bounds here are much lower than scrypt maximums yet seem sufficient
   BOTAN_ARG_CHECK(p <= 128, "Invalid scrypt p");
   BOTAN_ARG_CHECK(N <= 4194304 && is_power_of_2(N), "Invalid scrypt N");
   BOTAN_ARG_CHECK(r <= 64, "Invalid scrypt r");

   const size_t S = 128 * r;
   secure_vector<uint8_t> B(p * S);

   PKCS5_PBKDF2 pbkdf2(MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)").release());

   pbkdf2.pbkdf(B.data(), B.size(),
                password,
                salt, salt_len,
                1, std::chrono::milliseconds(0));

   // temp space
   secure_vector<uint8_t> V((N+1) * S);

   // these can be parallel
   for(size_t i = 0; i != p; ++i)
      {
      scryptROMmix(r, N, &B[128*r*i], V);
      }

   pbkdf2.pbkdf(output, output_len,
                password,
                B.data(), B.size(),
                1, std::chrono::milliseconds(0));
   }

}
