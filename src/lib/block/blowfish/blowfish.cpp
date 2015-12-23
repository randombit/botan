/*
* Blowfish
* (C) 1999-2011 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/blowfish.h>
#include <botan/loadstor.h>

namespace Botan {

/*
* Blowfish Encryption
*/
void Blowfish::encrypt_n(const byte in[], byte out[], size_t blocks) const
   {
   const u32bit* S1 = &m_S[0];
   const u32bit* S2 = &m_S[256];
   const u32bit* S3 = &m_S[512];
   const u32bit* S4 = &m_S[768];

   for(size_t i = 0; i != blocks; ++i)
      {
      u32bit L = load_be<u32bit>(in, 0);
      u32bit R = load_be<u32bit>(in, 1);

      for(size_t j = 0; j != 16; j += 2)
         {
         L ^= m_P[j];
         R ^= ((S1[get_byte(0, L)]  + S2[get_byte(1, L)]) ^
                S3[get_byte(2, L)]) + S4[get_byte(3, L)];

         R ^= m_P[j+1];
         L ^= ((S1[get_byte(0, R)]  + S2[get_byte(1, R)]) ^
                S3[get_byte(2, R)]) + S4[get_byte(3, R)];
         }

      L ^= m_P[16]; R ^= m_P[17];

      store_be(out, R, L);

      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      }
   }

/*
* Blowfish Decryption
*/
void Blowfish::decrypt_n(const byte in[], byte out[], size_t blocks) const
   {
   const u32bit* S1 = &m_S[0];
   const u32bit* S2 = &m_S[256];
   const u32bit* S3 = &m_S[512];
   const u32bit* S4 = &m_S[768];

   for(size_t i = 0; i != blocks; ++i)
      {
      u32bit L = load_be<u32bit>(in, 0);
      u32bit R = load_be<u32bit>(in, 1);

      for(size_t j = 17; j != 1; j -= 2)
         {
         L ^= m_P[j];
         R ^= ((S1[get_byte(0, L)]  + S2[get_byte(1, L)]) ^
                S3[get_byte(2, L)]) + S4[get_byte(3, L)];

         R ^= m_P[j-1];
         L ^= ((S1[get_byte(0, R)]  + S2[get_byte(1, R)]) ^
                S3[get_byte(2, R)]) + S4[get_byte(3, R)];
         }

      L ^= m_P[1]; R ^= m_P[0];

      store_be(out, R, L);

      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      }
   }

/*
* Blowfish Key Schedule
*/
void Blowfish::key_schedule(const byte key[], size_t length)
   {
   m_P.resize(18);
   copy_mem(m_P.data(), P_INIT, 18);

   m_S.resize(1024);
   copy_mem(m_S.data(), S_INIT, 1024);

   const byte null_salt[16] = { 0 };

   key_expansion(key, length, null_salt);
   }

void Blowfish::key_expansion(const byte key[],
                             size_t length,
                             const byte salt[16])
   {
   for(size_t i = 0, j = 0; i != 18; ++i, j += 4)
      m_P[i] ^= make_u32bit(key[(j  ) % length], key[(j+1) % length],
                          key[(j+2) % length], key[(j+3) % length]);

   u32bit L = 0, R = 0;
   generate_sbox(m_P, L, R, salt, 0);
   generate_sbox(m_S, L, R, salt, 2);
   }

/*
* Modified key schedule used for bcrypt password hashing
*/
void Blowfish::eks_key_schedule(const byte key[], size_t length,
                                const byte salt[16], size_t workfactor)
   {
   // Truncate longer passwords to the 56 byte limit Blowfish enforces
   length = std::min<size_t>(length, 55);

   if(workfactor == 0)
      throw Invalid_Argument("Bcrypt work factor must be at least 1");

   /*
   * On a 2.8 GHz Core-i7, workfactor == 18 takes about 25 seconds to
   * hash a password. This seems like a reasonable upper bound for the
   * time being.
   */
   if(workfactor > 18)
      throw Invalid_Argument("Requested Bcrypt work factor " +
                                  std::to_string(workfactor) + " too large");

   m_P.resize(18);
   copy_mem(m_P.data(), P_INIT, 18);

   m_S.resize(1024);
   copy_mem(m_S.data(), S_INIT, 1024);

   key_expansion(key, length, salt);

   const byte null_salt[16] = { 0 };
   const size_t rounds = static_cast<size_t>(1) << workfactor;

   for(size_t r = 0; r != rounds; ++r)
      {
      key_expansion(key, length, null_salt);
      key_expansion(salt, 16, null_salt);
      }
   }

/*
* Generate one of the Sboxes
*/
void Blowfish::generate_sbox(secure_vector<u32bit>& box,
                             u32bit& L, u32bit& R,
                             const byte salt[16],
                             size_t salt_off) const
   {
   const u32bit* S1 = &m_S[0];
   const u32bit* S2 = &m_S[256];
   const u32bit* S3 = &m_S[512];
   const u32bit* S4 = &m_S[768];

   for(size_t i = 0; i != box.size(); i += 2)
      {
      L ^= load_be<u32bit>(salt, (i + salt_off) % 4);
      R ^= load_be<u32bit>(salt, (i + salt_off + 1) % 4);

      for(size_t j = 0; j != 16; j += 2)
         {
         L ^= m_P[j];
         R ^= ((S1[get_byte(0, L)]  + S2[get_byte(1, L)]) ^
                S3[get_byte(2, L)]) + S4[get_byte(3, L)];

         R ^= m_P[j+1];
         L ^= ((S1[get_byte(0, R)]  + S2[get_byte(1, R)]) ^
                S3[get_byte(2, R)]) + S4[get_byte(3, R)];
         }

      u32bit T = R; R = L ^ m_P[16]; L = T ^ m_P[17];
      box[i] = L;
      box[i+1] = R;
      }
   }

/*
* Clear memory of sensitive data
*/
void Blowfish::clear()
   {
   zap(m_P);
   zap(m_S);
   }

}
