/*
* AES Key Wrap (RFC 3394)
* (C) 2011 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/rfc3394.h>
#include <botan/block_cipher.h>
#include <botan/loadstor.h>
#include <botan/exceptn.h>

namespace Botan {

secure_vector<byte> rfc3394_keywrap(const secure_vector<byte>& key,
                                    const SymmetricKey& kek)
   {
   if(key.size() % 8 != 0)
      throw Invalid_Argument("Bad input key size for NIST key wrap");

   if(kek.size() != 16 && kek.size() != 24 && kek.size() != 32)
      throw Invalid_Argument("Bad KEK length " + std::to_string(kek.size()) + " for NIST key wrap");

   const std::string cipher_name = "AES-" + std::to_string(8*kek.size());
   std::unique_ptr<BlockCipher> aes(BlockCipher::create_or_throw(cipher_name));
   aes->set_key(kek);

   const size_t n = key.size() / 8;

   secure_vector<byte> R((n + 1) * 8);
   secure_vector<byte> A(16);

   for(size_t i = 0; i != 8; ++i)
      A[i] = 0xA6;

   copy_mem(&R[8], key.data(), key.size());

   for(size_t j = 0; j <= 5; ++j)
      {
      for(size_t i = 1; i <= n; ++i)
         {
         const u32bit t = (n * j) + i;

         copy_mem(&A[8], &R[8*i], 8);

         aes->encrypt(A.data());
         copy_mem(&R[8*i], &A[8], 8);

         byte t_buf[4] = { 0 };
         store_be(t, t_buf);
         xor_buf(&A[4], t_buf, 4);
         }
      }

   copy_mem(R.data(), A.data(), 8);

   return R;
   }

secure_vector<byte> rfc3394_keyunwrap(const secure_vector<byte>& key,
                                      const SymmetricKey& kek)
   {
   if(key.size() < 16 || key.size() % 8 != 0)
      throw Invalid_Argument("Bad input key size for NIST key unwrap");

   if(kek.size() != 16 && kek.size() != 24 && kek.size() != 32)
      throw Invalid_Argument("Bad KEK length " + std::to_string(kek.size()) + " for NIST key unwrap");

   const std::string cipher_name = "AES-" + std::to_string(8*kek.size());
   std::unique_ptr<BlockCipher> aes(BlockCipher::create_or_throw(cipher_name));
   aes->set_key(kek);

   const size_t n = (key.size() - 8) / 8;

   secure_vector<byte> R(n * 8);
   secure_vector<byte> A(16);

   for(size_t i = 0; i != 8; ++i)
      A[i] = key[i];

   copy_mem(R.data(), &key[8], key.size() - 8);

   for(size_t j = 0; j <= 5; ++j)
      {
      for(size_t i = n; i != 0; --i)
         {
         const u32bit t = (5 - j) * n + i;

         byte t_buf[4] = { 0 };
         store_be(t, t_buf);

         xor_buf(&A[4], t_buf, 4);

         copy_mem(&A[8], &R[8*(i-1)], 8);

         aes->decrypt(A.data());

         copy_mem(&R[8*(i-1)], &A[8], 8);
         }
      }

   if(load_be<u64bit>(A.data(), 0) != 0xA6A6A6A6A6A6A6A6)
      throw Integrity_Failure("NIST key unwrap failed");

   return R;
   }

}
