/*
* AES Key Wrap (RFC 3394)
* (C) 2011 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/rfc3394.h>
#include <botan/algo_factory.h>
#include <botan/block_cipher.h>
#include <botan/loadstor.h>
#include <botan/exceptn.h>
#include <botan/internal/xor_buf.h>
#include <memory>

namespace Botan {

namespace {

BlockCipher* make_aes(size_t keylength,
                      Algorithm_Factory& af)
   {
   if(keylength == 16)
      return af.make_block_cipher("AES-128");
   else if(keylength == 24)
      return af.make_block_cipher("AES-192");
   else if(keylength == 32)
      return af.make_block_cipher("AES-256");
   else
      throw std::invalid_argument("Bad KEK length for NIST keywrap");
   }

}

secure_vector<byte> rfc3394_keywrap(const secure_vector<byte>& key,
                                    const SymmetricKey& kek,
                                    Algorithm_Factory& af)
   {
   if(key.size() % 8 != 0)
      throw std::invalid_argument("Bad input key size for NIST key wrap");

   std::unique_ptr<BlockCipher> aes(make_aes(kek.length(), af));
   aes->set_key(kek);

   const size_t n = key.size() / 8;

   secure_vector<byte> R((n + 1) * 8);
   secure_vector<byte> A(16);

   for(size_t i = 0; i != 8; ++i)
      A[i] = 0xA6;

   copy_mem(&R[8], &key[0], key.size());

   for(size_t j = 0; j <= 5; ++j)
      {
      for(size_t i = 1; i <= n; ++i)
         {
         const u32bit t = (n * j) + i;

         copy_mem(&A[8], &R[8*i], 8);

         aes->encrypt(&A[0]);
         copy_mem(&R[8*i], &A[8], 8);

         byte t_buf[4] = { 0 };
         store_be(t, t_buf);
         xor_buf(&A[4], &t_buf[0], 4);
         }
      }

   copy_mem(&R[0], &A[0], 8);

   return R;
   }

secure_vector<byte> rfc3394_keyunwrap(const secure_vector<byte>& key,
                                     const SymmetricKey& kek,
                                     Algorithm_Factory& af)
   {
   if(key.size() < 16 || key.size() % 8 != 0)
      throw std::invalid_argument("Bad input key size for NIST key unwrap");

   std::unique_ptr<BlockCipher> aes(make_aes(kek.length(), af));
   aes->set_key(kek);

   const size_t n = (key.size() - 8) / 8;

   secure_vector<byte> R(n * 8);
   secure_vector<byte> A(16);

   for(size_t i = 0; i != 8; ++i)
      A[i] = key[i];

   copy_mem(&R[0], &key[8], key.size() - 8);

   for(size_t j = 0; j <= 5; ++j)
      {
      for(size_t i = n; i != 0; --i)
         {
         const u32bit t = (5 - j) * n + i;

         byte t_buf[4] = { 0 };
         store_be(t, t_buf);

         xor_buf(&A[4], &t_buf[0], 4);

         copy_mem(&A[8], &R[8*(i-1)], 8);

         aes->decrypt(&A[0]);

         copy_mem(&R[8*(i-1)], &A[8], 8);
         }
      }

   if(load_be<u64bit>(&A[0], 0) != 0xA6A6A6A6A6A6A6A6)
      throw Integrity_Failure("NIST key unwrap failed");

   return R;
   }

}
