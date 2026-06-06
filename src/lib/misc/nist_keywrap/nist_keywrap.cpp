/*
* (C) 2011,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/nist_keywrap.h>

#include <botan/block_cipher.h>
#include <botan/exceptn.h>
#include <botan/internal/int_utils.h>
#include <botan/internal/loadstor.h>

namespace Botan {

namespace {

std::vector<uint8_t> raw_nist_key_wrap(const uint8_t input[], size_t input_len, const BlockCipher& bc, uint64_t ICV) {
   const size_t n = input_len / 8 + (input_len % 8 != 0 ? 1 : 0);

   secure_vector<uint8_t> R(mul_or_throw<size_t>(8, n + 1, "NIST key wrap input too large"));
   secure_vector<uint8_t> A(16);

   store_be(ICV, A.data());

   copy_mem(&R[8], input, input_len);

   for(size_t j = 0; j <= 5; ++j) {
      for(size_t i = 1; i <= n; ++i) {
         const uint32_t t = static_cast<uint32_t>((n * j) + i);

         copy_mem(&A[8], &R[8 * i], 8);

         bc.encrypt(A.data());
         copy_mem(&R[8 * i], &A[8], 8);

         uint8_t t_buf[4] = {0};
         store_be(t, t_buf);
         xor_buf(&A[4], t_buf, 4);
      }
   }

   copy_mem(R.data(), A.data(), 8);

   return std::vector<uint8_t>(R.begin(), R.end());
}

secure_vector<uint8_t> raw_nist_key_unwrap(const uint8_t input[],
                                           size_t input_len,
                                           const BlockCipher& bc,
                                           uint64_t& ICV_out) {
   if(input_len < 16 || input_len % 8 != 0) {
      throw Invalid_Argument("Bad input size for NIST key unwrap");
   }

   const size_t n = (input_len - 8) / 8;

   secure_vector<uint8_t> R(n * 8);
   secure_vector<uint8_t> A(16);

   for(size_t i = 0; i != 8; ++i) {
      A[i] = input[i];
   }

   copy_mem(R.data(), input + 8, input_len - 8);

   for(size_t j = 0; j <= 5; ++j) {
      for(size_t i = n; i != 0; --i) {
         const uint32_t t = static_cast<uint32_t>((5 - j) * n + i);

         uint8_t t_buf[4] = {0};
         store_be(t, t_buf);

         xor_buf(&A[4], t_buf, 4);

         copy_mem(&A[8], &R[8 * (i - 1)], 8);

         bc.decrypt(A.data());

         copy_mem(&R[8 * (i - 1)], &A[8], 8);
      }
   }

   ICV_out = load_be<uint64_t>(A.data(), 0);

   return R;
}

}  // namespace

std::vector<uint8_t> nist_key_wrap(const uint8_t input[], size_t input_len, const BlockCipher& bc) {
   if(bc.block_size() != 16) {
      throw Invalid_Argument("NIST key wrap algorithm requires a 128-bit cipher");
   }

   if(input_len == 0 || input_len % 8 != 0) {
      throw Invalid_Argument("Bad input size for NIST key wrap");
   }

   const uint64_t ICV = 0xA6A6A6A6A6A6A6A6;

   if(input_len == 8) {
      /*
      * Special case for small inputs: if input == 8 bytes just use ECB
      * (see RFC 3394 Section 2)
      */
      std::vector<uint8_t> block(16);
      store_be(ICV, block.data());
      copy_mem(block.data() + 8, input, input_len);
      bc.encrypt(block);
      return block;
   } else {
      return raw_nist_key_wrap(input, input_len, bc, ICV);
   }
}

secure_vector<uint8_t> nist_key_unwrap(const uint8_t input[], size_t input_len, const BlockCipher& bc) {
   if(bc.block_size() != 16) {
      throw Invalid_Argument("NIST key wrap algorithm requires a 128-bit cipher");
   }

   if(input_len < 16 || input_len % 8 != 0) {
      throw Invalid_Argument("Bad input size for NIST key unwrap");
   }

   const uint64_t ICV = 0xA6A6A6A6A6A6A6A6;

   uint64_t ICV_out = 0;
   secure_vector<uint8_t> R;

   if(input_len == 16) {
      secure_vector<uint8_t> block(input, input + input_len);
      bc.decrypt(block);

      ICV_out = load_be<uint64_t>(block.data(), 0);
      R.resize(8);
      copy_mem(R.data(), block.data() + 8, 8);
   } else {
      R = raw_nist_key_unwrap(input, input_len, bc, ICV_out);
   }

   if(ICV_out != ICV) {
      throw Invalid_Authentication_Tag("NIST key unwrap failed");
   }

   return R;
}

std::vector<uint8_t> nist_key_wrap_padded(const uint8_t input[], size_t input_len, const BlockCipher& bc) {
   if(bc.block_size() != 16) {
      throw Invalid_Argument("NIST key wrap algorithm requires a 128-bit cipher");
   }

   if(input_len == 0) {
      throw Invalid_Argument("NIST KWP cannot accept empty inputs");
   }

   const uint64_t ICV = 0xA65959A600000000 | static_cast<uint32_t>(input_len);

   if(input_len <= 8) {
      /*
      * Special case for small inputs: if input <= 8 bytes just use ECB
      */
      std::vector<uint8_t> block(16);
      store_be(ICV, block.data());
      copy_mem(block.data() + 8, input, input_len);
      bc.encrypt(block);
      return block;
   } else {
      return raw_nist_key_wrap(input, input_len, bc, ICV);
   }
}

secure_vector<uint8_t> nist_key_unwrap_padded(const uint8_t input[], size_t input_len, const BlockCipher& bc) {
   if(bc.block_size() != 16) {
      throw Invalid_Argument("NIST key wrap algorithm requires a 128-bit cipher");
   }

   if(input_len < 16 || input_len % 8 != 0) {
      throw Invalid_Argument("Bad input size for NIST key unwrap");
   }

   uint64_t ICV_out = 0;
   secure_vector<uint8_t> R;

   if(input_len == 16) {
      secure_vector<uint8_t> block(input, input + input_len);
      bc.decrypt(block);

      ICV_out = load_be<uint64_t>(block.data(), 0);
      R.resize(8);
      copy_mem(R.data(), block.data() + 8, 8);
   } else {
      R = raw_nist_key_unwrap(input, input_len, bc, ICV_out);
   }

   /*
   The padded key wrap ICV is 0xA65959A6 || uint32(plaintext_length).

   We know the expected ICV almost entirely: the top 32 bits are the
   fixed constant and the bottom 32 bits encode the original plaintext
   length, which is R.size() minus 0 to 7 bytes of padding. Compute
   the ICV we'd expect for the zero-padding case and subtract ICV_out;
   for a valid unwrap the difference is at most 7, and equals the padding.
   For an invalid unwrap the unsigned subtraction wraps to a value > 7
   (checked below), so the modular arithmetic here is intentional.
   */
   const uint64_t expected_ICV_max = 0xA65959A600000000 | static_cast<uint32_t>(R.size());
   const uint64_t padding = expected_ICV_max - ICV_out;

   if(padding > 7) {
      throw Invalid_Authentication_Tag("NIST key unwrap failed");
   }

   // Verify padding bytes are zero
   const uint64_t last_block = load_be<uint64_t>(R.data() + R.size() - 8, 0);
   const uint64_t padding_mask = (static_cast<uint64_t>(1) << (padding * 8)) - 1;
   if((last_block & padding_mask) != 0) {
      throw Invalid_Authentication_Tag("NIST key unwrap failed");
   }

   R.resize(R.size() - static_cast<size_t>(padding));
   return R;
}

}  // namespace Botan
