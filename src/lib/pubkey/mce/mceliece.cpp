/**
 * (C) Copyright Projet SECRET, INRIA, Rocquencourt
 * (C) Bhaskar Biswas and  Nicolas Sendrier
 *
 * (C) 2014 cryptosource GmbH
 * (C) 2014 Falko Strenzke fstrenzke@cryptosource.de
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 *
 */

#include <botan/mceliece.h>
#include <botan/mceliece_key.h>
#include <botan/internal/code_based_key_gen.h>
#include <botan/polyn_gf2m.h>
#include <botan/code_based_util.h>
#include <botan/goppa_code.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/xor_buf.h>

namespace Botan {

namespace {

void concat_vectors(byte* x, const byte* a, const byte* b, u32bit dimension, u32bit codimension)
   {
   if(dimension % 8 == 0)
      {
      const size_t dim_bytes = bit_size_to_byte_size(dimension);
      copy_mem(x, a, dim_bytes);
      copy_mem(x + dim_bytes, b, bit_size_to_byte_size(codimension));
      }
   else
      {
      u32bit i, j, k, l;
      i = dimension - 8 * (dimension/ 8);
      j = 8 - i;
      l = dimension / 8;
      copy_mem(x, a, 1 * (dimension / 8));
      x[l] = static_cast<byte>(a[l] & ((1 << i) - 1));

      for(k = 0; k < codimension / 8; ++k)
         {
         x[l] ^= static_cast<byte>(b[k] << i);
         ++l;
         x[l] = static_cast<byte>(b[k] >> j);
         }
      x[l] ^= static_cast<byte>(b[k] << i);
      }
   }

std::vector<byte> mult_by_pubkey(const byte *cleartext,
                                 std::vector<byte> const& public_matrix,
                                 u32bit code_length, u32bit t)
   {
   std::vector<byte> ciphertext(code_length);
   u32bit i, j;
   u32bit ext_deg = ceil_log2(code_length);
   u32bit codimension = ext_deg * t;
   u32bit dimension = code_length - codimension;
   std::vector<byte> cR(bit_size_to_32bit_size(codimension)* sizeof(u32bit));

   const byte* pt = public_matrix.data();

   for(i = 0; i < dimension / 8; ++i)
      {
      for(j = 0; j < 8; ++j)
         {
         if(cleartext[i] & (1 << j))
            {
            xor_buf(cR.data(), pt, cR.size());
            }
         pt += bit_size_to_32bit_size(codimension) * sizeof(u32bit);
         }
      }

   for(j = 0; j < dimension % 8 ; ++j)
      {
      if(cleartext[i] & (1 << j))
         {
         xor_buf(cR.data(), pt, bit_size_to_byte_size(codimension));
         }
      pt += bit_size_to_32bit_size(codimension) * sizeof(u32bit);
      }

   concat_vectors(ciphertext.data(), cleartext, cR.data(), dimension, codimension);
   return ciphertext;
   }

}

secure_vector<gf2m> create_random_error_positions(unsigned code_length,
                                                  unsigned error_weight,
                                                  RandomNumberGenerator& rng)
   {
   secure_vector<gf2m> result(error_weight);
   gf2m i;
   for(i = 0; i < result.size(); i++)
      {
      unsigned j;
      char try_again = 0;
      do
         {
         try_again = 0;
         gf2m new_pos = random_code_element(code_length, rng);
         for(j = 0; j < i; j++)
            {
            if(new_pos == result[j])
               {
               try_again = 1;
               break;
               }
            }
         result[i] = new_pos;
         } while(try_again);
      }
   return result;
   }

McEliece_Private_Operation::McEliece_Private_Operation(const McEliece_PrivateKey& private_key)
   :m_priv_key(private_key)
   {
   }

secure_vector<byte> McEliece_Private_Operation::decrypt(const byte msg[], size_t msg_len)
   {
   secure_vector<gf2m> err_pos;

   secure_vector<byte> plaintext = mceliece_decrypt(
      err_pos,
      msg, msg_len,
      m_priv_key
      );

   return mceliece_message_parts(err_pos, plaintext, m_priv_key.get_code_length()).get_concat();
   }

McEliece_Public_Operation::McEliece_Public_Operation(const McEliece_PublicKey& public_key, u32bit the_code_length)
   :m_pub_key(public_key),
    m_code_length(the_code_length)
   {}

secure_vector<byte> McEliece_Public_Operation::encrypt(const byte msg[], size_t msg_len, RandomNumberGenerator&)
   {
   mceliece_message_parts parts(msg, msg_len, m_pub_key.get_code_length());
   secure_vector<gf2m> err_pos = parts.get_error_positions();
   secure_vector<byte> message_word = parts.get_message_word();
   secure_vector<byte> ciphertext((m_pub_key.get_code_length()+7)/8);


   std::vector<byte> ciphertext_tmp = mceliece_encrypt( message_word,  m_pub_key.get_public_matrix(), err_pos, m_code_length);

   copy_mem(ciphertext.data(), ciphertext_tmp.data(), ciphertext.size());
   return ciphertext;
   }

std::vector<byte> mceliece_encrypt(const secure_vector<byte> & cleartext,
                                   std::vector<byte> const& public_matrix,
                                   const secure_vector<gf2m> & err_pos,
                                   u32bit code_length)
   {
   std::vector<byte> ciphertext = mult_by_pubkey(cleartext.data(), public_matrix, code_length, err_pos.size());

   // flip t error positions
   for(size_t i = 0; i < err_pos.size(); ++i)
      {
      ciphertext[err_pos[i] / 8] ^= (1 << (err_pos[i] % 8));
      }

   return ciphertext;
   }

}
