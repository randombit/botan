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

#include <botan/internal/mce_internal.h>
#include <botan/internal/code_based_util.h>

namespace Botan {

namespace {

void matrix_arr_mul(std::vector<u32bit> matrix,
                    u32bit numo_rows,
                    u32bit words_per_row,
                    const byte* input_vec,
                    u32bit* output_vec, u32bit output_vec_len)
   {
   for(size_t j = 0; j < numo_rows; j++)
      {
      if((input_vec[j / 8] >> (j % 8)) & 1)
         {
         for(size_t i = 0; i < output_vec_len; i ++)
            {
            output_vec[i] ^= matrix[ j * (words_per_row) + i];
            }
         }
      }
   }

/**
* returns the error vector to the syndrome
*/
secure_vector<gf2m> goppa_decode(const polyn_gf2m & syndrom_polyn,
                                 const polyn_gf2m & g,
                                 const std::vector<polyn_gf2m> & sqrtmod,
                                 const std::vector<gf2m> & Linv)
   {
   gf2m a;
   u32bit code_length = Linv.size();
   u32bit t = g.get_degree();

   std::shared_ptr<GF2m_Field> sp_field = g.get_sp_field();

   std::pair<polyn_gf2m, polyn_gf2m> h__aux = polyn_gf2m::eea_with_coefficients( syndrom_polyn, g, 1);
   polyn_gf2m & h = h__aux.first;
   polyn_gf2m & aux = h__aux.second;
   a = sp_field->gf_inv(aux.get_coef(0));
   gf2m log_a = sp_field->gf_log(a);
   for(int i = 0; i <= h.get_degree(); ++i)
      {
      h.set_coef(i,sp_field->gf_mul_zrz(log_a,h.get_coef(i)));
      }

   //  compute h(z) += z
   h.add_to_coef( 1, 1);
   // compute S square root of h (using sqrtmod)
   polyn_gf2m S(t - 1, g.get_sp_field());

   for(u32bit i=0;i<t;i++)
      {
      a = sp_field->gf_sqrt(h.get_coef(i));

      if(i & 1)
         {
         for(u32bit j=0;j<t;j++)
            {
            S.add_to_coef( j, sp_field->gf_mul(a, sqrtmod[i/2].get_coef(j)));
            }
         }
      else
         {
         S.add_to_coef( i/2, a);
         }
      } /* end for loop (i) */


   S.get_degree();

   std::pair<polyn_gf2m, polyn_gf2m> v__u = polyn_gf2m::eea_with_coefficients(S, g, t/2+1);
   polyn_gf2m & u = v__u.second;
   polyn_gf2m & v = v__u.first;

   // sigma = u^2+z*v^2
   polyn_gf2m sigma ( t , g.get_sp_field());

   const size_t u_deg = u.get_degree();
   for(size_t i = 0; i <= u_deg; ++i)
      {
      sigma.set_coef(2*i, sp_field->gf_square(u.get_coef(i)));
      }

   const int v_deg = v.get_degree();
   BOTAN_ASSERT(v_deg > 0, "Valid degree");
   for(int i = 0; i <= v_deg; ++i)
      {
      sigma.set_coef(2*i+1, sp_field->gf_square(v.get_coef(i)));
      }

   secure_vector<gf2m> res = find_roots_gf2m_decomp(sigma, code_length);
   size_t d = res.size();

   secure_vector<gf2m> result(d);
   for(u32bit i = 0; i < d; ++i)
      {
      gf2m current = res[i];

      gf2m tmp;
      tmp = gray_to_lex(current);
      if(tmp >= code_length) /* invalid root */
         {
         result[i] = i;
         }
      result[i] = Linv[tmp];
      }

   return result;
   }
}

void mceliece_decrypt(secure_vector<byte>& plaintext_out,
                      secure_vector<byte>& error_mask_out,
                      const secure_vector<byte>& ciphertext,
                      const McEliece_PrivateKey& key)
   {
   mceliece_decrypt(plaintext_out, error_mask_out, ciphertext.data(), ciphertext.size(), key);
   }

void mceliece_decrypt(
   secure_vector<byte>& plaintext,
   secure_vector<byte> & error_mask,
   const byte ciphertext[],
   size_t ciphertext_len,
   const McEliece_PrivateKey & key)
   {
   secure_vector<gf2m> error_pos;
   plaintext = mceliece_decrypt(error_pos, ciphertext, ciphertext_len, key);

   const size_t code_length = key.get_code_length();
   secure_vector<byte> result((code_length+7)/8);
   for(auto&& pos : error_pos)
      {
      if(pos > code_length)
         {
         throw Invalid_Argument("error position larger than code size");
         }
      result[pos / 8] |= (1 << (pos % 8));
      }

   error_mask = result;
   }

/**
* @p p_err_pos_len must point to the available length of @p error_pos on input, the
* function will set it to the actual number of errors returned in the @p error_pos
* array */
secure_vector<byte> mceliece_decrypt(
   secure_vector<gf2m> & error_pos,
   const byte *ciphertext, u32bit ciphertext_len,
   const McEliece_PrivateKey & key)
   {

   u32bit dimension = key.get_dimension();
   u32bit codimension = key.get_codimension();
   u32bit t = key.get_goppa_polyn().get_degree();
   polyn_gf2m syndrome_polyn(key.get_goppa_polyn().get_sp_field()); // init as zero polyn
   const unsigned unused_pt_bits = dimension % 8;
   const byte unused_pt_bits_mask = (1 << unused_pt_bits) - 1;

   if(ciphertext_len != (key.get_code_length()+7)/8)
      {
      throw Invalid_Argument("wrong size of McEliece ciphertext");
      }
   u32bit cleartext_len = (key.get_message_word_bit_length()+7)/8;

   if(cleartext_len != bit_size_to_byte_size(dimension))
      {
      throw Invalid_Argument("mce-decryption: wrong length of cleartext buffer");
      }

   secure_vector<u32bit> syndrome_vec(bit_size_to_32bit_size(codimension));
   matrix_arr_mul(key.get_H_coeffs(),
                  key.get_code_length(),
                  bit_size_to_32bit_size(codimension),
                  ciphertext,
                  syndrome_vec.data(), syndrome_vec.size());

   secure_vector<byte> syndrome_byte_vec(bit_size_to_byte_size(codimension));
   u32bit syndrome_byte_vec_size = syndrome_byte_vec.size();
   for(u32bit i = 0; i < syndrome_byte_vec_size; i++)
      {
      syndrome_byte_vec[i] = syndrome_vec[i/4] >> (8* (i % 4));
      }

   syndrome_polyn = polyn_gf2m(t-1, syndrome_byte_vec.data(), bit_size_to_byte_size(codimension), key.get_goppa_polyn().get_sp_field());

   syndrome_polyn.get_degree();
   error_pos = goppa_decode(syndrome_polyn, key.get_goppa_polyn(), key.get_sqrtmod(), key.get_Linv());

   u32bit nb_err = error_pos.size();

   secure_vector<byte> cleartext(cleartext_len);
   copy_mem(cleartext.data(), ciphertext, cleartext_len);

   for(u32bit i = 0; i < nb_err; i++)
      {
      gf2m current = error_pos[i];

      if(current >= cleartext_len * 8)
         {
         // an invalid position, this shouldn't happen
         continue;
         }
      cleartext[current / 8] ^= (1 << (current % 8));
      }

   if(unused_pt_bits)
      {
      cleartext[cleartext_len - 1] &= unused_pt_bits_mask;
      }

   return cleartext;
   }

}
