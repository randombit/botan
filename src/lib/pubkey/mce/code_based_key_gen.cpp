/*
 * (C) Copyright Projet SECRET, INRIA, Rocquencourt
 * (C) Bhaskar Biswas and  Nicolas Sendrier
 *
 * (C) 2014 cryptosource GmbH
 * (C) 2014 Falko Strenzke fstrenzke@cryptosource.de
 * (C) 2015 Jack Lloyd
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 *
 */

#include <botan/mceliece.h>
#include <botan/internal/mce_internal.h>
#include <botan/internal/code_based_util.h>
#include <botan/polyn_gf2m.h>
#include <botan/loadstor.h>

namespace Botan {

namespace {

class binary_matrix final
   {
   public:
      binary_matrix(size_t m_rown, size_t m_coln);

      void row_xor(size_t a, size_t b);
      secure_vector<size_t> row_reduced_echelon_form();

      /**
      * return the coefficient out of F_2
      */
      uint32_t coef(size_t i, size_t j)
         {
         return (m_elem[(i) * m_rwdcnt + (j) / 32] >> (j % 32)) & 1;
         }

      void set_coef_to_one(size_t i, size_t j)
         {
         m_elem[(i) * m_rwdcnt + (j) / 32] |= (static_cast<uint32_t>(1) << ((j) % 32)) ;
         }

      void toggle_coeff(size_t i, size_t j)
         {
         m_elem[(i) * m_rwdcnt + (j) / 32] ^= (static_cast<uint32_t>(1) << ((j) % 32)) ;
         }

      size_t rows() const { return m_rown; }

      size_t columns() const { return m_coln; }

   private:
      size_t m_rown;  // number of rows.
      size_t m_coln; // number of columns.
      size_t m_rwdcnt; // number of words in a row
   public:
      // TODO this should be private
      std::vector<uint32_t> m_elem;
   };

binary_matrix::binary_matrix(size_t rown, size_t coln)
   {
   m_coln = coln;
   m_rown = rown;
   m_rwdcnt = 1 + ((m_coln - 1) / 32);
   m_elem = std::vector<uint32_t>(m_rown * m_rwdcnt);
   }

void binary_matrix::row_xor(size_t a, size_t b)
   {
   for(size_t i = 0; i != m_rwdcnt; i++)
      {
      m_elem[a*m_rwdcnt+i] ^= m_elem[b*m_rwdcnt+i];
      }
   }

//the matrix is reduced from LSB...(from right)
secure_vector<size_t> binary_matrix::row_reduced_echelon_form()
   {
   secure_vector<size_t> perm(m_coln);
   for(size_t i = 0; i != m_coln; i++)
      {
      perm[i] = i; // initialize permutation.
      }

   uint32_t failcnt = 0;

   size_t max = m_coln - 1;
   for(size_t i = 0; i != m_rown; i++, max--)
      {
      bool found_row = false;

      for(size_t j = i; !found_row && j != m_rown; j++)
         {
         if(coef(j, max))
            {
            if(i != j) //not needed as ith row is 0 and jth row is 1.
               {
               row_xor(i, j);//xor to the row.(swap)?
               }

            found_row = true;
            }
         }

      //if no row with a 1 found then swap last column and the column with no 1 down.
      if(!found_row)
         {
         perm[m_coln - m_rown - 1 - failcnt] = static_cast<int>(max);
         failcnt++;
         if(!max)
            {
            perm.resize(0);
            }
         i--;
         }
      else
         {
         perm[i+m_coln - m_rown] = max;
         for(size_t j=i+1;j<m_rown;j++)//fill the column downwards with 0's
            {
            if(coef(j, max))
               {
               row_xor(j,i);//check the arg. order.
               }
            }

         //fill the column with 0's upwards too.
         for(size_t j = i; j != 0; --j)
            {
            if(coef(j - 1, max))
               {
               row_xor(j - 1, i);
               }
            }
         }
      }//end for(i)
   return perm;
   }

void randomize_support(std::vector<gf2m>& L, RandomNumberGenerator& rng)
   {
   for(size_t i = 0; i != L.size(); ++i)
      {
      gf2m rnd = random_gf2m(rng);

       // no rejection sampling, but for useful code-based parameters with n <= 13 this seem tolerable
      std::swap(L[i], L[rnd % L.size()]);
      }
   }

std::unique_ptr<binary_matrix> generate_R(std::vector<gf2m> &L, polyn_gf2m* g, std::shared_ptr<GF2m_Field> sp_field, size_t code_length, size_t t)
   {
   //L- Support
   //t- Number of errors
   //n- Length of the Goppa code
   //m- The extension degree of the GF
   //g- The generator polynomial.

   const size_t r = t * sp_field->get_extension_degree();

   binary_matrix H(r, code_length);

   for(size_t i = 0; i != code_length; i++)
      {
      gf2m x = g->eval(lex_to_gray(L[i]));//evaluate the polynomial at the point L[i].
      x = sp_field->gf_inv(x);
      gf2m y = x;
      for(size_t j=0;j<t;j++)
         {
         for(size_t k=0;k<sp_field->get_extension_degree();k++)
            {
            if(y & (1<<k))
               {
               //the co-eff. are set in 2^0,...,2^11 ; 2^0,...,2^11 format along the rows/cols?
               H.set_coef_to_one(j*sp_field->get_extension_degree()+ k,i);
               }
            }
         y = sp_field->gf_mul(y,lex_to_gray(L[i]));
         }
      }//The H matrix is fed.

   secure_vector<size_t> perm = H.row_reduced_echelon_form();
   if(perm.size() == 0)
      {
      throw Invalid_State("McEliece keygen failed - could not bring matrix to row reduced echelon form");
      }

   std::unique_ptr<binary_matrix> result(new binary_matrix(code_length-r, r)) ;
   for(size_t i = 0; i < result->rows(); ++i)
      {
      for(size_t j = 0; j < result->columns(); ++j)
         {
         if(H.coef(j, perm[i]))
            {
            result->toggle_coeff(i,j);
            }
         }
      }

   std::vector<gf2m> Laux(code_length);
   for(size_t i = 0; i < code_length; ++i)
      {
      Laux[i] = L[perm[i]];
      }

   for(size_t i = 0; i < code_length; ++i)
      {
      L[i] = Laux[i];
      }
   return result;
   }
}

McEliece_PrivateKey generate_mceliece_key(RandomNumberGenerator & rng, size_t ext_deg, size_t code_length, size_t t)
   {
   const size_t codimension = t * ext_deg;

   if(code_length <= codimension)
      {
      throw Invalid_Argument("invalid McEliece parameters");
      }

   std::shared_ptr<GF2m_Field> sp_field(new GF2m_Field(ext_deg));

   //pick the support.........
   std::vector<gf2m> L(code_length);

   for(size_t i = 0; i != L.size(); i++)
      {
      L[i] = static_cast<gf2m>(i);
      }
   randomize_support(L, rng);
   polyn_gf2m g(sp_field); // create as zero

   bool success = false;
   std::unique_ptr<binary_matrix> R;

   do
      {
      // create a random irreducible polynomial
      g = polyn_gf2m(t, rng, sp_field);

      try
         {
         R = generate_R(L, &g, sp_field, code_length, t);
         success = true;
         }
      catch(const Invalid_State &)
         {
         }
      } while (!success);

   std::vector<polyn_gf2m> sqrtmod = polyn_gf2m::sqrt_mod_init( g);
   std::vector<polyn_gf2m> F = syndrome_init(g, L, static_cast<int>(code_length));

   // Each F[i] is the (precomputed) syndrome of the error vector with
   // a single '1' in i-th position.
   // We do not store the F[i] as polynomials of degree t , but
   // as binary vectors of length ext_deg * t (this will
   // speed up the syndrome computation)
   //
   std::vector<uint32_t> H(bit_size_to_32bit_size(codimension) * code_length);
   uint32_t* sk = H.data();
   for(size_t i = 0; i < code_length; ++i)
      {
      for(size_t l = 0; l < t; ++l)
         {
         const size_t k = (l * ext_deg) / 32;
         const uint8_t j = (l * ext_deg) % 32;
         sk[k] ^= static_cast<uint32_t>(F[i].get_coef(l)) << j;
         if(j + ext_deg > 32)
            {
            sk[k + 1] ^= F[i].get_coef(l) >> (32 - j);
            }
         }
      sk += bit_size_to_32bit_size(codimension);
      }

   // We need the support L for decoding (decryption). In fact the
   // inverse is needed

   std::vector<gf2m> Linv(code_length) ;
   for(size_t i = 0; i != Linv.size(); ++i)
      {
      Linv[L[i]] = static_cast<gf2m>(i);
      }
   std::vector<uint8_t> pubmat(R->m_elem.size() * 4);
   for(size_t i = 0; i < R->m_elem.size(); i++)
      {
      store_le(R->m_elem[i], &pubmat[i*4]);
      }

   return McEliece_PrivateKey(g, H, sqrtmod, Linv, pubmat);
   }

}
