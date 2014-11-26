/**
 * (C) Copyright Projet SECRET, INRIA, Rocquencourt
 * (C) Bhaskar Biswas and  Nicolas Sendrier
 *
 * (C) 2014 cryptosource GmbH
 * (C) 2014 Falko Strenzke fstrenzke@cryptosource.de
 *
 * Distributed under the terms of the Botan license
 *
 */

#include <botan/internal/code_based_key_gen.h>
#include <botan/code_based_util.h>
#include <botan/gf2m_rootfind_dcmp.h>
#include <botan/internal/binary_matrix.h>
#include <botan/loadstor.h>
#include <botan/polyn_gf2m.h>

namespace Botan {

namespace {

void randomize_support(u32bit n, std::vector<gf2m> & L, RandomNumberGenerator & rng)
   {
   unsigned int i, j;
   gf2m_small_m::gf2m tmp;

   for (i = 0; i < n; ++i)
      {

      gf2m_small_m::gf2m rnd;
      rng.randomize(reinterpret_cast<byte*>(&rnd), sizeof(rnd));
      j = rnd % n; // no rejection sampling, but for useful code-based parameters with n <= 13 this seem tolerable

      tmp = L[j];
      L[j] = L[i];
      L[i] = tmp;
      }
   }

std::unique_ptr<binary_matrix> generate_R(std::vector<gf2m> &L, polyn_gf2m* g, std::shared_ptr<gf2m_small_m::Gf2m_Field> sp_field, u32bit code_length, u32bit t )
   {
   //L- Support
   //t- Number of errors
   //n- Length of the Goppa code
   //m- The extension degree of the GF
   //g- The generator polynomial.
   gf2m_small_m::gf2m x,y;
   u32bit i,j,k,r,n;
   std::vector<int> Laux(code_length);
   n=code_length;
   r=t*sp_field->get_extension_degree();

   binary_matrix H(r, n) ;

   for(i=0;i< n;i++)
      {
      x = g->eval(lex_to_gray(L[i]));//evaluate the polynomial at the point L[i].
      x = sp_field->gf_inv(x);
      y = x;
      for(j=0;j<t;j++)
         {
         for(k=0;k<sp_field->get_extension_degree();k++)
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

   secure_vector<int> perm = H.row_reduced_echelon_form();
   if (perm.size() == 0)
      {
      // result still is NULL
      throw Invalid_State("could not bring matrix in row reduced echelon form");
      }

   std::unique_ptr<binary_matrix> result(new binary_matrix(n-r,r)) ;
   for (i = 0; i < (*result).m_rown; ++i)
      {
      for (j = 0; j < (*result).m_coln; ++j)
         {
         if (H.coef(j,perm[i]))
            {
            result->toggle_coeff(i,j);
            }
         }
      }
   for (i = 0; i < code_length; ++i)
      {
      Laux[i] = L[perm[i]];
      }
   for (i = 0; i < code_length; ++i)
      {
      L[i] = Laux[i];
      }
   return result;
   }
}

McEliece_PrivateKey generate_mceliece_key( RandomNumberGenerator & rng, u32bit ext_deg, u32bit code_length, u32bit t)
   {
   u32bit i, j, k, l;
   std::unique_ptr<binary_matrix> R;

   u32bit codimension = t * ext_deg;
   if(code_length <= codimension)
      {
      throw Invalid_Argument("invalid McEliece parameters");
      }
   std::shared_ptr<gf2m_small_m::Gf2m_Field> sp_field ( new Gf2m_Field(ext_deg ));

   //pick the support.........
   std::vector<gf2m> L(code_length);

   for(i=0;i<code_length;i++)
      {
      L[i]=i;
      }
   randomize_support(code_length,L,rng);
   polyn_gf2m g(sp_field); // create as zero
   bool success = false;
   do
      {
      // create a random irreducible polynomial
      g = polyn_gf2m (t, rng, sp_field);

      try{
      R = generate_R(L,&g, sp_field, code_length, t);
      success = true;
      }
      catch(const Invalid_State &)
         {
         }
      } while (!success);

   std::vector<polyn_gf2m> sqrtmod = polyn_gf2m::sqrt_mod_init( g);
   std::vector<polyn_gf2m> F = syndrome_init(g, L, code_length);

   // Each F[i] is the (precomputed) syndrome of the error vector with
   // a single '1' in i-th position.
   // We do not store the F[i] as polynomials of degree t , but
   // as binary vectors of length ext_deg * t (this will
   // speed up the syndrome computation)
   //
   //
   std::vector<u32bit> H(bit_size_to_32bit_size(codimension) * code_length );
   u32bit* sk = &H[0];
   for (i = 0; i < code_length; ++i)
      {
      for (l = 0; l < t; ++l)
         {
         k = (l * ext_deg) / 32;
         j = (l * ext_deg) % 32;
         sk[k] ^= F[i].get_coef( l) << j;
         if (j + ext_deg > 32)
            {
            sk[k + 1] ^= F[i].get_coef( l) >> (32 - j);
            }
         }
      sk += bit_size_to_32bit_size(codimension);
      }

   // We need the support L for decoding (decryption). In fact the
   // inverse is needed

   std::vector<gf2m> Linv(code_length) ;
   for (i = 0; i < code_length; ++i)
      {
      Linv[L[i]] = i;
      }
   std::vector<byte> pubmat (R->m_alloc_size);
   for(i = 0; i < R->m_alloc_size/4; i++)
      {
      store_le(R->m_elem[i], &pubmat[i*4] );
      }

   return McEliece_PrivateKey(g, H, sqrtmod, Linv, pubmat);
   }

}
