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

#include <botan/internal/binary_matrix.h>
#include <botan/internal/xor_buf.h>

namespace Botan {

binary_matrix::binary_matrix (u32bit rown, u32bit coln)
   {
   m_coln = coln;
   m_rown = rown;
   m_rwdcnt = (1 + (m_coln - 1) / BITS_PER_U32);
   m_alloc_size = m_rown * (*this).m_rwdcnt * sizeof (u32bit);
   m_elem = std::vector<u32bit>((*this).m_alloc_size/4);
   }

void binary_matrix::row_xor(u32bit a, u32bit b)
   {
   u32bit i;
   for(i=0;i<m_rwdcnt;i++)
      {
      m_elem[a*m_rwdcnt+i]^=m_elem[b*m_rwdcnt+i];
      }
   }

//the matrix is reduced from LSB...(from right)
secure_vector<int> binary_matrix::row_reduced_echelon_form()
   {
   u32bit i, failcnt, findrow, max=m_coln - 1;

   secure_vector<int> perm(m_coln);
   for(i=0;i<m_coln;i++)
      {
      perm[i]=i;//initialize permutation.
      }
   failcnt = 0;

   for(i=0;i<m_rown;i++,max--)
      {
      findrow=0;
      for(u32bit j=i;j<m_rown;j++)
         {
         if(coef(j,max))
            {
            if (i!=j)//not needed as ith row is 0 and jth row is 1.
               row_xor(i,j);//xor to the row.(swap)?
            findrow=1;
            break;
            }//largest value found (end if)
         }

      if(!findrow)//if no row with a 1 found then swap last column and the column with no 1 down.
         {
         perm[m_coln - m_rown - 1 - failcnt] = max;
         failcnt++;
         if (!max)
            {
            //CSEC_FREE_MEM_CHK_SET_NULL(*p_perm);
            //CSEC_THR_RETURN();
            perm.resize(0);
            }
         i--;
         }
      else
         {
         perm[i+m_coln - m_rown] = max;
         for(u32bit j=i+1;j<m_rown;j++)//fill the column downwards with 0's
            {
            if(coef(j,(max)))
               {
               row_xor(j,i);//check the arg. order.
               }
            }

         for(int j=i-1;j>=0;j--)//fill the column with 0's upwards too.
            {
            if(coef(j,(max)))
               {
               row_xor(j,i);
               }
            }
         }
      }//end for(i)
   return perm;
   }


} // end namespace Botan
