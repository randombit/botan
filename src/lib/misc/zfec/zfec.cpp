/*
* Forward error correction based on Vandermonde matrices
*
* (C) 1997-1998 Luigi Rizzo (luigi@iet.unipi.it)
* (C) 2009,2010,2021 Jack Lloyd
* (C) 2011 Billy Brumley (billy.brumley@aalto.fi)
* (C) 2016-2017 Vivint, Inc.
*
* Botan is released under the Simplified BSD License (see license.txt)
*
* Portions of this code are also subject to the terms of the MIT License:
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

#include <botan/zfec.h>
#include <botan/exceptn.h>
#include <botan/internal/cpuid.h>
#include <botan/mem_ops.h>
#include <algorithm>
#include <iterator>
#include <vector>
#include <cstring>

namespace Botan {

namespace {

/* Tables for arithetic in GF(2^8) using 1+x^2+x^3+x^4+x^8
*
* See Lin & Costello, Appendix A, and Lee & Messerschmitt, p. 453.
*
* Generate GF(2**m) from the irreducible polynomial p(X) in p[0]..p[m]
* Lookup tables:
*     index->polynomial form           gf_exp[] contains j= \alpha^i;
*     polynomial form -> index form    gf_log[ j = \alpha^i ] = i
* \alpha=x is the primitive element of GF(2^m)
*/
alignas(256) const uint8_t GF_EXP[255] = {
   0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1D, 0x3A, 0x74,
   0xE8, 0xCD, 0x87, 0x13, 0x26, 0x4C, 0x98, 0x2D, 0x5A, 0xB4, 0x75,
   0xEA, 0xC9, 0x8F, 0x03, 0x06, 0x0C, 0x18, 0x30, 0x60, 0xC0, 0x9D,
   0x27, 0x4E, 0x9C, 0x25, 0x4A, 0x94, 0x35, 0x6A, 0xD4, 0xB5, 0x77,
   0xEE, 0xC1, 0x9F, 0x23, 0x46, 0x8C, 0x05, 0x0A, 0x14, 0x28, 0x50,
   0xA0, 0x5D, 0xBA, 0x69, 0xD2, 0xB9, 0x6F, 0xDE, 0xA1, 0x5F, 0xBE,
   0x61, 0xC2, 0x99, 0x2F, 0x5E, 0xBC, 0x65, 0xCA, 0x89, 0x0F, 0x1E,
   0x3C, 0x78, 0xF0, 0xFD, 0xE7, 0xD3, 0xBB, 0x6B, 0xD6, 0xB1, 0x7F,
   0xFE, 0xE1, 0xDF, 0xA3, 0x5B, 0xB6, 0x71, 0xE2, 0xD9, 0xAF, 0x43,
   0x86, 0x11, 0x22, 0x44, 0x88, 0x0D, 0x1A, 0x34, 0x68, 0xD0, 0xBD,
   0x67, 0xCE, 0x81, 0x1F, 0x3E, 0x7C, 0xF8, 0xED, 0xC7, 0x93, 0x3B,
   0x76, 0xEC, 0xC5, 0x97, 0x33, 0x66, 0xCC, 0x85, 0x17, 0x2E, 0x5C,
   0xB8, 0x6D, 0xDA, 0xA9, 0x4F, 0x9E, 0x21, 0x42, 0x84, 0x15, 0x2A,
   0x54, 0xA8, 0x4D, 0x9A, 0x29, 0x52, 0xA4, 0x55, 0xAA, 0x49, 0x92,
   0x39, 0x72, 0xE4, 0xD5, 0xB7, 0x73, 0xE6, 0xD1, 0xBF, 0x63, 0xC6,
   0x91, 0x3F, 0x7E, 0xFC, 0xE5, 0xD7, 0xB3, 0x7B, 0xF6, 0xF1, 0xFF,
   0xE3, 0xDB, 0xAB, 0x4B, 0x96, 0x31, 0x62, 0xC4, 0x95, 0x37, 0x6E,
   0xDC, 0xA5, 0x57, 0xAE, 0x41, 0x82, 0x19, 0x32, 0x64, 0xC8, 0x8D,
   0x07, 0x0E, 0x1C, 0x38, 0x70, 0xE0, 0xDD, 0xA7, 0x53, 0xA6, 0x51,
   0xA2, 0x59, 0xB2, 0x79, 0xF2, 0xF9, 0xEF, 0xC3, 0x9B, 0x2B, 0x56,
   0xAC, 0x45, 0x8A, 0x09, 0x12, 0x24, 0x48, 0x90, 0x3D, 0x7A, 0xF4,
   0xF5, 0xF7, 0xF3, 0xFB, 0xEB, 0xCB, 0x8B, 0x0B, 0x16, 0x2C, 0x58,
   0xB0, 0x7D, 0xFA, 0xE9, 0xCF, 0x83, 0x1B, 0x36, 0x6C, 0xD8, 0xAD,
   0x47, 0x8E,
};

alignas(256) const uint8_t GF_LOG[256] = {
   0xFF, 0x00, 0x01, 0x19, 0x02, 0x32, 0x1A, 0xC6, 0x03, 0xDF, 0x33,
   0xEE, 0x1B, 0x68, 0xC7, 0x4B, 0x04, 0x64, 0xE0, 0x0E, 0x34, 0x8D,
   0xEF, 0x81, 0x1C, 0xC1, 0x69, 0xF8, 0xC8, 0x08, 0x4C, 0x71, 0x05,
   0x8A, 0x65, 0x2F, 0xE1, 0x24, 0x0F, 0x21, 0x35, 0x93, 0x8E, 0xDA,
   0xF0, 0x12, 0x82, 0x45, 0x1D, 0xB5, 0xC2, 0x7D, 0x6A, 0x27, 0xF9,
   0xB9, 0xC9, 0x9A, 0x09, 0x78, 0x4D, 0xE4, 0x72, 0xA6, 0x06, 0xBF,
   0x8B, 0x62, 0x66, 0xDD, 0x30, 0xFD, 0xE2, 0x98, 0x25, 0xB3, 0x10,
   0x91, 0x22, 0x88, 0x36, 0xD0, 0x94, 0xCE, 0x8F, 0x96, 0xDB, 0xBD,
   0xF1, 0xD2, 0x13, 0x5C, 0x83, 0x38, 0x46, 0x40, 0x1E, 0x42, 0xB6,
   0xA3, 0xC3, 0x48, 0x7E, 0x6E, 0x6B, 0x3A, 0x28, 0x54, 0xFA, 0x85,
   0xBA, 0x3D, 0xCA, 0x5E, 0x9B, 0x9F, 0x0A, 0x15, 0x79, 0x2B, 0x4E,
   0xD4, 0xE5, 0xAC, 0x73, 0xF3, 0xA7, 0x57, 0x07, 0x70, 0xC0, 0xF7,
   0x8C, 0x80, 0x63, 0x0D, 0x67, 0x4A, 0xDE, 0xED, 0x31, 0xC5, 0xFE,
   0x18, 0xE3, 0xA5, 0x99, 0x77, 0x26, 0xB8, 0xB4, 0x7C, 0x11, 0x44,
   0x92, 0xD9, 0x23, 0x20, 0x89, 0x2E, 0x37, 0x3F, 0xD1, 0x5B, 0x95,
   0xBC, 0xCF, 0xCD, 0x90, 0x87, 0x97, 0xB2, 0xDC, 0xFC, 0xBE, 0x61,
   0xF2, 0x56, 0xD3, 0xAB, 0x14, 0x2A, 0x5D, 0x9E, 0x84, 0x3C, 0x39,
   0x53, 0x47, 0x6D, 0x41, 0xA2, 0x1F, 0x2D, 0x43, 0xD8, 0xB7, 0x7B,
   0xA4, 0x76, 0xC4, 0x17, 0x49, 0xEC, 0x7F, 0x0C, 0x6F, 0xF6, 0x6C,
   0xA1, 0x3B, 0x52, 0x29, 0x9D, 0x55, 0xAA, 0xFB, 0x60, 0x86, 0xB1,
   0xBB, 0xCC, 0x3E, 0x5A, 0xCB, 0x59, 0x5F, 0xB0, 0x9C, 0xA9, 0xA0,
   0x51, 0x0B, 0xF5, 0x16, 0xEB, 0x7A, 0x75, 0x2C, 0xD7, 0x4F, 0xAE,
   0xD5, 0xE9, 0xE6, 0xE7, 0xAD, 0xE8, 0x74, 0xD6, 0xF4, 0xEA, 0xA8,
   0x50, 0x58, 0xAF };

alignas(256) const uint8_t GF_INVERSE[256] = {
   0x00, 0x01, 0x8E, 0xF4, 0x47, 0xA7, 0x7A, 0xBA, 0xAD, 0x9D, 0xDD,
   0x98, 0x3D, 0xAA, 0x5D, 0x96, 0xD8, 0x72, 0xC0, 0x58, 0xE0, 0x3E,
   0x4C, 0x66, 0x90, 0xDE, 0x55, 0x80, 0xA0, 0x83, 0x4B, 0x2A, 0x6C,
   0xED, 0x39, 0x51, 0x60, 0x56, 0x2C, 0x8A, 0x70, 0xD0, 0x1F, 0x4A,
   0x26, 0x8B, 0x33, 0x6E, 0x48, 0x89, 0x6F, 0x2E, 0xA4, 0xC3, 0x40,
   0x5E, 0x50, 0x22, 0xCF, 0xA9, 0xAB, 0x0C, 0x15, 0xE1, 0x36, 0x5F,
   0xF8, 0xD5, 0x92, 0x4E, 0xA6, 0x04, 0x30, 0x88, 0x2B, 0x1E, 0x16,
   0x67, 0x45, 0x93, 0x38, 0x23, 0x68, 0x8C, 0x81, 0x1A, 0x25, 0x61,
   0x13, 0xC1, 0xCB, 0x63, 0x97, 0x0E, 0x37, 0x41, 0x24, 0x57, 0xCA,
   0x5B, 0xB9, 0xC4, 0x17, 0x4D, 0x52, 0x8D, 0xEF, 0xB3, 0x20, 0xEC,
   0x2F, 0x32, 0x28, 0xD1, 0x11, 0xD9, 0xE9, 0xFB, 0xDA, 0x79, 0xDB,
   0x77, 0x06, 0xBB, 0x84, 0xCD, 0xFE, 0xFC, 0x1B, 0x54, 0xA1, 0x1D,
   0x7C, 0xCC, 0xE4, 0xB0, 0x49, 0x31, 0x27, 0x2D, 0x53, 0x69, 0x02,
   0xF5, 0x18, 0xDF, 0x44, 0x4F, 0x9B, 0xBC, 0x0F, 0x5C, 0x0B, 0xDC,
   0xBD, 0x94, 0xAC, 0x09, 0xC7, 0xA2, 0x1C, 0x82, 0x9F, 0xC6, 0x34,
   0xC2, 0x46, 0x05, 0xCE, 0x3B, 0x0D, 0x3C, 0x9C, 0x08, 0xBE, 0xB7,
   0x87, 0xE5, 0xEE, 0x6B, 0xEB, 0xF2, 0xBF, 0xAF, 0xC5, 0x64, 0x07,
   0x7B, 0x95, 0x9A, 0xAE, 0xB6, 0x12, 0x59, 0xA5, 0x35, 0x65, 0xB8,
   0xA3, 0x9E, 0xD2, 0xF7, 0x62, 0x5A, 0x85, 0x7D, 0xA8, 0x3A, 0x29,
   0x71, 0xC8, 0xF6, 0xF9, 0x43, 0xD7, 0xD6, 0x10, 0x73, 0x76, 0x78,
   0x99, 0x0A, 0x19, 0x91, 0x14, 0x3F, 0xE6, 0xF0, 0x86, 0xB1, 0xE2,
   0xF1, 0xFA, 0x74, 0xF3, 0xB4, 0x6D, 0x21, 0xB2, 0x6A, 0xE3, 0xE7,
   0xB5, 0xEA, 0x03, 0x8F, 0xD3, 0xC9, 0x42, 0xD4, 0xE8, 0x75, 0x7F,
   0xFF, 0x7E, 0xFD };

const uint8_t* GF_MUL_TABLE(uint8_t y)
   {
   class GF_Table final
      {
      public:
         GF_Table()
            {
            m_table.resize(256 * 256);

            // x*0 = 0*y = 0 so we iterate over [1,255)
            for(size_t i = 1; i != 256; ++i)
               {
               for(size_t j = 1; j != 256; ++j)
                  {
                  m_table[256*i + j] = GF_EXP[(GF_LOG[i] + GF_LOG[j]) % 255];
                  }
               }
            }

         const uint8_t* ptr(uint8_t y) const
            {
            return &m_table[256*y];
            }
      private:
         std::vector<uint8_t> m_table;
      };

   static GF_Table table;
   return table.ptr(y);
   }

/*
* invert_matrix() takes a K*K matrix and produces its inverse
* (Gauss-Jordan algorithm, adapted from Numerical Recipes in C)
*/
void invert_matrix(uint8_t matrix[], size_t K)
   {
   class pivot_searcher
      {
      public:
         explicit pivot_searcher(size_t K) : m_ipiv(K) {}

         std::pair<size_t, size_t> operator()(size_t col, const uint8_t matrix[])
            {
            /*
            * Zeroing column 'col', look for a non-zero element.
            * First try on the diagonal, if it fails, look elsewhere.
            */

            const size_t K = m_ipiv.size();

            if(m_ipiv[col] == false && matrix[col*K + col] != 0)
               {
               m_ipiv[col] = true;
               return std::make_pair(col, col);
               }

            for(size_t row = 0; row != K; ++row)
               {
               if(m_ipiv[row])
                  continue;

               for(size_t i = 0; i != K; ++i)
                  {
                  if(m_ipiv[i] == false && matrix[row*K + i] != 0)
                     {
                     m_ipiv[i] = true;
                     return std::make_pair(row, i);
                     }
                  }
               }

            throw Invalid_Argument("ZFEC: pivot not found in invert_matrix");
            }

      private:
         // Marks elements already used as pivots
         std::vector<bool> m_ipiv;
      };

   pivot_searcher pivot_search(K);
   std::vector<size_t> indxc(K);
   std::vector<size_t> indxr(K);

   for(size_t col = 0; col != K; ++col)
      {
      const auto icolrow = pivot_search(col, matrix);

      const size_t icol = icolrow.first;
      const size_t irow = icolrow.second;

      /*
      * swap rows irow and icol, so afterwards the diagonal
      * element will be correct. Rarely done, not worth
      * optimizing.
      */
      if(irow != icol)
         {
         for(size_t i = 0; i != K; ++i)
            std::swap(matrix[irow*K + i], matrix[icol*K + i]);
         }

      indxr[col] = irow;
      indxc[col] = icol;
      uint8_t* pivot_row = &matrix[icol*K];
      const uint8_t c = pivot_row[icol];
      pivot_row[icol] = 1;

      if(c == 0)
         throw Invalid_Argument("ZFEC: singlar matrix");

      if(c != 1)
         {
         const uint8_t* mul_c = GF_MUL_TABLE(GF_INVERSE[c]);
         for(size_t i = 0; i != K; ++i)
            pivot_row[i] = mul_c[pivot_row[i]];
         }

      /*
      * From all rows, remove multiples of the selected row to zero
      * the relevant entry (in fact, the entry is not zero because we
      * know it must be zero).
      */
      for(size_t i = 0; i != K; ++i)
         {
         if(i != icol)
            {
            const uint8_t z = matrix[i*K + icol];
            matrix[i*K + icol] = 0;

            // This is equivalent to addmul()
            const uint8_t* mul_z = GF_MUL_TABLE(z);
            for(size_t j = 0; j != K; ++j)
               matrix[i*K + j] ^= mul_z[pivot_row[j]];
            }
         }
      }

   for(size_t i = 0; i != K; ++i)
      {
      if(indxr[i] != indxc[i])
         {
         for(size_t row = 0; row != K; ++row)
            std::swap(matrix[row*K + indxr[i]], matrix[row*K + indxc[i]]);
         }
      }
   }

/*
* Generate and invert a Vandermonde matrix.
*
* Only uses the second column of the matrix, containing the p_i's
* (contents - 0, GF_EXP[0...n])
*
* Algorithm borrowed from "Numerical recipes in C", section 2.8, but
* largely revised for my purposes.
*
* p = coefficients of the matrix (p_i)
* q = values of the polynomial (known)
*/
void create_inverted_vdm(uint8_t vdm[], size_t K)
   {
   if(K == 0)
      {
      return;
      }

   if(K == 1) /* degenerate case, matrix must be p^0 = 1 */
      {
      vdm[0] = 1;
      return;
      }

   /*
   * c holds the coefficient of P(x) = Prod (x - p_i), i=0..K-1
   * b holds the coefficient for the matrix inversion
   */
   std::vector<uint8_t> b(K);
   std::vector<uint8_t> c(K);

   /*
   * construct coeffs. recursively. We know c[K] = 1 (implicit)
   * and start P_0 = x - p_0, then at each stage multiply by
   * x - p_i generating P_i = x P_{i-1} - p_i P_{i-1}
   * After K steps we are done.
   */
   c[K-1] = 0; /* really -p(0), but x = -x in GF(2^m) */
   for(size_t i = 1; i < K; ++i)
      {
      const uint8_t* mul_p_i = GF_MUL_TABLE(GF_EXP[i]);

      for(size_t j = K-1  - (i - 1); j < K-1; ++j)
         c[j] ^= mul_p_i[c[j+1]];
      c[K-1] ^= GF_EXP[i];
      }

   for(size_t row = 0; row < K; ++row)
      {
      // synthetic division etc.
      const uint8_t* mul_p_row = GF_MUL_TABLE(row == 0 ? 0 : GF_EXP[row]);

      uint8_t t = 1;
      b[K-1] = 1; /* this is in fact c[K] */
      for(size_t i = K - 1; i > 0; i--)
         {
         b[i-1] = c[i] ^ mul_p_row[b[i]];
         t = b[i-1] ^ mul_p_row[t];
         }

      const uint8_t* mul_t_inv = GF_MUL_TABLE(GF_INVERSE[t]);
      for(size_t col = 0; col != K; ++col)
         vdm[col*K + row] = mul_t_inv[b[col]];
      }
   }

// helpers for Galois field arithmetic

uint8_t gf_add(uint8_t a, uint8_t b)
   {
   return a ^ b;
   }

uint8_t gf_mul(uint8_t a, uint8_t b)
   {
   return GF_MUL_TABLE(a)[b];
   }

uint8_t gf_pow(uint8_t base, size_t power)
   {
   uint8_t out = 1;
   auto mul_base = GF_MUL_TABLE(base);
   for(size_t i = 0; i < power; ++i)
      {
      out = mul_base[out];
      }
   return out;
   }

uint8_t gf_div(uint8_t a, uint8_t b)
   {
   if(b == 0)
      {
      throw Internal_Error("division by zero");
      }
   if(a == 0)
      {
      return 0;
      }
   return GF_EXP[(GF_LOG[a] - GF_LOG[b]) % 255];
   }

uint8_t gf_inv(uint8_t v)
   {
   if(v == 0)
      {
      throw Internal_Error("inversion of zero");
      }
   return GF_EXP[(255 - GF_LOG[v]) % 255];
   }

uint8_t gf_dot(const uint8_t* a, const uint8_t* b, int size)
   {
   uint8_t out = 0;
   for(int i = 0; i < size; ++i)
      {
      out = gf_add(out, gf_mul(a[i], b[i]));
      }
   return out;
   }

// represents a polynomial over Galois fields
class GFPoly
   {
   public:
      GFPoly()
         : start_at {0} {}

      explicit GFPoly(std::vector<uint8_t> values_)
         : values {std::move(values_)}
         , start_at {0} {}

      explicit GFPoly(int size)
         : values {std::vector<uint8_t>(size, 0)}
         , start_at {0} {}

      int size() const
         {
         return static_cast<int>(values.size()) - start_at;
         }

      int deg() const
         {
         return static_cast<int>(size()) - 1;
         }

      GFPoly scale(uint8_t factor) const
         {
         std::vector<uint8_t> out(size(), 0);
         for(int i = 0; i < static_cast<int>(out.size()); ++i)
            {
            out[i] = gf_mul((*this)[i], factor);
            }
         return GFPoly(std::move(out));
         }

      uint8_t index(int power) const
         {
         if(power < 0)
            {
            return 0;
            }
         int which = deg() - power;
         if(which < 0)
            {
            return 0;
            }
         return (*this)[which];
         }

      void set(int pow, uint8_t coef)
         {
         int which = deg() - pow;
         if(which < 0)
            {
            std::vector<uint8_t> tmp = std::move(values);
            values = std::vector<uint8_t>(-which, 0);
            values.insert(values.end(), tmp.begin() + start_at, tmp.end());
            which = deg() - pow;
            start_at = 0;
            }
         values[start_at + which] = coef;
         }

      GFPoly add(const GFPoly& b) const
         {
         auto len = size();
         if(b.size() > len)
            {
            len = b.size();
            }
         GFPoly out(len);
         for(int i = 0; i < out.size(); ++i)
            {
            auto ai = index(i);
            auto bi = b.index(i);
            out.set(i, gf_add(ai, bi));
            }
         return out;
         }

      bool is_zero() const
         {
         return std::all_of(values.begin() + start_at, values.end(), [](uint8_t v) -> bool { return v == 0; });
         }

      void remove_leading_zeroes()
         {
         while(start_at < static_cast<int>(values.size()) && values[start_at] == 0)
            {
            ++start_at;
            }
         }

      void push_back(uint8_t v)
         {
         values.push_back(v);
         }

      // Calculates *this divided by b; returns the quotient and remainder.
      // Throws Internal_Error on divide by zero.
      [[nodiscard]] std::pair<GFPoly, GFPoly> div(GFPoly b)
         {
         // sanitize the divisor by removing leading zeros.
         b.remove_leading_zeroes();
         if(b.size() == 0)
            {
            throw Internal_Error("polynomial divide by zero");
            }

         // sanitize the base poly as well
         GFPoly p = *this;
         p.remove_leading_zeroes();
         if(p.size() == 0)
            {
            return std::make_pair(GFPoly(1), GFPoly(1));
            }

         GFPoly q;
         while(b.deg() <= p.deg())
            {
            auto leading_p = p.index(p.deg());
            auto leading_b = b.index(b.deg());

            auto coef = gf_div(leading_p, leading_b);
            q.push_back(coef);

            auto padded = b.scale(coef);
            std::vector<uint8_t> zeros_to_append(p.deg() - padded.deg(), 0);
            std::copy(zeros_to_append.begin(), zeros_to_append.end(), std::back_inserter(padded.values));

            p = p.add(padded);
            if(p[0] != 0)
               {
               throw Internal_Error("algebraic error in polynomial division");
               }
            p.shift(1);
            }

         while(p.size() > 1 && p[0] == 0)
            {
            p.shift(1);
            }

         return std::make_pair(q, p);
         }

      uint8_t& operator[](int index)
         {
         if(static_cast<int>(values.size()) - start_at <= index)
            {
            throw Lookup_Error("index out of bounds");
            }
         return values[index + start_at];
         }

      const uint8_t& operator[](int index) const
         {
         if(static_cast<int>(values.size()) - start_at <= index)
            {
            throw Lookup_Error("index out of bounds");
            }
         return values[index + start_at];
         }

      void shift(int elements)
         {
         if(static_cast<int>(values.size()) - start_at < elements)
            {
            throw Internal_Error("can't shift this polynomial to requested extent");
            }
         start_at += elements;
         }

      uint8_t eval(uint8_t x) const
         {
         uint8_t out = 0;
         for(int i = 0; i <= deg(); ++i)
            {
            auto x_i = gf_pow(x, i);
            auto p_i = index(i);
            out = gf_add(out, gf_mul(p_i, x_i));
            }
         return out;
         }

   private:
      std::vector<uint8_t> values;
      // This class is implemented using an index into the array, because
      // "remove elements from the beginning of the array" is something that
      // is needed quite frequently in the course of our berlekamp-welch error
      // correction. All lookups into `values` should add `start_at` to the
      // desired index.
      int start_at;
   };

}

// Helper class for matrix algebra over Galois fields
class GFMat
   {
   public:
      GFMat(int i, int j)
         : m_d(i*j)
         , m_r(i)
         , m_c(j) {}

      [[nodiscard]] int index(int i, int j) const
         {
         return m_c * i + j;
         }

      [[nodiscard]] uint8_t get(int i, int j) const
         {
         return m_d[index(i, j)];
         }

      void set(int i, int j, uint8_t val)
         {
         m_d[index(i, j)] = val;
         }

      uint8_t* index_row(int i)
         {
         return &m_d[index(i, 0)];
         }

      void swap_row(int i, int j)
         {
         std::vector<uint8_t> tmp(m_c);
         auto ri = index_row(i);
         auto rj = index_row(j);
         std::copy(ri, ri + m_c, tmp.begin());
         std::copy(rj, rj + m_c, ri);
         std::copy(tmp.begin(), tmp.begin() + m_c, rj);
         }

      void scale_row(int r, uint8_t val)
         {
         auto ri = index_row(r);
         for(int i = 0; i < m_c; ++i)
            {
            ri[i] = gf_mul(ri[i], val);
            }
         }

      void addmul_row(int i, int j, uint8_t val)
         {
         auto ri = index_row(i);
         auto rj = index_row(j);
         ZFEC::addmul(rj, ri, val, m_c);
         }

      // in-place invert. the output is put into a, and *this is turned into
      // the identity matrix. a is expected to be the identity matrix.
      void invert_with(GFMat& a)
         {
         for(int i = 0; i < m_r; ++i)
            {
            int p_row = i;
            auto p_val = get(i, i);
            for(int j = i + 1; j < m_r && p_val == 0; ++j)
               {
               p_row = j;
               p_val = get(j, i);
               }
            if(p_val == 0)
               {
               continue;
               }

            if(p_row != i)
               {
               swap_row(i, p_row);
               a.swap_row(i, p_row);
               }

            auto inv = gf_inv(p_val);
            scale_row(i, inv);
            a.scale_row(i, inv);

            for(int j = i + 1; j < m_r; ++j)
               {
               auto leading = get(j, i);
               addmul_row(i, j, leading);
               a.addmul_row(i, j, leading);
               }
            }

         for(int i = m_r - 1; i > 0; --i)
            {
            for(int j = i - 1; j >= 0; --j)
               {
               auto trailing = get(j, i);
               addmul_row(i, j, trailing);
               a.addmul_row(i, j, trailing);
               }
            }
         }

      // in-place standardize.
      void standardize()
         {
         for(int i = 0; i < m_r; ++i)
            {
            int p_row = i;
            auto p_val = get(i, i);
            for(int j = i + 1; j < m_r && p_val == 0; ++j)
               {
               p_row = j;
               p_val = get(j, i);
               }
            if(p_val == 0)
               {
               continue;
               }

            if(p_row != i)
               {
               swap_row(i, p_row);
               }

            auto inv = gf_inv(p_val);
            scale_row(i, inv);

            for(int j = i + 1; j < m_r; ++j)
               {
               auto leading = get(j, i);
               addmul_row(i, j, leading);
               }
            }

         for(int i = m_r - 1; i > 0; --i)
            {
            for(int j = i - 1; j >= 0; --j)
               {
               auto trailing = get(j, i);
               addmul_row(i, j, trailing);
               }
            }
         }

      // parity() returns the new matrix because it changes dimensions.
      // It can be done in place, but is easier to implement with a copy.
      GFMat parity() const
         {
         // we assume *this is in standard form already.
         // it is of form [I_r | P]
         // our output will be [-P_transpose | I_(c - r)]
         // but our field is of characteristic 2 so we do not need the negative.

         // In terms of *this:
         // I_r has r rows and r columns.
         // P has r rows and c-r columns.
         // P_transpose has c-r rows, and r columns.
         // I_(c-r) has c-r rows and c-r columns.
         // so: out.r == c-r, out.c == r + c - r == c

         GFMat out(m_c-m_r, m_c);

         // step 1. fill in the identity. it starts at column offset r.
         for(int i = 0; i < m_c-m_r; i++)
            {
            out.set(i, i+m_r, 1);
            }

         // step 2: fill in the transposed P matrix. i and j are in terms of out.
         for(int i = 0; i < m_c-m_r; i++)
            {
            for(int j = 0; j < m_r; j++)
               {
               out.set(i, j, get(j, i+m_r));
               }
            }

         return out;
         }

      int get_r() const
         {
         return m_r;
         }

      int get_c() const
         {
         return m_c;
         }

   private:
      std::vector<uint8_t> m_d;
      int m_r;
      int m_c;
   };

namespace {

GFMat syndrome_matrix(
   int k, int n,
   const std::vector<uint8_t>& vand_matrix,
   const std::vector<size_t>& share_nums)
   {
   // get a list of keepers
   std::vector<bool> keepers(n);
   int share_count = 0;
   for(auto share_num : share_nums)
      {
      if(!keepers[share_num])
         {
         keepers[share_num] = true;
         ++share_count;
         }
      }

   // create a vandermonde matrix but skip columns where we're missing
   // the share.
   GFMat out(k, share_count);
   for(int i = 0; i < k; ++i)
      {
      int skipped = 0;
      for(int j = 0; j < n; ++j)
         {
         if(!keepers[j])
            {
            ++skipped;
            continue;
            }
         out.set(i, j-skipped, vand_matrix[i*n+j]);
         }
      }

   // standardize the output and convert into parity form
   out.standardize();
   return out.parity();
   }

const uint8_t interp_base = 2;

uint8_t eval_point(int num)
   {
   if(num == 0)
      {
      return 0;
      }
   return gf_pow(interp_base, num - 1);
   }

}

/*
* addmul() computes z[] = z[] + x[] * y
*/
void ZFEC::addmul(uint8_t z[], const uint8_t x[], uint8_t y, size_t size)
   {
   if(y == 0)
      return;

   const uint8_t* GF_MUL_Y = GF_MUL_TABLE(y);

   // first align z to 16 bytes
   while(size > 0 && reinterpret_cast<uintptr_t>(z) % 16)
      {
      z[0] ^= GF_MUL_Y[x[0]];
      ++z;
      ++x;
      size--;
      }

#if defined(BOTAN_HAS_ZFEC_VPERM)
   if(size >= 16 && CPUID::has_vperm())
      {
      const size_t consumed = addmul_vperm(z, x, y, size);
      z += consumed;
      x += consumed;
      size -= consumed;
      }
#endif

#if defined(BOTAN_HAS_ZFEC_SSE2)
   if(size >= 64 && CPUID::has_sse2())
      {
      const size_t consumed = addmul_sse2(z, x, y, size);
      z += consumed;
      x += consumed;
      size -= consumed;
      }
#endif

   while(size >= 16)
      {
      z[0] ^= GF_MUL_Y[x[0]];
      z[1] ^= GF_MUL_Y[x[1]];
      z[2] ^= GF_MUL_Y[x[2]];
      z[3] ^= GF_MUL_Y[x[3]];
      z[4] ^= GF_MUL_Y[x[4]];
      z[5] ^= GF_MUL_Y[x[5]];
      z[6] ^= GF_MUL_Y[x[6]];
      z[7] ^= GF_MUL_Y[x[7]];
      z[8] ^= GF_MUL_Y[x[8]];
      z[9] ^= GF_MUL_Y[x[9]];
      z[10] ^= GF_MUL_Y[x[10]];
      z[11] ^= GF_MUL_Y[x[11]];
      z[12] ^= GF_MUL_Y[x[12]];
      z[13] ^= GF_MUL_Y[x[13]];
      z[14] ^= GF_MUL_Y[x[14]];
      z[15] ^= GF_MUL_Y[x[15]];

      x += 16;
      z += 16;
      size -= 16;
      }

   // Clean up the trailing pieces
   for(size_t i = 0; i != size; ++i)
      z[i] ^= GF_MUL_Y[x[i]];
   }

/*
* This section contains the proper FEC encoding/decoding routines.
* The encoding matrix is computed starting with a Vandermonde matrix,
* and then transforming it into a systematic matrix.
*/

/*
* ZFEC constructor
*/
ZFEC::ZFEC(size_t K, size_t N) :
   m_K(K), m_N(N), m_enc_matrix(N * K), m_vand_matrix(K * N)
   {
   if(m_K == 0 || m_N == 0 || m_K > 256 || m_N > 256 || m_K > N)
      throw Invalid_Argument("ZFEC: violated 1 <= K <= N <= 256");

   std::vector<uint8_t> temp_matrix(m_N * m_K);

   /*
   * quick code to build systematic matrix: invert the top
   * K*K Vandermonde matrix, multiply right the bottom n-K rows
   * by the inverse, and construct the identity matrix at the top.
   */
   create_inverted_vdm(&temp_matrix[0], m_K);

   for(size_t i = m_K*m_K; i != temp_matrix.size(); ++i)
      temp_matrix[i] = GF_EXP[((i / m_K) * (i % m_K)) % 255];

   /*
   * the upper part of the encoding matrix is I
   */
   for(size_t i = 0; i != m_K; ++i)
      m_enc_matrix[i*(m_K+1)] = 1;

   /*
   * computes C = AB where A is n*K, B is K*m, C is n*m
   */
   for(size_t row = m_K; row != m_N; ++row)
      {
      for(size_t col = 0; col != m_K; ++col)
         {
         uint8_t acc = 0;
         for(size_t i = 0; i != m_K; i++)
            {
            const uint8_t row_v = temp_matrix[row * m_K + i];
            const uint8_t row_c = temp_matrix[col + m_K * i];
            acc ^= GF_MUL_TABLE(row_v)[row_c];
            }
         m_enc_matrix[row * m_K + col] = acc;
         }
      }

   /*
   * compute another Vandermonde matrix (N*K), for use with
   * Berlekamp-Welch error correction.
   */
   m_vand_matrix[0] = 1;
   uint8_t g = 1;
   for(size_t row = 0; row < m_K; ++row)
      {
      uint8_t a = 1;
      for(size_t col = 1; col < m_N; ++col)
         {
         m_vand_matrix[row * m_N + col] = a;
         a = GF_MUL_TABLE(g)[a];
         }
      g = GF_MUL_TABLE(2)[g];
      }
   }

/*
* ZFEC encoding routine
*/
void ZFEC::encode(
   const uint8_t input[], size_t size,
   const output_cb_t& output_cb)
   const
   {
   if(size % m_K != 0)
      throw Invalid_Argument("ZFEC::encode: input must be multiple of K uint8_ts");

   const size_t share_size = size / m_K;

   std::vector<const uint8_t*> shares;
   for(size_t i = 0; i != m_K; ++i)
      shares.push_back(input + i*share_size);

   this->encode_shares(shares, share_size, output_cb);
   }

void ZFEC::encode_shares(
   const std::vector<const uint8_t*>& shares,
   size_t share_size,
   const output_cb_t& output_cb)
   const
   {
   if(shares.size() != m_K)
      throw Invalid_Argument("ZFEC::encode_shares must provide K shares");

   // The initial shares are just the original input shares
   for(size_t i = 0; i != m_K; ++i)
      output_cb(i, shares[i], share_size);

   std::vector<uint8_t> fec_buf(share_size);

   for(size_t i = m_K; i != m_N; ++i)
      {
      clear_mem(fec_buf.data(), fec_buf.size());

      for(size_t j = 0; j != m_K; ++j)
         {
         addmul(&fec_buf[0], shares[j],
                m_enc_matrix[i*m_K+j], share_size);
         }

      output_cb(i, &fec_buf[0], fec_buf.size());
      }
   }

/*
* ZFEC decoding routine
*/
void ZFEC::decode_shares(
   const std::map<size_t, const uint8_t*>& shares,
   size_t share_size,
   const output_cb_t& output_cb) const
   {
   /*
   Todo:
   If shares.size() < K:
   signal decoding error for missing shares < K
   emit existing shares < K
   (ie, partial recovery if possible)
   Assert share_size % K == 0
   */

   if(shares.size() < m_K)
      throw Decoding_Error("ZFEC: could not decode, less than K surviving shares");

   std::vector<uint8_t> decoding_matrix(m_K * m_K);
   std::vector<size_t> indexes(m_K);
   std::vector<const uint8_t*> sharesv(m_K);

   auto shares_b_iter = shares.begin();
   auto shares_e_iter = shares.rbegin();

   bool missing_primary_share = false;

   for(size_t i = 0; i != m_K; ++i)
      {
      size_t share_id = 0;
      const uint8_t* share_data = nullptr;

      if(shares_b_iter->first == i)
         {
         share_id = shares_b_iter->first;
         share_data = shares_b_iter->second;
         ++shares_b_iter;
         }
      else
         {
         // if share i not found, use the unused one closest to n
         share_id = shares_e_iter->first;
         share_data = shares_e_iter->second;
         ++shares_e_iter;
         missing_primary_share = true;
         }

      if(share_id >= m_N)
         throw Decoding_Error("ZFEC: invalid share id detected during decode");

      /*
      This is a systematic code (encoding matrix includes K*K identity
      matrix), so shares less than K are copies of the input data,
      can output_cb directly. Also we know the encoding matrix in those rows
      contains I, so we can set the single bit directly without copying
      the entire row
      */
      if(share_id < m_K)
         {
         decoding_matrix[i*(m_K+1)] = 1;
         output_cb(share_id, share_data, share_size);
         }
      else // will decode after inverting matrix
         {
         std::memcpy(&decoding_matrix[i*m_K], &m_enc_matrix[share_id*m_K], m_K);
         }

      sharesv[i] = share_data;
      indexes[i] = share_id;
      }

   // If we had the original data shares then no need to perform
   // a matrix inversion, return immediately.
   if(!missing_primary_share)
      {
      for(size_t i = 0; i != indexes.size(); ++i)
         {
         BOTAN_ASSERT_NOMSG(indexes[i] < m_K);
         }
      return;
      }

   invert_matrix(&decoding_matrix[0], m_K);

   for(size_t i = 0; i != indexes.size(); ++i)
      {
      if(indexes[i] >= m_K)
         {
         std::vector<uint8_t> buf(share_size);
         for(size_t col = 0; col != m_K; ++col)
            {
            addmul(&buf[0], sharesv[col], decoding_matrix[i*m_K + col], share_size);
            }
         output_cb(i, &buf[0], share_size);
         }
      }
   }

std::string ZFEC::provider() const
   {
#if defined(BOTAN_HAS_ZFEC_VPERM)
   if(CPUID::has_vperm())
      {
      return "vperm";
      }
#endif

#if defined(BOTAN_HAS_ZFEC_SSE2)
   if(CPUID::has_sse2())
      {
      return "sse2";
      }
#endif

   return "base";
   }

std::vector<uint8_t> ZFEC::berlekamp_welch(
   const std::vector<uint8_t*>& shares,
   const std::vector<size_t>& share_numbers,
   int index) const
   {
   auto r = static_cast<int>(shares.size()); // required + redundancy size
   auto e = (r - static_cast<int>(m_K)) / 2; // degree of E polynomial
   auto q = e + static_cast<int>(m_K);       // degree of Q polynomial

   if(e <= 0)
      {
      throw Decoding_Error("ZFEC: could not correct, need more than K surviving shares");
      }

   int dim = q + e;

   // build the system of equations s * u = f
   GFMat s(dim, dim);           // constraint matrix
   GFMat a(dim, dim);           // augmented matrix
   std::vector<uint8_t> f(dim); // constant column vector
   std::vector<uint8_t> u(dim); // solution vector

   for(int i = 0; i < dim; ++i)
      {
      auto x_i = eval_point(static_cast<int>(share_numbers[i]));
      auto r_i = shares[i][index];
      f[i] = gf_mul(gf_pow(x_i, e), r_i);

      for(int j = 0; j < q; ++j)
         {
         s.set(i, j, gf_pow(x_i, j));
         if(i == j)
            {
            a.set(i, j, 1);
            }
         }

      for(int k = 0; k < e; ++k)
         {
         auto j = k + q;
         s.set(i, j, gf_mul(gf_pow(x_i, k), r_i));
         if(i == j)
            {
            a.set(i, j, 1);
            }
         }
      }

   // invert and put the result in a
   s.invert_with(a);

   // multiply the inverted matrix by the column vector
   for(int i = 0; i < dim; ++i)
      {
      auto ri = a.index_row(i);
      u[i] = gf_dot(ri, f.data(), dim);
      }

   // reverse u for easier construction of the polynomials
   std::reverse(u.begin(), u.end());

   GFPoly q_poly(u);
   q_poly.shift(e);
   GFPoly e_poly(e+1);
   e_poly[0] = 1;
   std::copy(u.begin(), u.begin() + e, &e_poly[1]);

   auto [p_poly, rem] = q_poly.div(e_poly);
   if(!rem.is_zero())
      {
      throw Decoding_Error("ZFEC: could not correct; too many errors encountered");
      }

   std::vector<uint8_t> out(m_N);
   for(size_t i = 0; i < m_N; ++i)
      {
      uint8_t pt = 0;
      if(i != 0)
         {
         pt = gf_pow(interp_base, i - 1);
         }
      out[i] = p_poly.eval(pt);
      }

   return out;
   }

std::map<size_t, const uint8_t*> ZFEC::correct(
   const std::map<size_t, uint8_t*>& shares,
   size_t share_size) const
   {
   if(shares.size() < m_K)
      {
      throw Decoding_Error("ZFEC: could not correct, less than K surviving shares");
      }

   std::vector<uint8_t*> shares_vec;
   std::vector<size_t> shares_nums;
   shares_vec.reserve(shares.size());
   shares_nums.reserve(shares.size());
   std::map<size_t, const uint8_t*> result;
   for(auto [num, data] : shares)
      {
      shares_vec.push_back(data);
      shares_nums.push_back(num);
      result[num] = data;
      }

   // fast path: check to see if there are no errors by evaluating it with
   // the syndrome matrix.
   auto synd = syndrome_matrix(static_cast<int>(m_K), static_cast<int>(m_N), m_vand_matrix, shares_nums);
   std::vector<uint8_t> buf(share_size);

   for(int i = 0; i < synd.get_r(); ++i)
      {
      std::fill(buf.begin(), buf.end(), 0);
      for(int j = 0; j < synd.get_c(); ++j)
         {
         addmul(&buf[0], shares_vec[j],
                synd.get(i, j), share_size);
         }

      for(int j = 0; j < static_cast<int>(buf.size()); ++j)
         {
         if(buf[j] == 0)
            {
            continue;
            }
         auto data = berlekamp_welch(shares_vec, shares_nums, j);
         for(auto [share_num, share] : shares)
            {
            share[j] = data[share_num];
            }
         }
      }

   // Return a map that the caller can use when calling decode_shares() after
   // this. We could *probably* get away with returning
   // reinterpret_cast<std::map<size_t, const uint8_t*>*>(&shares), but this
   // separately-constructed map is probably worth the runtime cost for the
   // sake of more correct code.
   return result;
   }

void ZFEC::decode_corrected(
   const std::map<size_t, uint8_t*>& shares,
   size_t share_size,
   const output_cb_t& output_cb) const
   {
   auto consted_map = correct(shares, share_size);
   decode_shares(consted_map, share_size, output_cb);
   }

}
