/*
* SM3
* (C) 2017 Ribose Inc.
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/sm3.h>

namespace Botan {

std::unique_ptr<HashFunction> SM3::copy_state() const
   {
   return std::unique_ptr<HashFunction>(new SM3(*this));
   }

namespace {

const uint32_t SM3_IV[] = {
   0x7380166fUL, 0x4914b2b9UL, 0x172442d7UL, 0xda8a0600UL,
   0xa96f30bcUL, 0x163138aaUL, 0xe38dee4dUL, 0xb0fb0e4eUL
};

inline uint32_t P0(uint32_t X)
   {
   return X ^ rotl<9>(X) ^ rotl<17>(X);
   }

inline uint32_t P1(uint32_t X)
   {
   return X ^ rotl<15>(X) ^ rotl<23>(X);
   }

inline uint32_t FF1(uint32_t X, uint32_t Y, uint32_t Z)
   {
   return (X & Y) | ((X | Y) & Z);
   //return (X & Y) | (X & Z) | (Y & Z);
   }

inline uint32_t GG1(uint32_t X, uint32_t Y, uint32_t Z)
   {
   //return (X & Y) | (~X & Z);
   return ((Z ^ (X & (Y ^ Z))));
   }

inline void R1(uint32_t A, uint32_t& B, uint32_t C, uint32_t& D,
               uint32_t E, uint32_t& F, uint32_t G, uint32_t& H,
               uint32_t TJ, uint32_t Wi, uint32_t Wj)
   {
   const uint32_t A12 = rotl<12>(A);
   const uint32_t SS1 = rotl<7>(A12 + E + TJ);
   const uint32_t TT1 = (A ^ B ^ C) + D + (SS1 ^ A12) + Wj;
   const uint32_t TT2 = (E ^ F ^ G) + H + SS1 + Wi;

   B = rotl<9>(B);
   D = TT1;
   F = rotl<19>(F);
   H = P0(TT2);
   }

inline void R2(uint32_t A, uint32_t& B, uint32_t C, uint32_t& D,
               uint32_t E, uint32_t& F, uint32_t G, uint32_t& H,
               uint32_t TJ, uint32_t Wi, uint32_t Wj)
   {
   const uint32_t A12 = rotl<12>(A);
   const uint32_t SS1 = rotl<7>(A12 + E + TJ);
   const uint32_t TT1 = FF1(A, B, C) + D + (SS1 ^ A12) + Wj;
   const uint32_t TT2 = GG1(E, F, G) + H + SS1 + Wi;

   B = rotl<9>(B);
   D = TT1;
   F = rotl<19>(F);
   H = P0(TT2);
   }

}

/*
* SM3 Compression Function
*/
void SM3::compress_n(const uint8_t input[], size_t blocks)
   {
   uint32_t A = m_digest[0], B = m_digest[1], C = m_digest[2], D = m_digest[3],
            E = m_digest[4], F = m_digest[5], G = m_digest[6], H = m_digest[7];
   uint32_t W[68];

   for(size_t i = 0; i != blocks; ++i)
      {
      // Message Extension (a)
      W[ 0] = load_be<uint32_t>(input, 0);
      W[ 1] = load_be<uint32_t>(input, 1);
      W[ 2] = load_be<uint32_t>(input, 2);
      W[ 3] = load_be<uint32_t>(input, 3);
      W[ 4] = load_be<uint32_t>(input, 4);
      W[ 5] = load_be<uint32_t>(input, 5);
      W[ 6] = load_be<uint32_t>(input, 6);
      W[ 7] = load_be<uint32_t>(input, 7);
      W[ 8] = load_be<uint32_t>(input, 8);
      W[ 9] = load_be<uint32_t>(input, 9);
      W[10] = load_be<uint32_t>(input, 10);
      W[11] = load_be<uint32_t>(input, 11);
      W[12] = load_be<uint32_t>(input, 12);
      W[13] = load_be<uint32_t>(input, 13);
      W[14] = load_be<uint32_t>(input, 14);
      W[15] = load_be<uint32_t>(input, 15);

      // Message Extension (b)
      W[16] = P1(W[ 0] ^ W[ 7] ^ rotl<15>(W[13])) ^ rotl<7>(W[ 3]) ^ W[10];
      W[17] = P1(W[ 1] ^ W[ 8] ^ rotl<15>(W[14])) ^ rotl<7>(W[ 4]) ^ W[11];
      W[18] = P1(W[ 2] ^ W[ 9] ^ rotl<15>(W[15])) ^ rotl<7>(W[ 5]) ^ W[12];
      W[19] = P1(W[ 3] ^ W[10] ^ rotl<15>(W[16])) ^ rotl<7>(W[ 6]) ^ W[13];
      W[20] = P1(W[ 4] ^ W[11] ^ rotl<15>(W[17])) ^ rotl<7>(W[ 7]) ^ W[14];
      W[21] = P1(W[ 5] ^ W[12] ^ rotl<15>(W[18])) ^ rotl<7>(W[ 8]) ^ W[15];
      W[22] = P1(W[ 6] ^ W[13] ^ rotl<15>(W[19])) ^ rotl<7>(W[ 9]) ^ W[16];
      W[23] = P1(W[ 7] ^ W[14] ^ rotl<15>(W[20])) ^ rotl<7>(W[10]) ^ W[17];
      W[24] = P1(W[ 8] ^ W[15] ^ rotl<15>(W[21])) ^ rotl<7>(W[11]) ^ W[18];
      W[25] = P1(W[ 9] ^ W[16] ^ rotl<15>(W[22])) ^ rotl<7>(W[12]) ^ W[19];
      W[26] = P1(W[10] ^ W[17] ^ rotl<15>(W[23])) ^ rotl<7>(W[13]) ^ W[20];
      W[27] = P1(W[11] ^ W[18] ^ rotl<15>(W[24])) ^ rotl<7>(W[14]) ^ W[21];
      W[28] = P1(W[12] ^ W[19] ^ rotl<15>(W[25])) ^ rotl<7>(W[15]) ^ W[22];
      W[29] = P1(W[13] ^ W[20] ^ rotl<15>(W[26])) ^ rotl<7>(W[16]) ^ W[23];
      W[30] = P1(W[14] ^ W[21] ^ rotl<15>(W[27])) ^ rotl<7>(W[17]) ^ W[24];
      W[31] = P1(W[15] ^ W[22] ^ rotl<15>(W[28])) ^ rotl<7>(W[18]) ^ W[25];
      W[32] = P1(W[16] ^ W[23] ^ rotl<15>(W[29])) ^ rotl<7>(W[19]) ^ W[26];
      W[33] = P1(W[17] ^ W[24] ^ rotl<15>(W[30])) ^ rotl<7>(W[20]) ^ W[27];
      W[34] = P1(W[18] ^ W[25] ^ rotl<15>(W[31])) ^ rotl<7>(W[21]) ^ W[28];
      W[35] = P1(W[19] ^ W[26] ^ rotl<15>(W[32])) ^ rotl<7>(W[22]) ^ W[29];
      W[36] = P1(W[20] ^ W[27] ^ rotl<15>(W[33])) ^ rotl<7>(W[23]) ^ W[30];
      W[37] = P1(W[21] ^ W[28] ^ rotl<15>(W[34])) ^ rotl<7>(W[24]) ^ W[31];
      W[38] = P1(W[22] ^ W[29] ^ rotl<15>(W[35])) ^ rotl<7>(W[25]) ^ W[32];
      W[39] = P1(W[23] ^ W[30] ^ rotl<15>(W[36])) ^ rotl<7>(W[26]) ^ W[33];
      W[40] = P1(W[24] ^ W[31] ^ rotl<15>(W[37])) ^ rotl<7>(W[27]) ^ W[34];
      W[41] = P1(W[25] ^ W[32] ^ rotl<15>(W[38])) ^ rotl<7>(W[28]) ^ W[35];
      W[42] = P1(W[26] ^ W[33] ^ rotl<15>(W[39])) ^ rotl<7>(W[29]) ^ W[36];
      W[43] = P1(W[27] ^ W[34] ^ rotl<15>(W[40])) ^ rotl<7>(W[30]) ^ W[37];
      W[44] = P1(W[28] ^ W[35] ^ rotl<15>(W[41])) ^ rotl<7>(W[31]) ^ W[38];
      W[45] = P1(W[29] ^ W[36] ^ rotl<15>(W[42])) ^ rotl<7>(W[32]) ^ W[39];
      W[46] = P1(W[30] ^ W[37] ^ rotl<15>(W[43])) ^ rotl<7>(W[33]) ^ W[40];
      W[47] = P1(W[31] ^ W[38] ^ rotl<15>(W[44])) ^ rotl<7>(W[34]) ^ W[41];
      W[48] = P1(W[32] ^ W[39] ^ rotl<15>(W[45])) ^ rotl<7>(W[35]) ^ W[42];
      W[49] = P1(W[33] ^ W[40] ^ rotl<15>(W[46])) ^ rotl<7>(W[36]) ^ W[43];
      W[50] = P1(W[34] ^ W[41] ^ rotl<15>(W[47])) ^ rotl<7>(W[37]) ^ W[44];
      W[51] = P1(W[35] ^ W[42] ^ rotl<15>(W[48])) ^ rotl<7>(W[38]) ^ W[45];
      W[52] = P1(W[36] ^ W[43] ^ rotl<15>(W[49])) ^ rotl<7>(W[39]) ^ W[46];
      W[53] = P1(W[37] ^ W[44] ^ rotl<15>(W[50])) ^ rotl<7>(W[40]) ^ W[47];
      W[54] = P1(W[38] ^ W[45] ^ rotl<15>(W[51])) ^ rotl<7>(W[41]) ^ W[48];
      W[55] = P1(W[39] ^ W[46] ^ rotl<15>(W[52])) ^ rotl<7>(W[42]) ^ W[49];
      W[56] = P1(W[40] ^ W[47] ^ rotl<15>(W[53])) ^ rotl<7>(W[43]) ^ W[50];
      W[57] = P1(W[41] ^ W[48] ^ rotl<15>(W[54])) ^ rotl<7>(W[44]) ^ W[51];
      W[58] = P1(W[42] ^ W[49] ^ rotl<15>(W[55])) ^ rotl<7>(W[45]) ^ W[52];
      W[59] = P1(W[43] ^ W[50] ^ rotl<15>(W[56])) ^ rotl<7>(W[46]) ^ W[53];
      W[60] = P1(W[44] ^ W[51] ^ rotl<15>(W[57])) ^ rotl<7>(W[47]) ^ W[54];
      W[61] = P1(W[45] ^ W[52] ^ rotl<15>(W[58])) ^ rotl<7>(W[48]) ^ W[55];
      W[62] = P1(W[46] ^ W[53] ^ rotl<15>(W[59])) ^ rotl<7>(W[49]) ^ W[56];
      W[63] = P1(W[47] ^ W[54] ^ rotl<15>(W[60])) ^ rotl<7>(W[50]) ^ W[57];
      W[64] = P1(W[48] ^ W[55] ^ rotl<15>(W[61])) ^ rotl<7>(W[51]) ^ W[58];
      W[65] = P1(W[49] ^ W[56] ^ rotl<15>(W[62])) ^ rotl<7>(W[52]) ^ W[59];
      W[66] = P1(W[50] ^ W[57] ^ rotl<15>(W[63])) ^ rotl<7>(W[53]) ^ W[60];
      W[67] = P1(W[51] ^ W[58] ^ rotl<15>(W[64])) ^ rotl<7>(W[54]) ^ W[61];

      R1(A, B, C, D, E, F, G, H, 0x79CC4519, W[ 0], W[ 0] ^ W[ 4]);
      R1(D, A, B, C, H, E, F, G, 0xF3988A32, W[ 1], W[ 1] ^ W[ 5]);
      R1(C, D, A, B, G, H, E, F, 0xE7311465, W[ 2], W[ 2] ^ W[ 6]);
      R1(B, C, D, A, F, G, H, E, 0xCE6228CB, W[ 3], W[ 3] ^ W[ 7]);
      R1(A, B, C, D, E, F, G, H, 0x9CC45197, W[ 4], W[ 4] ^ W[ 8]);
      R1(D, A, B, C, H, E, F, G, 0x3988A32F, W[ 5], W[ 5] ^ W[ 9]);
      R1(C, D, A, B, G, H, E, F, 0x7311465E, W[ 6], W[ 6] ^ W[10]);
      R1(B, C, D, A, F, G, H, E, 0xE6228CBC, W[ 7], W[ 7] ^ W[11]);
      R1(A, B, C, D, E, F, G, H, 0xCC451979, W[ 8], W[ 8] ^ W[12]);
      R1(D, A, B, C, H, E, F, G, 0x988A32F3, W[ 9], W[ 9] ^ W[13]);
      R1(C, D, A, B, G, H, E, F, 0x311465E7, W[10], W[10] ^ W[14]);
      R1(B, C, D, A, F, G, H, E, 0x6228CBCE, W[11], W[11] ^ W[15]);
      R1(A, B, C, D, E, F, G, H, 0xC451979C, W[12], W[12] ^ W[16]);
      R1(D, A, B, C, H, E, F, G, 0x88A32F39, W[13], W[13] ^ W[17]);
      R1(C, D, A, B, G, H, E, F, 0x11465E73, W[14], W[14] ^ W[18]);
      R1(B, C, D, A, F, G, H, E, 0x228CBCE6, W[15], W[15] ^ W[19]);
      R2(A, B, C, D, E, F, G, H, 0x9D8A7A87, W[16], W[16] ^ W[20]);
      R2(D, A, B, C, H, E, F, G, 0x3B14F50F, W[17], W[17] ^ W[21]);
      R2(C, D, A, B, G, H, E, F, 0x7629EA1E, W[18], W[18] ^ W[22]);
      R2(B, C, D, A, F, G, H, E, 0xEC53D43C, W[19], W[19] ^ W[23]);
      R2(A, B, C, D, E, F, G, H, 0xD8A7A879, W[20], W[20] ^ W[24]);
      R2(D, A, B, C, H, E, F, G, 0xB14F50F3, W[21], W[21] ^ W[25]);
      R2(C, D, A, B, G, H, E, F, 0x629EA1E7, W[22], W[22] ^ W[26]);
      R2(B, C, D, A, F, G, H, E, 0xC53D43CE, W[23], W[23] ^ W[27]);
      R2(A, B, C, D, E, F, G, H, 0x8A7A879D, W[24], W[24] ^ W[28]);
      R2(D, A, B, C, H, E, F, G, 0x14F50F3B, W[25], W[25] ^ W[29]);
      R2(C, D, A, B, G, H, E, F, 0x29EA1E76, W[26], W[26] ^ W[30]);
      R2(B, C, D, A, F, G, H, E, 0x53D43CEC, W[27], W[27] ^ W[31]);
      R2(A, B, C, D, E, F, G, H, 0xA7A879D8, W[28], W[28] ^ W[32]);
      R2(D, A, B, C, H, E, F, G, 0x4F50F3B1, W[29], W[29] ^ W[33]);
      R2(C, D, A, B, G, H, E, F, 0x9EA1E762, W[30], W[30] ^ W[34]);
      R2(B, C, D, A, F, G, H, E, 0x3D43CEC5, W[31], W[31] ^ W[35]);
      R2(A, B, C, D, E, F, G, H, 0x7A879D8A, W[32], W[32] ^ W[36]);
      R2(D, A, B, C, H, E, F, G, 0xF50F3B14, W[33], W[33] ^ W[37]);
      R2(C, D, A, B, G, H, E, F, 0xEA1E7629, W[34], W[34] ^ W[38]);
      R2(B, C, D, A, F, G, H, E, 0xD43CEC53, W[35], W[35] ^ W[39]);
      R2(A, B, C, D, E, F, G, H, 0xA879D8A7, W[36], W[36] ^ W[40]);
      R2(D, A, B, C, H, E, F, G, 0x50F3B14F, W[37], W[37] ^ W[41]);
      R2(C, D, A, B, G, H, E, F, 0xA1E7629E, W[38], W[38] ^ W[42]);
      R2(B, C, D, A, F, G, H, E, 0x43CEC53D, W[39], W[39] ^ W[43]);
      R2(A, B, C, D, E, F, G, H, 0x879D8A7A, W[40], W[40] ^ W[44]);
      R2(D, A, B, C, H, E, F, G, 0x0F3B14F5, W[41], W[41] ^ W[45]);
      R2(C, D, A, B, G, H, E, F, 0x1E7629EA, W[42], W[42] ^ W[46]);
      R2(B, C, D, A, F, G, H, E, 0x3CEC53D4, W[43], W[43] ^ W[47]);
      R2(A, B, C, D, E, F, G, H, 0x79D8A7A8, W[44], W[44] ^ W[48]);
      R2(D, A, B, C, H, E, F, G, 0xF3B14F50, W[45], W[45] ^ W[49]);
      R2(C, D, A, B, G, H, E, F, 0xE7629EA1, W[46], W[46] ^ W[50]);
      R2(B, C, D, A, F, G, H, E, 0xCEC53D43, W[47], W[47] ^ W[51]);
      R2(A, B, C, D, E, F, G, H, 0x9D8A7A87, W[48], W[48] ^ W[52]);
      R2(D, A, B, C, H, E, F, G, 0x3B14F50F, W[49], W[49] ^ W[53]);
      R2(C, D, A, B, G, H, E, F, 0x7629EA1E, W[50], W[50] ^ W[54]);
      R2(B, C, D, A, F, G, H, E, 0xEC53D43C, W[51], W[51] ^ W[55]);
      R2(A, B, C, D, E, F, G, H, 0xD8A7A879, W[52], W[52] ^ W[56]);
      R2(D, A, B, C, H, E, F, G, 0xB14F50F3, W[53], W[53] ^ W[57]);
      R2(C, D, A, B, G, H, E, F, 0x629EA1E7, W[54], W[54] ^ W[58]);
      R2(B, C, D, A, F, G, H, E, 0xC53D43CE, W[55], W[55] ^ W[59]);
      R2(A, B, C, D, E, F, G, H, 0x8A7A879D, W[56], W[56] ^ W[60]);
      R2(D, A, B, C, H, E, F, G, 0x14F50F3B, W[57], W[57] ^ W[61]);
      R2(C, D, A, B, G, H, E, F, 0x29EA1E76, W[58], W[58] ^ W[62]);
      R2(B, C, D, A, F, G, H, E, 0x53D43CEC, W[59], W[59] ^ W[63]);
      R2(A, B, C, D, E, F, G, H, 0xA7A879D8, W[60], W[60] ^ W[64]);
      R2(D, A, B, C, H, E, F, G, 0x4F50F3B1, W[61], W[61] ^ W[65]);
      R2(C, D, A, B, G, H, E, F, 0x9EA1E762, W[62], W[62] ^ W[66]);
      R2(B, C, D, A, F, G, H, E, 0x3D43CEC5, W[63], W[63] ^ W[67]);

      A = (m_digest[0] ^= A);
      B = (m_digest[1] ^= B);
      C = (m_digest[2] ^= C);
      D = (m_digest[3] ^= D);
      E = (m_digest[4] ^= E);
      F = (m_digest[5] ^= F);
      G = (m_digest[6] ^= G);
      H = (m_digest[7] ^= H);

      input += hash_block_size();
      }
   }

/*
* Copy out the digest
*/
void SM3::copy_out(uint8_t output[])
   {
   copy_out_vec_be(output, output_length(), m_digest);
   }

/*
* Clear memory of sensitive data
*/
void SM3::clear()
   {
   MDx_HashFunction::clear();
   std::copy(std::begin(SM3_IV), std::end(SM3_IV), m_digest.begin());
   }

}
