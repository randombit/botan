/*
* SM3
* (C) 2017 Ribose Inc.
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/sm3.h>
#include <botan/loadstor.h>
#include <botan/rotate.h>

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

inline uint32_t P1(uint32_t X)
   {
   return X ^ rotl<15>(X) ^ rotl<23>(X);
   }

inline uint32_t SM3_E(uint32_t W0, uint32_t W7, uint32_t W13, uint32_t W3, uint32_t W10)
   {
   return P1(W0 ^ W7 ^ rotl<15>(W13)) ^ rotl<7>(W3) ^ W10;
   }

}

/*
* SM3 Compression Function
*/
void SM3::compress_n(const uint8_t input[], size_t blocks)
   {
   uint32_t A = m_digest[0], B = m_digest[1], C = m_digest[2], D = m_digest[3],
            E = m_digest[4], F = m_digest[5], G = m_digest[6], H = m_digest[7];

   for(size_t i = 0; i != blocks; ++i)
      {
      uint32_t W00 = load_be<uint32_t>(input, 0);
      uint32_t W01 = load_be<uint32_t>(input, 1);
      uint32_t W02 = load_be<uint32_t>(input, 2);
      uint32_t W03 = load_be<uint32_t>(input, 3);
      uint32_t W04 = load_be<uint32_t>(input, 4);
      uint32_t W05 = load_be<uint32_t>(input, 5);
      uint32_t W06 = load_be<uint32_t>(input, 6);
      uint32_t W07 = load_be<uint32_t>(input, 7);
      uint32_t W08 = load_be<uint32_t>(input, 8);
      uint32_t W09 = load_be<uint32_t>(input, 9);
      uint32_t W10 = load_be<uint32_t>(input, 10);
      uint32_t W11 = load_be<uint32_t>(input, 11);
      uint32_t W12 = load_be<uint32_t>(input, 12);
      uint32_t W13 = load_be<uint32_t>(input, 13);
      uint32_t W14 = load_be<uint32_t>(input, 14);
      uint32_t W15 = load_be<uint32_t>(input, 15);

      R1(A, B, C, D, E, F, G, H, 0x79CC4519, W00, W00 ^ W04);
      W00 = SM3_E(W00, W07, W13, W03, W10);
      R1(D, A, B, C, H, E, F, G, 0xF3988A32, W01, W01 ^ W05);
      W01 = SM3_E(W01, W08, W14, W04, W11);
      R1(C, D, A, B, G, H, E, F, 0xE7311465, W02, W02 ^ W06);
      W02 = SM3_E(W02, W09, W15, W05, W12);
      R1(B, C, D, A, F, G, H, E, 0xCE6228CB, W03, W03 ^ W07);
      W03 = SM3_E(W03, W10, W00, W06, W13);
      R1(A, B, C, D, E, F, G, H, 0x9CC45197, W04, W04 ^ W08);
      W04 = SM3_E(W04, W11, W01, W07, W14);
      R1(D, A, B, C, H, E, F, G, 0x3988A32F, W05, W05 ^ W09);
      W05 = SM3_E(W05, W12, W02, W08, W15);
      R1(C, D, A, B, G, H, E, F, 0x7311465E, W06, W06 ^ W10);
      W06 = SM3_E(W06, W13, W03, W09, W00);
      R1(B, C, D, A, F, G, H, E, 0xE6228CBC, W07, W07 ^ W11);
      W07 = SM3_E(W07, W14, W04, W10, W01);
      R1(A, B, C, D, E, F, G, H, 0xCC451979, W08, W08 ^ W12);
      W08 = SM3_E(W08, W15, W05, W11, W02);
      R1(D, A, B, C, H, E, F, G, 0x988A32F3, W09, W09 ^ W13);
      W09 = SM3_E(W09, W00, W06, W12, W03);
      R1(C, D, A, B, G, H, E, F, 0x311465E7, W10, W10 ^ W14);
      W10 = SM3_E(W10, W01, W07, W13, W04);
      R1(B, C, D, A, F, G, H, E, 0x6228CBCE, W11, W11 ^ W15);
      W11 = SM3_E(W11, W02, W08, W14, W05);
      R1(A, B, C, D, E, F, G, H, 0xC451979C, W12, W12 ^ W00);
      W12 = SM3_E(W12, W03, W09, W15, W06);
      R1(D, A, B, C, H, E, F, G, 0x88A32F39, W13, W13 ^ W01);
      W13 = SM3_E(W13, W04, W10, W00, W07);
      R1(C, D, A, B, G, H, E, F, 0x11465E73, W14, W14 ^ W02);
      W14 = SM3_E(W14, W05, W11, W01, W08);
      R1(B, C, D, A, F, G, H, E, 0x228CBCE6, W15, W15 ^ W03);
      W15 = SM3_E(W15, W06, W12, W02, W09);
      R2(A, B, C, D, E, F, G, H, 0x9D8A7A87, W00, W00 ^ W04);
      W00 = SM3_E(W00, W07, W13, W03, W10);
      R2(D, A, B, C, H, E, F, G, 0x3B14F50F, W01, W01 ^ W05);
      W01 = SM3_E(W01, W08, W14, W04, W11);
      R2(C, D, A, B, G, H, E, F, 0x7629EA1E, W02, W02 ^ W06);
      W02 = SM3_E(W02, W09, W15, W05, W12);
      R2(B, C, D, A, F, G, H, E, 0xEC53D43C, W03, W03 ^ W07);
      W03 = SM3_E(W03, W10, W00, W06, W13);
      R2(A, B, C, D, E, F, G, H, 0xD8A7A879, W04, W04 ^ W08);
      W04 = SM3_E(W04, W11, W01, W07, W14);
      R2(D, A, B, C, H, E, F, G, 0xB14F50F3, W05, W05 ^ W09);
      W05 = SM3_E(W05, W12, W02, W08, W15);
      R2(C, D, A, B, G, H, E, F, 0x629EA1E7, W06, W06 ^ W10);
      W06 = SM3_E(W06, W13, W03, W09, W00);
      R2(B, C, D, A, F, G, H, E, 0xC53D43CE, W07, W07 ^ W11);
      W07 = SM3_E(W07, W14, W04, W10, W01);
      R2(A, B, C, D, E, F, G, H, 0x8A7A879D, W08, W08 ^ W12);
      W08 = SM3_E(W08, W15, W05, W11, W02);
      R2(D, A, B, C, H, E, F, G, 0x14F50F3B, W09, W09 ^ W13);
      W09 = SM3_E(W09, W00, W06, W12, W03);
      R2(C, D, A, B, G, H, E, F, 0x29EA1E76, W10, W10 ^ W14);
      W10 = SM3_E(W10, W01, W07, W13, W04);
      R2(B, C, D, A, F, G, H, E, 0x53D43CEC, W11, W11 ^ W15);
      W11 = SM3_E(W11, W02, W08, W14, W05);
      R2(A, B, C, D, E, F, G, H, 0xA7A879D8, W12, W12 ^ W00);
      W12 = SM3_E(W12, W03, W09, W15, W06);
      R2(D, A, B, C, H, E, F, G, 0x4F50F3B1, W13, W13 ^ W01);
      W13 = SM3_E(W13, W04, W10, W00, W07);
      R2(C, D, A, B, G, H, E, F, 0x9EA1E762, W14, W14 ^ W02);
      W14 = SM3_E(W14, W05, W11, W01, W08);
      R2(B, C, D, A, F, G, H, E, 0x3D43CEC5, W15, W15 ^ W03);
      W15 = SM3_E(W15, W06, W12, W02, W09);
      R2(A, B, C, D, E, F, G, H, 0x7A879D8A, W00, W00 ^ W04);
      W00 = SM3_E(W00, W07, W13, W03, W10);
      R2(D, A, B, C, H, E, F, G, 0xF50F3B14, W01, W01 ^ W05);
      W01 = SM3_E(W01, W08, W14, W04, W11);
      R2(C, D, A, B, G, H, E, F, 0xEA1E7629, W02, W02 ^ W06);
      W02 = SM3_E(W02, W09, W15, W05, W12);
      R2(B, C, D, A, F, G, H, E, 0xD43CEC53, W03, W03 ^ W07);
      W03 = SM3_E(W03, W10, W00, W06, W13);
      R2(A, B, C, D, E, F, G, H, 0xA879D8A7, W04, W04 ^ W08);
      W04 = SM3_E(W04, W11, W01, W07, W14);
      R2(D, A, B, C, H, E, F, G, 0x50F3B14F, W05, W05 ^ W09);
      W05 = SM3_E(W05, W12, W02, W08, W15);
      R2(C, D, A, B, G, H, E, F, 0xA1E7629E, W06, W06 ^ W10);
      W06 = SM3_E(W06, W13, W03, W09, W00);
      R2(B, C, D, A, F, G, H, E, 0x43CEC53D, W07, W07 ^ W11);
      W07 = SM3_E(W07, W14, W04, W10, W01);
      R2(A, B, C, D, E, F, G, H, 0x879D8A7A, W08, W08 ^ W12);
      W08 = SM3_E(W08, W15, W05, W11, W02);
      R2(D, A, B, C, H, E, F, G, 0x0F3B14F5, W09, W09 ^ W13);
      W09 = SM3_E(W09, W00, W06, W12, W03);
      R2(C, D, A, B, G, H, E, F, 0x1E7629EA, W10, W10 ^ W14);
      W10 = SM3_E(W10, W01, W07, W13, W04);
      R2(B, C, D, A, F, G, H, E, 0x3CEC53D4, W11, W11 ^ W15);
      W11 = SM3_E(W11, W02, W08, W14, W05);
      R2(A, B, C, D, E, F, G, H, 0x79D8A7A8, W12, W12 ^ W00);
      W12 = SM3_E(W12, W03, W09, W15, W06);
      R2(D, A, B, C, H, E, F, G, 0xF3B14F50, W13, W13 ^ W01);
      W13 = SM3_E(W13, W04, W10, W00, W07);
      R2(C, D, A, B, G, H, E, F, 0xE7629EA1, W14, W14 ^ W02);
      W14 = SM3_E(W14, W05, W11, W01, W08);
      R2(B, C, D, A, F, G, H, E, 0xCEC53D43, W15, W15 ^ W03);
      W15 = SM3_E(W15, W06, W12, W02, W09);
      R2(A, B, C, D, E, F, G, H, 0x9D8A7A87, W00, W00 ^ W04);
      W00 = SM3_E(W00, W07, W13, W03, W10);
      R2(D, A, B, C, H, E, F, G, 0x3B14F50F, W01, W01 ^ W05);
      W01 = SM3_E(W01, W08, W14, W04, W11);
      R2(C, D, A, B, G, H, E, F, 0x7629EA1E, W02, W02 ^ W06);
      W02 = SM3_E(W02, W09, W15, W05, W12);
      R2(B, C, D, A, F, G, H, E, 0xEC53D43C, W03, W03 ^ W07);
      W03 = SM3_E(W03, W10, W00, W06, W13);
      R2(A, B, C, D, E, F, G, H, 0xD8A7A879, W04, W04 ^ W08);
      R2(D, A, B, C, H, E, F, G, 0xB14F50F3, W05, W05 ^ W09);
      R2(C, D, A, B, G, H, E, F, 0x629EA1E7, W06, W06 ^ W10);
      R2(B, C, D, A, F, G, H, E, 0xC53D43CE, W07, W07 ^ W11);
      R2(A, B, C, D, E, F, G, H, 0x8A7A879D, W08, W08 ^ W12);
      R2(D, A, B, C, H, E, F, G, 0x14F50F3B, W09, W09 ^ W13);
      R2(C, D, A, B, G, H, E, F, 0x29EA1E76, W10, W10 ^ W14);
      R2(B, C, D, A, F, G, H, E, 0x53D43CEC, W11, W11 ^ W15);
      R2(A, B, C, D, E, F, G, H, 0xA7A879D8, W12, W12 ^ W00);
      R2(D, A, B, C, H, E, F, G, 0x4F50F3B1, W13, W13 ^ W01);
      R2(C, D, A, B, G, H, E, F, 0x9EA1E762, W14, W14 ^ W02);
      R2(B, C, D, A, F, G, H, E, 0x3D43CEC5, W15, W15 ^ W03);

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
