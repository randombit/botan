/*
* SHA-{224,256}
* (C) 1999-2010 Jack Lloyd
*     2007 FlexSecure GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/sha2_32.h>

namespace Botan {

namespace {

namespace SHA2_32 {

/*
* SHA-256 Rho Function
*/
inline uint32_t rho(uint32_t X, uint32_t rot1, uint32_t rot2, uint32_t rot3) {
  return (rotate_right(X, rot1) ^ rotate_right(X, rot2) ^
          rotate_right(X, rot3));
}

/*
* SHA-256 Sigma Function
*/
inline uint32_t sigma(uint32_t X, uint32_t rot1, uint32_t rot2, uint32_t shift) {
  return (rotate_right(X, rot1) ^ rotate_right(X, rot2) ^ (X >> shift));
}

/*
* SHA-256 F1 Function
*
* Use a macro as many compilers won't inline a function this big,
* even though it is much faster if inlined.
*/
#define SHA2_32_F(A, B, C, D, E, F, G, H, M1, M2, M3, M4, magic)   \
  do {                                                            \
    H += magic + rho(E, 6, 11, 25) + ((E & F) ^ (~E & G)) + M1;  \
    D += H;                                                      \
    H += rho(A, 2, 13, 22) + ((A & B) | ((A | B) & C));          \
    M1 += sigma(M2, 17, 19, 10) + M3 + sigma(M4, 7, 18, 3);      \
  } while(0);

/*
* SHA-224 / SHA-256 compression function
*/
void compress(secure_vector<uint32_t>& digest,
              const uint8_t input[], size_t blocks) {
  uint32_t A = digest[0], B = digest[1], C = digest[2],
           D = digest[3], E = digest[4], F = digest[5],
           G = digest[6], H = digest[7];

  for (size_t i = 0; i != blocks; ++i) {
    uint32_t W00 = load_be<uint32_t>(input,  0);
    uint32_t W01 = load_be<uint32_t>(input,  1);
    uint32_t W02 = load_be<uint32_t>(input,  2);
    uint32_t W03 = load_be<uint32_t>(input,  3);
    uint32_t W04 = load_be<uint32_t>(input,  4);
    uint32_t W05 = load_be<uint32_t>(input,  5);
    uint32_t W06 = load_be<uint32_t>(input,  6);
    uint32_t W07 = load_be<uint32_t>(input,  7);
    uint32_t W08 = load_be<uint32_t>(input,  8);
    uint32_t W09 = load_be<uint32_t>(input,  9);
    uint32_t W10 = load_be<uint32_t>(input, 10);
    uint32_t W11 = load_be<uint32_t>(input, 11);
    uint32_t W12 = load_be<uint32_t>(input, 12);
    uint32_t W13 = load_be<uint32_t>(input, 13);
    uint32_t W14 = load_be<uint32_t>(input, 14);
    uint32_t W15 = load_be<uint32_t>(input, 15);

    SHA2_32_F(A, B, C, D, E, F, G, H, W00, W14, W09, W01, 0x428A2F98);
    SHA2_32_F(H, A, B, C, D, E, F, G, W01, W15, W10, W02, 0x71374491);
    SHA2_32_F(G, H, A, B, C, D, E, F, W02, W00, W11, W03, 0xB5C0FBCF);
    SHA2_32_F(F, G, H, A, B, C, D, E, W03, W01, W12, W04, 0xE9B5DBA5);
    SHA2_32_F(E, F, G, H, A, B, C, D, W04, W02, W13, W05, 0x3956C25B);
    SHA2_32_F(D, E, F, G, H, A, B, C, W05, W03, W14, W06, 0x59F111F1);
    SHA2_32_F(C, D, E, F, G, H, A, B, W06, W04, W15, W07, 0x923F82A4);
    SHA2_32_F(B, C, D, E, F, G, H, A, W07, W05, W00, W08, 0xAB1C5ED5);
    SHA2_32_F(A, B, C, D, E, F, G, H, W08, W06, W01, W09, 0xD807AA98);
    SHA2_32_F(H, A, B, C, D, E, F, G, W09, W07, W02, W10, 0x12835B01);
    SHA2_32_F(G, H, A, B, C, D, E, F, W10, W08, W03, W11, 0x243185BE);
    SHA2_32_F(F, G, H, A, B, C, D, E, W11, W09, W04, W12, 0x550C7DC3);
    SHA2_32_F(E, F, G, H, A, B, C, D, W12, W10, W05, W13, 0x72BE5D74);
    SHA2_32_F(D, E, F, G, H, A, B, C, W13, W11, W06, W14, 0x80DEB1FE);
    SHA2_32_F(C, D, E, F, G, H, A, B, W14, W12, W07, W15, 0x9BDC06A7);
    SHA2_32_F(B, C, D, E, F, G, H, A, W15, W13, W08, W00, 0xC19BF174);
    SHA2_32_F(A, B, C, D, E, F, G, H, W00, W14, W09, W01, 0xE49B69C1);
    SHA2_32_F(H, A, B, C, D, E, F, G, W01, W15, W10, W02, 0xEFBE4786);
    SHA2_32_F(G, H, A, B, C, D, E, F, W02, W00, W11, W03, 0x0FC19DC6);
    SHA2_32_F(F, G, H, A, B, C, D, E, W03, W01, W12, W04, 0x240CA1CC);
    SHA2_32_F(E, F, G, H, A, B, C, D, W04, W02, W13, W05, 0x2DE92C6F);
    SHA2_32_F(D, E, F, G, H, A, B, C, W05, W03, W14, W06, 0x4A7484AA);
    SHA2_32_F(C, D, E, F, G, H, A, B, W06, W04, W15, W07, 0x5CB0A9DC);
    SHA2_32_F(B, C, D, E, F, G, H, A, W07, W05, W00, W08, 0x76F988DA);
    SHA2_32_F(A, B, C, D, E, F, G, H, W08, W06, W01, W09, 0x983E5152);
    SHA2_32_F(H, A, B, C, D, E, F, G, W09, W07, W02, W10, 0xA831C66D);
    SHA2_32_F(G, H, A, B, C, D, E, F, W10, W08, W03, W11, 0xB00327C8);
    SHA2_32_F(F, G, H, A, B, C, D, E, W11, W09, W04, W12, 0xBF597FC7);
    SHA2_32_F(E, F, G, H, A, B, C, D, W12, W10, W05, W13, 0xC6E00BF3);
    SHA2_32_F(D, E, F, G, H, A, B, C, W13, W11, W06, W14, 0xD5A79147);
    SHA2_32_F(C, D, E, F, G, H, A, B, W14, W12, W07, W15, 0x06CA6351);
    SHA2_32_F(B, C, D, E, F, G, H, A, W15, W13, W08, W00, 0x14292967);
    SHA2_32_F(A, B, C, D, E, F, G, H, W00, W14, W09, W01, 0x27B70A85);
    SHA2_32_F(H, A, B, C, D, E, F, G, W01, W15, W10, W02, 0x2E1B2138);
    SHA2_32_F(G, H, A, B, C, D, E, F, W02, W00, W11, W03, 0x4D2C6DFC);
    SHA2_32_F(F, G, H, A, B, C, D, E, W03, W01, W12, W04, 0x53380D13);
    SHA2_32_F(E, F, G, H, A, B, C, D, W04, W02, W13, W05, 0x650A7354);
    SHA2_32_F(D, E, F, G, H, A, B, C, W05, W03, W14, W06, 0x766A0ABB);
    SHA2_32_F(C, D, E, F, G, H, A, B, W06, W04, W15, W07, 0x81C2C92E);
    SHA2_32_F(B, C, D, E, F, G, H, A, W07, W05, W00, W08, 0x92722C85);
    SHA2_32_F(A, B, C, D, E, F, G, H, W08, W06, W01, W09, 0xA2BFE8A1);
    SHA2_32_F(H, A, B, C, D, E, F, G, W09, W07, W02, W10, 0xA81A664B);
    SHA2_32_F(G, H, A, B, C, D, E, F, W10, W08, W03, W11, 0xC24B8B70);
    SHA2_32_F(F, G, H, A, B, C, D, E, W11, W09, W04, W12, 0xC76C51A3);
    SHA2_32_F(E, F, G, H, A, B, C, D, W12, W10, W05, W13, 0xD192E819);
    SHA2_32_F(D, E, F, G, H, A, B, C, W13, W11, W06, W14, 0xD6990624);
    SHA2_32_F(C, D, E, F, G, H, A, B, W14, W12, W07, W15, 0xF40E3585);
    SHA2_32_F(B, C, D, E, F, G, H, A, W15, W13, W08, W00, 0x106AA070);
    SHA2_32_F(A, B, C, D, E, F, G, H, W00, W14, W09, W01, 0x19A4C116);
    SHA2_32_F(H, A, B, C, D, E, F, G, W01, W15, W10, W02, 0x1E376C08);
    SHA2_32_F(G, H, A, B, C, D, E, F, W02, W00, W11, W03, 0x2748774C);
    SHA2_32_F(F, G, H, A, B, C, D, E, W03, W01, W12, W04, 0x34B0BCB5);
    SHA2_32_F(E, F, G, H, A, B, C, D, W04, W02, W13, W05, 0x391C0CB3);
    SHA2_32_F(D, E, F, G, H, A, B, C, W05, W03, W14, W06, 0x4ED8AA4A);
    SHA2_32_F(C, D, E, F, G, H, A, B, W06, W04, W15, W07, 0x5B9CCA4F);
    SHA2_32_F(B, C, D, E, F, G, H, A, W07, W05, W00, W08, 0x682E6FF3);
    SHA2_32_F(A, B, C, D, E, F, G, H, W08, W06, W01, W09, 0x748F82EE);
    SHA2_32_F(H, A, B, C, D, E, F, G, W09, W07, W02, W10, 0x78A5636F);
    SHA2_32_F(G, H, A, B, C, D, E, F, W10, W08, W03, W11, 0x84C87814);
    SHA2_32_F(F, G, H, A, B, C, D, E, W11, W09, W04, W12, 0x8CC70208);
    SHA2_32_F(E, F, G, H, A, B, C, D, W12, W10, W05, W13, 0x90BEFFFA);
    SHA2_32_F(D, E, F, G, H, A, B, C, W13, W11, W06, W14, 0xA4506CEB);
    SHA2_32_F(C, D, E, F, G, H, A, B, W14, W12, W07, W15, 0xBEF9A3F7);
    SHA2_32_F(B, C, D, E, F, G, H, A, W15, W13, W08, W00, 0xC67178F2);

    A = (digest[0] += A);
    B = (digest[1] += B);
    C = (digest[2] += C);
    D = (digest[3] += D);
    E = (digest[4] += E);
    F = (digest[5] += F);
    G = (digest[6] += G);
    H = (digest[7] += H);

    input += 64;
  }
}

}

}

/*
* SHA-224 compression function
*/
void SHA_224::compress_n(const uint8_t input[], size_t blocks) {
  SHA2_32::compress(m_digest, input, blocks);
}

/*
* Copy out the digest
*/
void SHA_224::copy_out(uint8_t output[]) {
  copy_out_vec_be(output, output_length(), m_digest);
}

/*
* Clear memory of sensitive data
*/
void SHA_224::clear() {
  MDx_HashFunction::clear();
  m_digest[0] = 0xC1059ED8;
  m_digest[1] = 0x367CD507;
  m_digest[2] = 0x3070DD17;
  m_digest[3] = 0xF70E5939;
  m_digest[4] = 0xFFC00B31;
  m_digest[5] = 0x68581511;
  m_digest[6] = 0x64F98FA7;
  m_digest[7] = 0xBEFA4FA4;
}

/*
* SHA-256 compression function
*/
void SHA_256::compress_n(const uint8_t input[], size_t blocks) {
  SHA2_32::compress(m_digest, input, blocks);
}

/*
* Copy out the digest
*/
void SHA_256::copy_out(uint8_t output[]) {
  copy_out_vec_be(output, output_length(), m_digest);
}

/*
* Clear memory of sensitive data
*/
void SHA_256::clear() {
  MDx_HashFunction::clear();
  m_digest[0] = 0x6A09E667;
  m_digest[1] = 0xBB67AE85;
  m_digest[2] = 0x3C6EF372;
  m_digest[3] = 0xA54FF53A;
  m_digest[4] = 0x510E527F;
  m_digest[5] = 0x9B05688C;
  m_digest[6] = 0x1F83D9AB;
  m_digest[7] = 0x5BE0CD19;
}

}
