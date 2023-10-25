/*
* Asymmetric primitives for dilithium
* (C) 2022-2023 Jack Lloyd
* (C) 2022-2023 Michael Boric, René Meusel - Rohde & Schwarz Cybersecurity
* (C) 2022      Manuel Glaser - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_DILITHIUM_ASYM_PRIMITIVES_H_
#define BOTAN_DILITHIUM_ASYM_PRIMITIVES_H_

#include <botan/dilithium.h>

#include <botan/xof.h>
#include <botan/internal/shake.h>

#include <memory>
#include <span>
#include <vector>

namespace Botan {

/**
* Adapter class that uses polymorphy to distinguish
* Dilithium "common" from Dilithium "AES" modes.
*/
class Dilithium_Symmetric_Primitives {
   public:
      enum class XofType { k128, k256 };

   public:
      static std::unique_ptr<Dilithium_Symmetric_Primitives> create(DilithiumMode mode);

      virtual ~Dilithium_Symmetric_Primitives() = default;

      // H is same for all modes
      secure_vector<uint8_t> H(std::span<const uint8_t> seed, size_t out_len) const {
         return SHAKE_256(out_len * 8).process(seed.data(), seed.size());
      }

      // CRH is same for all modes
      secure_vector<uint8_t> CRH(std::span<const uint8_t> in, size_t out_len) const {
         return SHAKE_256(out_len * 8).process(in.data(), in.size());
      }

      // ExpandMatrix always uses the 256 version of the XOF
      secure_vector<uint8_t> ExpandMask(std::span<const uint8_t> seed, uint16_t nonce, size_t out_len) const {
         return XOF(XofType::k256, seed, nonce)->output(out_len);
      }

      // Mode dependent function
      virtual std::unique_ptr<Botan::XOF> XOF(XofType type, std::span<const uint8_t> seed, uint16_t nonce) const = 0;
};

enum DilithiumEta : uint32_t { Eta2 = 2, Eta4 = 4 };

// Constants and mode dependent values
class DilithiumModeConstants {
   public:
      static constexpr int32_t SEEDBYTES = 32;
      static constexpr int32_t CRHBYTES = 64;
      static constexpr int32_t N = 256;
      static constexpr int32_t Q = 8380417;
      static constexpr int32_t D = 13;
      static constexpr int32_t ROOT_OF_UNITY = 1753;
      static constexpr int32_t POLYT1_PACKEDBYTES = 320;
      static constexpr int32_t POLYT0_PACKEDBYTES = 416;
      static constexpr int32_t SHAKE128_RATE = 168;
      static constexpr int32_t SHAKE256_RATE = 136;
      static constexpr int32_t SHA3_256_RATE = 136;
      static constexpr int32_t SHA3_512_RATE = 72;
      static constexpr int32_t AES256CTR_BLOCKBYTES = 64;
      static constexpr int32_t QINV = 58728449;
      static constexpr int32_t ZETAS[DilithiumModeConstants::N] = {
         0,        25847,    -2608894, -518909,  237124,   -777960,  -876248,  466468,   1826347,  2353451,  -359251,
         -2091905, 3119733,  -2884855, 3111497,  2680103,  2725464,  1024112,  -1079900, 3585928,  -549488,  -1119584,
         2619752,  -2108549, -2118186, -3859737, -1399561, -3277672, 1757237,  -19422,   4010497,  280005,   2706023,
         95776,    3077325,  3530437,  -1661693, -3592148, -2537516, 3915439,  -3861115, -3043716, 3574422,  -2867647,
         3539968,  -300467,  2348700,  -539299,  -1699267, -1643818, 3505694,  -3821735, 3507263,  -2140649, -1600420,
         3699596,  811944,   531354,   954230,   3881043,  3900724,  -2556880, 2071892,  -2797779, -3930395, -1528703,
         -3677745, -3041255, -1452451, 3475950,  2176455,  -1585221, -1257611, 1939314,  -4083598, -1000202, -3190144,
         -3157330, -3632928, 126922,   3412210,  -983419,  2147896,  2715295,  -2967645, -3693493, -411027,  -2477047,
         -671102,  -1228525, -22981,   -1308169, -381987,  1349076,  1852771,  -1430430, -3343383, 264944,   508951,
         3097992,  44288,    -1100098, 904516,   3958618,  -3724342, -8578,    1653064,  -3249728, 2389356,  -210977,
         759969,   -1316856, 189548,   -3553272, 3159746,  -1851402, -2409325, -177440,  1315589,  1341330,  1285669,
         -1584928, -812732,  -1439742, -3019102, -3881060, -3628969, 3839961,  2091667,  3407706,  2316500,  3817976,
         -3342478, 2244091,  -2446433, -3562462, 266997,   2434439,  -1235728, 3513181,  -3520352, -3759364, -1197226,
         -3193378, 900702,   1859098,  909542,   819034,   495491,   -1613174, -43260,   -522500,  -655327,  -3122442,
         2031748,  3207046,  -3556995, -525098,  -768622,  -3595838, 342297,   286988,   -2437823, 4108315,  3437287,
         -3342277, 1735879,  203044,   2842341,  2691481,  -2590150, 1265009,  4055324,  1247620,  2486353,  1595974,
         -3767016, 1250494,  2635921,  -3548272, -2994039, 1869119,  1903435,  -1050970, -1333058, 1237275,  -3318210,
         -1430225, -451100,  1312455,  3306115,  -1962642, -1279661, 1917081,  -2546312, -1374803, 1500165,  777191,
         2235880,  3406031,  -542412,  -2831860, -1671176, -1846953, -2584293, -3724270, 594136,   -3776993, -2013608,
         2432395,  2454455,  -164721,  1957272,  3369112,  185531,   -1207385, -3183426, 162844,   1616392,  3014001,
         810149,   1652634,  -3694233, -1799107, -3038916, 3523897,  3866901,  269760,   2213111,  -975884,  1717735,
         472078,   -426683,  1723600,  -1803090, 1910376,  -1667432, -1104333, -260646,  -3833893, -2939036, -2235985,
         -420899,  -2286327, 183443,   -976891,  1612842,  -3545687, -554416,  3919660,  -48306,   -1362209, 3937738,
         1400424,  -846154,  1976782};
      static constexpr int32_t kSerializedPolynomialByteLength = DilithiumModeConstants::N / 2 * 3;

      DilithiumModeConstants(DilithiumMode dimension);

      DilithiumModeConstants(const DilithiumModeConstants& other) : DilithiumModeConstants(other.m_mode) {}

      DilithiumModeConstants(DilithiumModeConstants&& other) = default;
      DilithiumModeConstants& operator=(const DilithiumModeConstants& other) = delete;
      DilithiumModeConstants& operator=(DilithiumModeConstants&& other) = default;

      // Getter
      uint8_t k() const { return m_k; }

      uint8_t l() const { return m_l; }

      DilithiumEta eta() const { return m_eta; }

      size_t tau() const { return m_tau; }

      size_t poly_uniform_gamma1_nblocks() const { return m_poly_uniform_gamma1_nblocks; }

      size_t stream256_blockbytes() const { return m_stream256_blockbytes; }

      size_t stream128_blockbytes() const { return m_stream128_blockbytes; }

      size_t polyw1_packedbytes() const { return m_polyw1_packedbytes; }

      size_t omega() const { return m_omega; }

      size_t polyz_packedbytes() const { return m_polyz_packedbytes; }

      size_t gamma2() const { return m_gamma2; }

      size_t gamma1() const { return m_gamma1; }

      size_t beta() const { return m_beta; }

      size_t poly_uniform_eta_nblocks() const { return m_poly_uniform_eta_nblocks; }

      size_t poly_uniform_nblocks() const { return m_poly_uniform_nblocks; }

      size_t polyeta_packedbytes() const { return m_polyeta_packedbytes; }

      size_t public_key_bytes() const { return m_public_key_bytes; }

      size_t crypto_bytes() const { return m_crypto_bytes; }

      OID oid() const { return m_mode.object_identifier(); }

      DilithiumMode mode() const { return m_mode; }

      size_t private_key_bytes() const { return m_private_key_bytes; }

      size_t nist_security_strength() const { return m_nist_security_strength; }

      // Wrapper
      decltype(auto) H(std::span<const uint8_t> seed, size_t out_len) const {
         return m_symmetric_primitives->H(seed, out_len);
      }

      secure_vector<uint8_t> CRH(const std::span<const uint8_t> in) const {
         return m_symmetric_primitives->CRH(in, DilithiumModeConstants::CRHBYTES);
      }

      std::unique_ptr<Botan::XOF> XOF_128(std::span<const uint8_t> seed, uint16_t nonce) const {
         return this->m_symmetric_primitives->XOF(Dilithium_Symmetric_Primitives::XofType::k128, seed, nonce);
      }

      std::unique_ptr<Botan::XOF> XOF_256(std::span<const uint8_t> seed, uint16_t nonce) const {
         return this->m_symmetric_primitives->XOF(Dilithium_Symmetric_Primitives::XofType::k256, seed, nonce);
      }

      secure_vector<uint8_t> ExpandMask(const secure_vector<uint8_t>& seed, uint16_t nonce) const {
         return this->m_symmetric_primitives->ExpandMask(
            seed, nonce, poly_uniform_gamma1_nblocks() * stream256_blockbytes());
      }

   private:
      DilithiumMode m_mode;

      uint16_t m_nist_security_strength;

      // generated matrix dimension is m_k x m_l
      uint8_t m_k;
      uint8_t m_l;
      DilithiumEta m_eta;
      int32_t m_tau;
      int32_t m_beta;
      int32_t m_gamma1;
      int32_t m_gamma2;
      int32_t m_omega;
      int32_t m_stream128_blockbytes;
      int32_t m_stream256_blockbytes;
      int32_t m_poly_uniform_nblocks;
      int32_t m_poly_uniform_eta_nblocks;
      int32_t m_poly_uniform_gamma1_nblocks;
      int32_t m_polyvech_packedbytes;
      int32_t m_polyz_packedbytes;
      int32_t m_polyw1_packedbytes;
      int32_t m_polyeta_packedbytes;
      int32_t m_private_key_bytes;
      int32_t m_public_key_bytes;
      int32_t m_crypto_bytes;

      // Mode dependent primitives
      std::unique_ptr<Dilithium_Symmetric_Primitives> m_symmetric_primitives;
};
}  // namespace Botan

#endif
