/*
* Crystals Dilithium Digital Signature Algorithms
* Based on the public domain reference implementation by the
* designers (https://github.com/pq-crystals/dilithium)
*
* Further changes
* (C) 2021-2023 Jack Lloyd
* (C) 2021-2022 Manuel Glaser - Rohde & Schwarz Cybersecurity
* (C) 2021-2023 Michael Boric, René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/dilithium.h>

#include <botan/exceptn.h>
#include <botan/hash.h>
#include <botan/rng.h>

#include <botan/internal/dilithium_polynomials.h>
#include <botan/internal/fmt.h>
#include <botan/internal/parsing.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/internal/shake.h>
#include <botan/internal/stl_util.h>

#include <algorithm>
#include <array>
#include <iterator>
#include <span>
#include <vector>

namespace Botan {
namespace {

std::pair<Dilithium::PolynomialVector, Dilithium::PolynomialVector> calculate_t0_and_t1(
   const DilithiumModeConstants& mode,
   const std::vector<uint8_t>& rho,
   Dilithium::PolynomialVector s1,
   const Dilithium::PolynomialVector& s2) {
   /* Generate matrix */
   auto matrix = Dilithium::PolynomialMatrix::generate_matrix(rho, mode);

   /* Matrix-vector multiplication */
   s1.ntt();
   auto t = Dilithium::PolynomialVector::generate_polyvec_matrix_pointwise_montgomery(matrix.get_matrix(), s1, mode);
   t.reduce();
   t.invntt_tomont();

   /* Add error vector s2 */
   t.add_polyvec(s2);

   /* Extract t and write public key */
   t.cadd_q();

   Dilithium::PolynomialVector t0(mode.k());
   Dilithium::PolynomialVector t1(mode.k());
   Dilithium::PolynomialVector::fill_polyvecs_power2round(t1, t0, t);

   return {std::move(t0), std::move(t1)};
}

DilithiumMode::Mode dilithium_mode_from_string(std::string_view str) {
   if(str == "Dilithium-4x4-r3") {
      return DilithiumMode::Dilithium4x4;
   }
   if(str == "Dilithium-4x4-AES-r3") {
      return DilithiumMode::Dilithium4x4_AES;
   }
   if(str == "Dilithium-6x5-r3") {
      return DilithiumMode::Dilithium6x5;
   }
   if(str == "Dilithium-6x5-AES-r3") {
      return DilithiumMode::Dilithium6x5_AES;
   }
   if(str == "Dilithium-8x7-r3") {
      return DilithiumMode::Dilithium8x7;
   }
   if(str == "Dilithium-8x7-AES-r3") {
      return DilithiumMode::Dilithium8x7_AES;
   }
   if(str == "ML-DSA-4x4-IPD") {
      return DilithiumMode::ML_DSA4x4_IPD;
   }
   if(str == "ML-DSA-6x5-IPD") {
      return DilithiumMode::ML_DSA6x5_IPD;
   }
   if(str == "ML-DSA-8x7-IPD") {
      return DilithiumMode::ML_DSA8x7_IPD;
   }
   throw Invalid_Argument(fmt("'{}' is not a valid Dilithium mode name", str));
}

}  // namespace

DilithiumMode::DilithiumMode(const OID& oid) : m_mode(dilithium_mode_from_string(oid.to_formatted_string())) {}

DilithiumMode::DilithiumMode(std::string_view str) : m_mode(dilithium_mode_from_string(str)) {}

OID DilithiumMode::object_identifier() const {
   return OID::from_string(to_string());
}

std::string DilithiumMode::to_string() const {
   switch(m_mode) {
      case DilithiumMode::Dilithium4x4:
         return "Dilithium-4x4-r3";
      case DilithiumMode::Dilithium4x4_AES:
         return "Dilithium-4x4-AES-r3";
      case DilithiumMode::Dilithium6x5:
         return "Dilithium-6x5-r3";
      case DilithiumMode::Dilithium6x5_AES:
         return "Dilithium-6x5-AES-r3";
      case DilithiumMode::Dilithium8x7:
         return "Dilithium-8x7-r3";
      case DilithiumMode::Dilithium8x7_AES:
         return "Dilithium-8x7-AES-r3";
      case DilithiumMode::ML_DSA4x4_IPD:
         return "ML-DSA-4x4-IPD";
      case DilithiumMode::ML_DSA6x5_IPD:
         return "ML-DSA-6x5-IPD";
      case DilithiumMode::ML_DSA8x7_IPD:
         return "ML-DSA-8x7-IPD";
   }

   BOTAN_ASSERT_UNREACHABLE();
}

class Dilithium_PublicKeyInternal {
   public:
      Dilithium_PublicKeyInternal(DilithiumModeConstants mode_constants) :
            m_mode_constants(std::move(mode_constants)) {}

      Dilithium_PublicKeyInternal(DilithiumModeConstants mode_constants, std::span<const uint8_t> raw_pk) :
            m_mode_constants(std::move(mode_constants)) {
         BOTAN_ASSERT_NOMSG(raw_pk.size() == m_mode_constants.public_key_bytes());

         BufferSlicer s(raw_pk);
         m_rho = s.copy_as_vector(DilithiumModeConstants::SEEDBYTES);
         m_t1 = Dilithium::PolynomialVector::unpack_t1(
            s.take(DilithiumModeConstants::POLYT1_PACKEDBYTES * m_mode_constants.k()), m_mode_constants);

         BOTAN_ASSERT_NOMSG(s.remaining() == 0);
         BOTAN_STATE_CHECK(m_t1.m_vec.size() == m_mode_constants.k());

         m_raw_pk_shake256 = compute_raw_pk_shake256();
      }

      Dilithium_PublicKeyInternal(DilithiumModeConstants mode_constants,
                                  std::vector<uint8_t> rho,
                                  const Dilithium::PolynomialVector& s1,
                                  const Dilithium::PolynomialVector& s2) :
            m_mode_constants(std::move(mode_constants)),
            m_rho(std::move(rho)),
            m_t1([&] { return calculate_t0_and_t1(m_mode_constants, m_rho, s1, s2).second; }()) {
         BOTAN_ASSERT_NOMSG(!m_rho.empty());
         BOTAN_ASSERT_NOMSG(!m_t1.m_vec.empty());
         m_raw_pk_shake256 = compute_raw_pk_shake256();
      }

      Dilithium_PublicKeyInternal(DilithiumModeConstants mode,
                                  std::vector<uint8_t> rho,
                                  Dilithium::PolynomialVector t1) :
            m_mode_constants(std::move(mode)), m_rho(std::move(rho)), m_t1(std::move(t1)) {
         BOTAN_ASSERT_NOMSG(!m_rho.empty());
         BOTAN_ASSERT_NOMSG(!m_t1.m_vec.empty());
         m_raw_pk_shake256 = compute_raw_pk_shake256();
      }

      ~Dilithium_PublicKeyInternal() = default;

      Dilithium_PublicKeyInternal(const Dilithium_PublicKeyInternal&) = delete;
      Dilithium_PublicKeyInternal(Dilithium_PublicKeyInternal&&) = delete;
      Dilithium_PublicKeyInternal& operator=(const Dilithium_PublicKeyInternal& other) = delete;
      Dilithium_PublicKeyInternal& operator=(Dilithium_PublicKeyInternal&& other) = delete;

      std::vector<uint8_t> raw_pk() const { return concat<std::vector<uint8_t>>(m_rho, m_t1.polyvec_pack_t1()); }

      const std::vector<uint8_t>& raw_pk_shake256() const {
         BOTAN_STATE_CHECK(m_raw_pk_shake256.size() == m_mode_constants.trbytes());
         return m_raw_pk_shake256;
      }

      const Dilithium::PolynomialVector& t1() const { return m_t1; }

      const std::vector<uint8_t>& rho() const { return m_rho; }

      const DilithiumModeConstants& mode_constants() const { return m_mode_constants; }

   private:
      std::vector<uint8_t> compute_raw_pk_shake256() const {
         SHAKE_256 shake(m_mode_constants.trbytes() * 8);
         shake.update(m_rho);
         shake.update(m_t1.polyvec_pack_t1());
         return shake.final_stdvec();
      }

      const DilithiumModeConstants m_mode_constants;
      std::vector<uint8_t> m_raw_pk_shake256;
      std::vector<uint8_t> m_rho;
      Dilithium::PolynomialVector m_t1;
};

class Dilithium_PrivateKeyInternal {
   public:
      Dilithium_PrivateKeyInternal(DilithiumModeConstants mode_constants) :
            m_mode_constants(std::move(mode_constants)) {}

      Dilithium_PrivateKeyInternal(DilithiumModeConstants mode_constants,
                                   std::vector<uint8_t> rho,
                                   secure_vector<uint8_t> tr,
                                   secure_vector<uint8_t> key,
                                   Dilithium::PolynomialVector s1,
                                   Dilithium::PolynomialVector s2,
                                   Dilithium::PolynomialVector t0) :
            m_mode_constants(std::move(mode_constants)),
            m_rho(std::move(rho)),
            m_tr(std::move(tr)),
            m_key(std::move(key)),
            m_t0(std::move(t0)),
            m_s1(std::move(s1)),
            m_s2(std::move(s2)) {}

      Dilithium_PrivateKeyInternal(DilithiumModeConstants mode_constants, std::span<const uint8_t> sk) :
            Dilithium_PrivateKeyInternal(std::move(mode_constants)) {
         BOTAN_ASSERT_NOMSG(sk.size() == m_mode_constants.private_key_bytes());

         BufferSlicer s(sk);
         m_rho = s.copy_as_vector(DilithiumModeConstants::SEEDBYTES);
         m_key = s.copy_as_secure_vector(DilithiumModeConstants::SEEDBYTES);
         m_tr = s.copy_as_secure_vector(m_mode_constants.trbytes());
         m_s1 = Dilithium::PolynomialVector::unpack_eta(
            s.take(m_mode_constants.l() * m_mode_constants.polyeta_packedbytes()),
            m_mode_constants.l(),
            m_mode_constants);
         m_s2 = Dilithium::PolynomialVector::unpack_eta(
            s.take(m_mode_constants.k() * m_mode_constants.polyeta_packedbytes()),
            m_mode_constants.k(),
            m_mode_constants);
         m_t0 = Dilithium::PolynomialVector::unpack_t0(
            s.take(m_mode_constants.k() * DilithiumModeConstants::POLYT0_PACKEDBYTES), m_mode_constants);

         BOTAN_ASSERT_NOMSG(s.empty());
      }

      secure_vector<uint8_t> raw_sk() const {
         return concat<secure_vector<uint8_t>>(m_rho,
                                               m_key,
                                               m_tr,
                                               m_s1.polyvec_pack_eta(m_mode_constants),
                                               m_s2.polyvec_pack_eta(m_mode_constants),
                                               m_t0.polyvec_pack_t0());
      }

      const DilithiumModeConstants& mode_constants() const { return m_mode_constants; }

      const std::vector<uint8_t>& rho() const { return m_rho; }

      const secure_vector<uint8_t>& get_key() const { return m_key; }

      const secure_vector<uint8_t>& tr() const { return m_tr; }

      const Dilithium::PolynomialVector& s1() const { return m_s1; }

      const Dilithium::PolynomialVector& s2() const { return m_s2; }

      const Dilithium::PolynomialVector& t0() const { return m_t0; }

   private:
      const DilithiumModeConstants m_mode_constants;
      std::vector<uint8_t> m_rho;
      secure_vector<uint8_t> m_tr, m_key;
      Dilithium::PolynomialVector m_t0, m_s1, m_s2;
};

class Dilithium_Signature_Operation final : public PK_Ops::Signature {
   public:
      Dilithium_Signature_Operation(const Dilithium_PrivateKey& priv_key_dilithium, bool randomized) :
            m_priv_key(priv_key_dilithium),
            m_matrix(Dilithium::PolynomialMatrix::generate_matrix(m_priv_key.m_private->rho(),
                                                                  m_priv_key.m_private->mode_constants())),
            m_shake(DilithiumModeConstants::CRHBYTES * 8),
            m_randomized(randomized) {
         m_shake.update(m_priv_key.m_private->tr());
      }

      void update(const uint8_t msg[], size_t msg_len) override { m_shake.update(msg, msg_len); }

      secure_vector<uint8_t> sign(RandomNumberGenerator& rng) override {
         const auto mu = m_shake.final_stdvec();

         // Get set up for the next message (if any)
         m_shake.update(m_priv_key.m_private->tr());

         const auto& mode_constants = m_priv_key.m_private->mode_constants();

         const auto rhoprime = mode_constants.calc_rhoprime(rng, m_priv_key.m_private->get_key(), mu, m_randomized);

         /* Transform vectors */
         auto s1 = m_priv_key.m_private->s1();
         s1.ntt();

         auto s2 = m_priv_key.m_private->s2();
         s2.ntt();

         auto t0 = m_priv_key.m_private->t0();
         t0.ntt();

         // Note: nonce (as requested by `polyvecl_uniform_gamma1`) is actually just uint16_t
         //       but to avoid an integer overflow, we use uint32_t as the loop variable.
         for(uint32_t nonce = 0; nonce <= std::numeric_limits<uint16_t>::max(); ++nonce) {
            /* Sample intermediate vector y */
            Dilithium::PolynomialVector y(mode_constants.l());

            y.polyvecl_uniform_gamma1(rhoprime, static_cast<uint16_t>(nonce), mode_constants);

            auto z = y;
            z.ntt();

            /* Matrix-vector multiplication */
            auto w1 = Dilithium::PolynomialVector::generate_polyvec_matrix_pointwise_montgomery(
               m_matrix.get_matrix(), z, mode_constants);

            w1.reduce();
            w1.invntt_tomont();

            /* Decompose w and call the random oracle */
            w1.cadd_q();

            auto w1_w0 = w1.polyvec_decompose(mode_constants);

            auto packed_w1 = std::get<0>(w1_w0).polyvec_pack_w1(mode_constants);

            SHAKE_256 shake256_variable(mode_constants.ctildebytes() * 8);
            shake256_variable.update(mu.data(), DilithiumModeConstants::CRHBYTES);
            shake256_variable.update(packed_w1.data(), packed_w1.size());
            auto sm = shake256_variable.final();

            auto cp = Dilithium::Polynomial::poly_challenge(sm.data(), mode_constants);
            cp.ntt();

            /* Compute z, reject if it reveals secret */
            s1.polyvec_pointwise_poly_montgomery(z, cp);

            z.invntt_tomont();
            z.add_polyvec(y);

            z.reduce();
            if(z.polyvec_chknorm(mode_constants.gamma1() - mode_constants.beta())) {
               continue;
            }

            /* Check that subtracting cs2 does not change high bits of w and low bits
            * do not reveal secret information */
            Dilithium::PolynomialVector h(mode_constants.k());
            s2.polyvec_pointwise_poly_montgomery(h, cp);
            h.invntt_tomont();
            std::get<1>(w1_w0) -= h;
            std::get<1>(w1_w0).reduce();

            if(std::get<1>(w1_w0).polyvec_chknorm(mode_constants.gamma2() - mode_constants.beta())) {
               continue;
            }

            /* Compute hints for w1 */
            t0.polyvec_pointwise_poly_montgomery(h, cp);
            h.invntt_tomont();
            h.reduce();
            if(h.polyvec_chknorm(mode_constants.gamma2())) {
               continue;
            }

            std::get<1>(w1_w0).add_polyvec(h);
            std::get<1>(w1_w0).cadd_q();

            auto n = Dilithium::PolynomialVector::generate_hint_polyvec(
               h, std::get<1>(w1_w0), std::get<0>(w1_w0), mode_constants);
            if(n > mode_constants.omega()) {
               continue;
            }

            /* Write signature */
            return pack_sig(sm, z, h);
         }

         throw Internal_Error("Dilithium signature loop did not terminate");
      }

      size_t signature_length() const override {
         const auto& dilithium_math = m_priv_key.m_private->mode_constants();
         return dilithium_math.crypto_bytes();
      }

      AlgorithmIdentifier algorithm_identifier() const override;

      std::string hash_function() const override { return "SHAKE-256(512)"; }

   private:
      // Bit-pack signature sig = (c, z, h).
      secure_vector<uint8_t> pack_sig(const secure_vector<uint8_t>& c,
                                      const Dilithium::PolynomialVector& z,
                                      const Dilithium::PolynomialVector& h) {
         const auto& mode_constants = m_priv_key.m_private->mode_constants();
         BOTAN_ASSERT_NOMSG(c.size() == mode_constants.ctildebytes());
         size_t position = 0;
         secure_vector<uint8_t> sig(mode_constants.crypto_bytes());

         std::copy(c.begin(), c.end(), sig.begin());
         position += mode_constants.ctildebytes();

         for(size_t i = 0; i < mode_constants.l(); ++i) {
            z.m_vec[i].polyz_pack(&sig[position + i * mode_constants.polyz_packedbytes()], mode_constants);
         }
         position += mode_constants.l() * mode_constants.polyz_packedbytes();

         /* Encode h */
         for(size_t i = 0; i < mode_constants.omega() + mode_constants.k(); ++i) {
            sig[i + position] = 0;
         }

         size_t k = 0;
         for(size_t i = 0; i < mode_constants.k(); ++i) {
            for(size_t j = 0; j < DilithiumModeConstants::N; ++j) {
               if(h.m_vec[i].m_coeffs[j] != 0) {
                  sig[position + k] = static_cast<uint8_t>(j);
                  k++;
               }
            }
            sig[position + mode_constants.omega() + i] = static_cast<uint8_t>(k);
         }
         return sig;
      }

      const Dilithium_PrivateKey m_priv_key;
      const Dilithium::PolynomialMatrix m_matrix;
      SHAKE_256 m_shake;
      bool m_randomized;
};

AlgorithmIdentifier Dilithium_Signature_Operation::algorithm_identifier() const {
   return m_priv_key.algorithm_identifier();
}

class Dilithium_Verification_Operation final : public PK_Ops::Verification {
   public:
      Dilithium_Verification_Operation(const Dilithium_PublicKey& pub_dilithium) :
            m_pub_key(pub_dilithium.m_public),
            m_matrix(Dilithium::PolynomialMatrix::generate_matrix(m_pub_key->rho(), m_pub_key->mode_constants())),
            m_pk_hash(m_pub_key->raw_pk_shake256()),
            m_shake(DilithiumModeConstants::CRHBYTES * 8) {
         m_shake.update(m_pk_hash);
      }

      /*
      * Add more data to the message currently being signed
      * @param msg the message
      * @param msg_len the length of msg in bytes
      */
      void update(const uint8_t msg[], size_t msg_len) override { m_shake.update(msg, msg_len); }

      /*
      * Perform a verification operation
      * @param rng a random number generator
      */
      bool is_valid_signature(const uint8_t* sig, size_t sig_len) override {
         /* Compute CRH(H(rho, t1), msg) */
         const auto mu = m_shake.final_stdvec();

         // Reset the SHAKE context for the next message
         m_shake.update(m_pk_hash);

         const auto& mode_constants = m_pub_key->mode_constants();

         if(sig_len != mode_constants.crypto_bytes()) {
            return false;
         }

         Dilithium::PolynomialVector z(mode_constants.l());
         Dilithium::PolynomialVector h(mode_constants.k());
         std::vector<uint8_t> signature(sig, sig + sig_len);
         std::vector<uint8_t> c(mode_constants.ctildebytes());
         if(Dilithium::PolynomialVector::unpack_sig(c, z, h, signature, mode_constants)) {
            return false;
         }

         if(z.polyvec_chknorm(mode_constants.gamma1() - mode_constants.beta())) {
            return false;
         }

         /* Matrix-vector multiplication; compute Az - c2^dt1 */
         auto cp = Dilithium::Polynomial::poly_challenge(c.data(), mode_constants);
         cp.ntt();

         Dilithium::PolynomialVector t1 = m_pub_key->t1();
         t1.polyvec_shiftl();
         t1.ntt();
         t1.polyvec_pointwise_poly_montgomery(t1, cp);

         z.ntt();

         auto w1 = Dilithium::PolynomialVector::generate_polyvec_matrix_pointwise_montgomery(
            m_matrix.get_matrix(), z, mode_constants);
         w1 -= t1;
         w1.reduce();
         w1.invntt_tomont();
         w1.cadd_q();
         w1.polyvec_use_hint(w1, h, mode_constants);
         auto packed_w1 = w1.polyvec_pack_w1(mode_constants);

         /* Call random oracle and verify challenge */
         SHAKE_256 shake256_variable(mode_constants.ctildebytes() * 8);
         shake256_variable.update(mu.data(), mu.size());
         shake256_variable.update(packed_w1.data(), packed_w1.size());
         auto c2 = shake256_variable.final();

         BOTAN_ASSERT_NOMSG(c.size() == c2.size());
         return std::equal(c.begin(), c.end(), c2.begin());
      }

      std::string hash_function() const override { return "SHAKE-256(512)"; }

   private:
      std::shared_ptr<Dilithium_PublicKeyInternal> m_pub_key;
      const Dilithium::PolynomialMatrix m_matrix;
      const std::vector<uint8_t> m_pk_hash;
      SHAKE_256 m_shake;
};

Dilithium_PublicKey::Dilithium_PublicKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> pk) :
      Dilithium_PublicKey(pk, DilithiumMode(alg_id.oid())) {}

Dilithium_PublicKey::Dilithium_PublicKey(std::span<const uint8_t> pk, DilithiumMode m) {
   DilithiumModeConstants mode_constants(m);
   BOTAN_ARG_CHECK(pk.empty() || pk.size() == mode_constants.public_key_bytes(),
                   "dilithium public key does not have the correct byte count");

   m_public = std::make_shared<Dilithium_PublicKeyInternal>(std::move(mode_constants), pk);
}

std::string Dilithium_PublicKey::algo_name() const {
   return object_identifier().to_formatted_string();
}

AlgorithmIdentifier Dilithium_PublicKey::algorithm_identifier() const {
   return AlgorithmIdentifier(object_identifier(), AlgorithmIdentifier::USE_EMPTY_PARAM);
}

OID Dilithium_PublicKey::object_identifier() const {
   return m_public->mode_constants().oid();
}

size_t Dilithium_PublicKey::key_length() const {
   return m_public->mode_constants().public_key_bytes();
}

size_t Dilithium_PublicKey::estimated_strength() const {
   return m_public->mode_constants().nist_security_strength();
}

std::vector<uint8_t> Dilithium_PublicKey::public_key_bits() const {
   return m_public->raw_pk();
}

bool Dilithium_PublicKey::check_key(RandomNumberGenerator&, bool) const {
   return true;  // ???
}

std::unique_ptr<Private_Key> Dilithium_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<Dilithium_PrivateKey>(rng, m_public->mode_constants().mode());
}

std::unique_ptr<PK_Ops::Verification> Dilithium_PublicKey::create_verification_op(std::string_view params,
                                                                                  std::string_view provider) const {
   BOTAN_ARG_CHECK(params.empty() || params == "Pure", "Unexpected parameters for verifying with Dilithium");
   if(provider.empty() || provider == "base") {
      return std::make_unique<Dilithium_Verification_Operation>(*this);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

std::unique_ptr<PK_Ops::Verification> Dilithium_PublicKey::create_x509_verification_op(
   const AlgorithmIdentifier& alg_id, std::string_view provider) const {
   if(provider.empty() || provider == "base") {
      if(alg_id != this->algorithm_identifier()) {
         throw Decoding_Error("Unexpected AlgorithmIdentifier for Dilithium X.509 signature");
      }
      return std::make_unique<Dilithium_Verification_Operation>(*this);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

Dilithium_PrivateKey::Dilithium_PrivateKey(RandomNumberGenerator& rng, DilithiumMode m) {
   DilithiumModeConstants mode_constants(m);

   secure_vector<uint8_t> seedbuf = rng.random_vec(DilithiumModeConstants::SEEDBYTES);

   auto seed = mode_constants.H(seedbuf, 2 * DilithiumModeConstants::SEEDBYTES + DilithiumModeConstants::CRHBYTES);

   // seed is a concatenation of rho || rhoprime || key
   std::vector<uint8_t> rho(seed.begin(), seed.begin() + DilithiumModeConstants::SEEDBYTES);
   secure_vector<uint8_t> rhoprime(seed.begin() + DilithiumModeConstants::SEEDBYTES,
                                   seed.begin() + DilithiumModeConstants::SEEDBYTES + DilithiumModeConstants::CRHBYTES);
   secure_vector<uint8_t> key(seed.begin() + DilithiumModeConstants::SEEDBYTES + DilithiumModeConstants::CRHBYTES,
                              seed.end());

   BOTAN_ASSERT_NOMSG(rho.size() == DilithiumModeConstants::SEEDBYTES);
   BOTAN_ASSERT_NOMSG(rhoprime.size() == DilithiumModeConstants::CRHBYTES);
   BOTAN_ASSERT_NOMSG(key.size() == DilithiumModeConstants::SEEDBYTES);

   /* Sample short vectors s1 and s2 */
   Dilithium::PolynomialVector s1(mode_constants.l());
   Dilithium::PolynomialVector::fill_polyvec_uniform_eta(s1, rhoprime, 0, mode_constants);

   Dilithium::PolynomialVector s2(mode_constants.k());
   Dilithium::PolynomialVector::fill_polyvec_uniform_eta(s2, rhoprime, mode_constants.l(), mode_constants);

   auto [t0, t1] = calculate_t0_and_t1(mode_constants, rho, s1, s2);

   m_public = std::make_shared<Dilithium_PublicKeyInternal>(mode_constants, rho, std::move(t1));

   /* Compute H(rho, t1) == H(pk) and write secret key */
   auto tr = mode_constants.H(m_public->raw_pk(), mode_constants.trbytes());

   m_private = std::make_shared<Dilithium_PrivateKeyInternal>(std::move(mode_constants),
                                                              std::move(rho),
                                                              std::move(tr),
                                                              std::move(key),
                                                              std::move(s1),
                                                              std::move(s2),
                                                              std::move(t0));
}

Dilithium_PrivateKey::Dilithium_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> sk) :
      Dilithium_PrivateKey(sk, DilithiumMode(alg_id.oid())) {}

Dilithium_PrivateKey::Dilithium_PrivateKey(std::span<const uint8_t> sk, DilithiumMode m) {
   DilithiumModeConstants mode_constants(m);
   BOTAN_ARG_CHECK(sk.size() == mode_constants.private_key_bytes(),
                   "dilithium private key does not have the correct byte count");
   m_private = std::make_shared<Dilithium_PrivateKeyInternal>(std::move(mode_constants), sk);
   m_public = std::make_shared<Dilithium_PublicKeyInternal>(
      m_private->mode_constants(), m_private->rho(), m_private->s1(), m_private->s2());
}

secure_vector<uint8_t> Dilithium_PrivateKey::raw_private_key_bits() const {
   return this->private_key_bits();
}

secure_vector<uint8_t> Dilithium_PrivateKey::private_key_bits() const {
   return m_private->raw_sk();
}

std::unique_ptr<PK_Ops::Signature> Dilithium_PrivateKey::create_signature_op(RandomNumberGenerator& rng,
                                                                             std::string_view params,
                                                                             std::string_view provider) const {
   BOTAN_UNUSED(rng);

   BOTAN_ARG_CHECK(params.empty() || params == "Deterministic" || params == "Randomized",
                   "Unexpected parameters for signing with Dilithium");

   const bool randomized = (params == "Randomized");
   if(provider.empty() || provider == "base") {
      return std::make_unique<Dilithium_Signature_Operation>(*this, randomized);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

std::unique_ptr<Public_Key> Dilithium_PrivateKey::public_key() const {
   return std::make_unique<Dilithium_PublicKey>(*this);
}
}  // namespace Botan
