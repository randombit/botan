/*
 * FrodoKEM implemenation
 * Based on the MIT licensed reference implementation by the designers
 * (https://github.com/microsoft/PQCrypto-LWEKE/tree/master/src)
 *
 * The Fellowship of the FrodoKEM:
 * (C) 2023 Jack Lloyd
 *     2023 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/frodokem.h>

#include <botan/assert.h>
#include <botan/hex.h>
#include <botan/rng.h>
#include <botan/xof.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/frodo_constants.h>
#include <botan/internal/frodo_matrix.h>
#include <botan/internal/frodo_types.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/internal/stl_util.h>

#include <algorithm>
#include <memory>
#include <tuple>
#include <vector>

namespace Botan {

class FrodoKEM_PublicKeyInternal {
   public:
      FrodoKEM_PublicKeyInternal(FrodoKEMConstants constants, FrodoSeedA seed_a, FrodoMatrix b) :
            m_constants(std::move(constants)), m_seed_a(std::move(seed_a)), m_b(std::move(b)) {
         auto& shake = m_constants.SHAKE_XOF();
         shake.update(serialize());
         m_hash = shake.output<FrodoPublicKeyHash>(m_constants.len_sec_bytes());
      }

      const FrodoKEMConstants& constants() const { return m_constants; }

      const FrodoSeedA& seed_a() const { return m_seed_a; }

      const FrodoMatrix& b() const { return m_b; }

      const FrodoPublicKeyHash& hash() const { return m_hash; }

      std::vector<uint8_t> serialize() const { return concat<std::vector<uint8_t>>(seed_a(), b().pack(m_constants)); }

   private:
      FrodoKEMConstants m_constants;
      FrodoSeedA m_seed_a;
      FrodoMatrix m_b;
      FrodoPublicKeyHash m_hash;
};

class FrodoKEM_PrivateKeyInternal {
   public:
      FrodoKEM_PrivateKeyInternal(FrodoSeedS s, FrodoMatrix s_trans) :
            m_s(std::move(s)), m_s_trans(std::move(s_trans)) {}

      const FrodoSeedS& s() const { return m_s; }

      const FrodoMatrix& s_trans() const { return m_s_trans; }

   private:
      FrodoSeedS m_s;
      FrodoMatrix m_s_trans;
};

//
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
//

class Frodo_KEM_Encryptor final : public PK_Ops::KEM_Encryption_with_KDF {
   public:
      Frodo_KEM_Encryptor(std::shared_ptr<FrodoKEM_PublicKeyInternal> key, std::string_view kdf) :
            KEM_Encryption_with_KDF(kdf), m_public_key(std::move(key)) {}

      size_t raw_kem_shared_key_length() const override { return m_public_key->constants().len_sec_bytes(); }

      size_t encapsulated_key_length() const override { return m_public_key->constants().len_ct_bytes(); }

      void raw_kem_encrypt(std::span<uint8_t> out_encapsulated_key,
                           std::span<uint8_t> out_shared_key,
                           RandomNumberGenerator& rng) override {
         const auto& consts = m_public_key->constants();
         auto& shake = consts.SHAKE_XOF();
         auto sample_generator = FrodoMatrix::make_sample_generator(consts, shake);

         BufferStuffer out_ct_bs(out_encapsulated_key);

         auto c_1 = out_ct_bs.next<FrodoPackedMatrix>(consts.len_packed_b_bytes());
         auto c_2 = out_ct_bs.next<FrodoPackedMatrix>(consts.len_packed_c_bytes());
         auto salt = out_ct_bs.next<FrodoSalt>(consts.len_salt_bytes());

         BOTAN_ASSERT_NOMSG(out_ct_bs.full());

         const auto u = rng.random_vec<FrodoPlaintext>(consts.len_sec_bytes());
         rng.randomize(salt);

         shake.update(m_public_key->hash());
         shake.update(u);
         shake.update(salt);
         const auto seed_se = shake.output<FrodoSeedSE>(consts.len_se_bytes());
         const auto k = shake.output<FrodoIntermediateSharedSecret>(consts.len_sec_bytes());
         shake.clear();

         shake.update(consts.encapsulation_domain_separator());
         shake.update(seed_se);

         const auto s_p = sample_generator(std::tuple(consts.n_bar(), consts.n()));

         const auto e_p = sample_generator(std::tuple(consts.n_bar(), consts.n()));

         const auto b_p = FrodoMatrix::mul_add_sa_plus_e(consts, s_p, e_p, m_public_key->seed_a());

         b_p.pack(consts, c_1);

         const auto e_pp = sample_generator(std::tuple(consts.n_bar(), consts.n_bar()));
         shake.clear();

         const auto v = FrodoMatrix::mul_add_sb_plus_e(consts, m_public_key->b(), s_p, e_pp);

         const auto encoded = FrodoMatrix::encode(consts, u);

         const auto c = FrodoMatrix::add(consts, v, encoded);

         c.pack(consts, c_2);

         shake.update(out_encapsulated_key);
         shake.update(k);
         shake.output(out_shared_key);
      }

   private:
      std::shared_ptr<FrodoKEM_PublicKeyInternal> m_public_key;
};

class Frodo_KEM_Decryptor final : public PK_Ops::KEM_Decryption_with_KDF {
   public:
      Frodo_KEM_Decryptor(std::shared_ptr<FrodoKEM_PublicKeyInternal> public_key,
                          std::shared_ptr<FrodoKEM_PrivateKeyInternal> private_key,
                          std::string_view kdf) :
            KEM_Decryption_with_KDF(kdf), m_public_key(std::move(public_key)), m_private_key(std::move(private_key)) {}

      size_t raw_kem_shared_key_length() const override { return m_public_key->constants().len_sec_bytes(); }

      size_t encapsulated_key_length() const override { return m_public_key->constants().len_ct_bytes(); }

      void raw_kem_decrypt(std::span<uint8_t> out_shared_key, std::span<const uint8_t> encapsulated_key) override {
         const auto& consts = m_public_key->constants();
         auto& shake = consts.SHAKE_XOF();
         auto sample_generator = FrodoMatrix::make_sample_generator(consts, shake);

         if(encapsulated_key.size() != consts.len_ct_bytes()) {
            throw Invalid_Argument("FrodoKEM ciphertext does not have the correct byte count");
         }

         BufferSlicer ct_bs(encapsulated_key);
         auto c_1 = ct_bs.take<FrodoPackedMatrix>(consts.len_packed_b_bytes());
         auto c_2 = ct_bs.take<FrodoPackedMatrix>(consts.len_packed_c_bytes());
         auto salt = ct_bs.take<FrodoSalt>(consts.len_salt_bytes());
         BOTAN_ASSERT_NOMSG(ct_bs.empty());

         const auto b_p = FrodoMatrix::unpack(consts, {consts.n_bar(), consts.n()}, c_1);
         const auto c = FrodoMatrix::unpack(consts, {consts.n_bar(), consts.n_bar()}, c_2);

         const auto w = FrodoMatrix::mul_bs(consts, b_p, m_private_key->s_trans());
         const auto m = FrodoMatrix::sub(consts, c, w);

         const auto seed_u_p = m.decode(consts);

         shake.update(m_public_key->hash());
         shake.update(seed_u_p);
         shake.update(salt);

         const auto seed_se_p = shake.output<FrodoSeedSE>(consts.len_se_bytes());
         const auto k_p = shake.output<FrodoIntermediateSharedSecret>(consts.len_sec_bytes());
         shake.clear();

         shake.update(consts.encapsulation_domain_separator());
         shake.update(seed_se_p);
         const auto s_p = sample_generator(std::tuple(consts.n_bar(), consts.n()));

         const auto e_p = sample_generator(std::tuple(consts.n_bar(), consts.n()));

         auto b_pp = FrodoMatrix::mul_add_sa_plus_e(consts, s_p, e_p, m_public_key->seed_a());

         const auto e_pp = sample_generator(std::tuple(consts.n_bar(), consts.n_bar()));
         shake.clear();

         const auto v = FrodoMatrix::mul_add_sb_plus_e(consts, m_public_key->b(), s_p, e_pp);

         const auto encoded = FrodoMatrix::encode(consts, seed_u_p);
         auto c_p = FrodoMatrix::add(consts, v, encoded);

         // b_p and c are unpacked values that are reduced by definition.
         // b_pp and c_p are calculated values that need the reduction for
         // an unambiguous comparison that is required next.
         b_pp.reduce(consts);
         c_p.reduce(consts);

         // The spec concats the matrices b_p and c (b_pp and c_p respectively)
         // and performs a single CT comparison. For convenience we compare the
         // matrices individually in CT and CT-&& the resulting masks.
         const auto cmp = b_p.constant_time_compare(b_pp) & c.constant_time_compare(c_p);

         std::vector<uint8_t> k_bar(consts.len_sec_bytes(), 0);
         CT::conditional_copy_mem(cmp, k_bar.data(), k_p.data(), m_private_key->s().data(), consts.len_sec_bytes());

         shake.update(encapsulated_key);
         shake.update(k_bar);
         shake.output(out_shared_key);
      }

   private:
      std::shared_ptr<FrodoKEM_PublicKeyInternal> m_public_key;
      std::shared_ptr<FrodoKEM_PrivateKeyInternal> m_private_key;
};

//
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
//

FrodoKEM_PublicKey::FrodoKEM_PublicKey(std::span<const uint8_t> pub_key, FrodoKEMMode mode) {
   FrodoKEMConstants consts(mode);
   if(pub_key.size() != consts.len_public_key_bytes()) {
      throw Invalid_Argument("FrodoKEM public key does not have the correct byte count");
   }

   BufferSlicer pk_bs(pub_key);
   auto seed_a = pk_bs.copy<FrodoSeedA>(consts.len_a_bytes());
   const auto packed_b = pk_bs.take<FrodoPackedMatrix>(consts.d() * consts.n() * consts.n_bar() / 8);
   BOTAN_ASSERT_NOMSG(pk_bs.empty());

   auto b = FrodoMatrix::unpack(consts, std::tuple(consts.n(), consts.n_bar()), packed_b);

   m_public = std::make_shared<FrodoKEM_PublicKeyInternal>(std::move(consts), std::move(seed_a), std::move(b));
}

FrodoKEM_PublicKey::FrodoKEM_PublicKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) :
      FrodoKEM_PublicKey(key_bits, FrodoKEMMode(alg_id.oid())) {}

FrodoKEM_PublicKey::FrodoKEM_PublicKey(const FrodoKEM_PublicKey& other) {
   m_public = std::make_shared<FrodoKEM_PublicKeyInternal>(
      other.m_public->constants(), other.m_public->seed_a(), other.m_public->b());
}

FrodoKEM_PublicKey& FrodoKEM_PublicKey::operator=(const FrodoKEM_PublicKey& other) {
   if(this != &other) {
      m_public = std::make_shared<FrodoKEM_PublicKeyInternal>(
         other.m_public->constants(), other.m_public->seed_a(), other.m_public->b());
   }
   return *this;
}

AlgorithmIdentifier FrodoKEM_PublicKey::algorithm_identifier() const {
   return AlgorithmIdentifier(object_identifier(), AlgorithmIdentifier::USE_EMPTY_PARAM);
}

OID FrodoKEM_PublicKey::object_identifier() const {
   return m_public->constants().mode().object_identifier();
}

size_t FrodoKEM_PublicKey::key_length() const {
   return m_public->constants().n();
}

size_t FrodoKEM_PublicKey::estimated_strength() const {
   return m_public->constants().estimated_strength();
}

std::vector<uint8_t> FrodoKEM_PublicKey::raw_public_key_bits() const {
   return concat<std::vector<uint8_t>>(m_public->seed_a(), m_public->b().pack(m_public->constants()));
}

std::vector<uint8_t> FrodoKEM_PublicKey::public_key_bits() const {
   // Currently, there isn't a finalized definition of an ASN.1 structure for
   // FrodoKEM public keys. Therefore, we return the raw public key bits.
   return raw_public_key_bits();
}

bool FrodoKEM_PublicKey::check_key(RandomNumberGenerator&, bool) const {
   return true;
}

std::unique_ptr<Private_Key> FrodoKEM_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<FrodoKEM_PrivateKey>(rng, m_public->constants().mode());
}

std::unique_ptr<PK_Ops::KEM_Encryption> FrodoKEM_PublicKey::create_kem_encryption_op(std::string_view params,
                                                                                     std::string_view provider) const {
   if(provider.empty() || provider == "base") {
      return std::make_unique<Frodo_KEM_Encryptor>(m_public, params);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

//
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
//

FrodoKEM_PrivateKey::FrodoKEM_PrivateKey(RandomNumberGenerator& rng, FrodoKEMMode mode) {
   FrodoKEMConstants consts(mode);
   auto& shake = consts.SHAKE_XOF();
   auto sample_generator = FrodoMatrix::make_sample_generator(consts, shake);

   auto s = rng.random_vec<FrodoSeedS>(consts.len_sec_bytes());
   const auto seed_se = rng.random_vec<FrodoSeedSE>(consts.len_se_bytes());
   const auto z = rng.random_vec<FrodoSeedZ>(consts.len_a_bytes());

   shake.update(z);
   auto seed_a = shake.output<FrodoSeedA>(consts.len_a_bytes());
   shake.clear();

   shake.update(consts.keygen_domain_separator());
   shake.update(seed_se);

   auto s_trans = sample_generator(std::tuple(consts.n_bar(), consts.n()));
   auto e = sample_generator(std::tuple(consts.n(), consts.n_bar()));

   auto b = FrodoMatrix::mul_add_as_plus_e(consts, s_trans, e, seed_a);

   m_public = std::make_shared<FrodoKEM_PublicKeyInternal>(std::move(consts), std::move(seed_a), std::move(b));
   m_private = std::make_shared<FrodoKEM_PrivateKeyInternal>(std::move(s), std::move(s_trans));
}

FrodoKEM_PrivateKey::FrodoKEM_PrivateKey(std::span<const uint8_t> sk, FrodoKEMMode mode) {
   FrodoKEMConstants consts(mode);

   if(sk.size() != consts.len_private_key_bytes()) {
      throw Invalid_Argument("FrodoKEM private key does not have the correct byte count");
   }

   BufferSlicer sk_bs(sk);
   auto s = sk_bs.copy<FrodoSeedS>(consts.len_sec_bytes());
   auto seed_a = sk_bs.copy<FrodoSeedA>(consts.len_a_bytes());
   const auto packed_b = sk_bs.take<FrodoPackedMatrix>(consts.d() * consts.n() * consts.n_bar() / 8);
   const auto s_trans_bytes = sk_bs.take<FrodoSerializedMatrix>(consts.n_bar() * consts.n() * 2);
   const auto pkh = sk_bs.copy<FrodoPublicKeyHash>(consts.len_sec_bytes());
   BOTAN_ASSERT_NOMSG(sk_bs.empty());

   auto b = FrodoMatrix::unpack(consts, std::tuple(consts.n(), consts.n_bar()), packed_b);
   auto s_trans = FrodoMatrix::deserialize({consts.n_bar(), consts.n()}, s_trans_bytes);

   m_public = std::make_shared<FrodoKEM_PublicKeyInternal>(std::move(consts), std::move(seed_a), std::move(b));
   m_private = std::make_shared<FrodoKEM_PrivateKeyInternal>(std::move(s), std::move(s_trans));

   BOTAN_STATE_CHECK(pkh == m_public->hash());
}

FrodoKEM_PrivateKey::FrodoKEM_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) :
      FrodoKEM_PrivateKey(key_bits, FrodoKEMMode(alg_id.oid())) {}

std::unique_ptr<Public_Key> FrodoKEM_PrivateKey::public_key() const {
   return std::make_unique<FrodoKEM_PublicKey>(*this);
}

secure_vector<uint8_t> FrodoKEM_PrivateKey::private_key_bits() const {
   return raw_private_key_bits();  // TODO: check if we need to do something else here
}

secure_vector<uint8_t> FrodoKEM_PrivateKey::raw_private_key_bits() const {
   return concat<secure_vector<uint8_t>>(m_private->s(),
                                         m_public->seed_a(),
                                         m_public->b().pack(m_public->constants()),
                                         m_private->s_trans().serialize(),
                                         m_public->hash());
}

std::unique_ptr<PK_Ops::KEM_Decryption> FrodoKEM_PrivateKey::create_kem_decryption_op(RandomNumberGenerator& rng,
                                                                                      std::string_view params,
                                                                                      std::string_view provider) const {
   BOTAN_UNUSED(rng);
   if(provider.empty() || provider == "base") {
      return std::make_unique<Frodo_KEM_Decryptor>(m_public, m_private, params);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

}  // namespace Botan
