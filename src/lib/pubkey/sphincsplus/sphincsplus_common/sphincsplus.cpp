/*
* Sphincs+
* (C) 2023 Jack Lloyd
*     2023 Fabian Albert, René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
**/

#include <botan/sphincsplus.h>

#include <botan/rng.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/internal/sp_fors.h>
#include <botan/internal/sp_hash.h>
#include <botan/internal/sp_hypertree.h>
#include <botan/internal/sp_treehash.h>
#include <botan/internal/sp_types.h>
#include <botan/internal/sp_wots.h>
#include <botan/internal/sp_xmss.h>
#include <botan/internal/stl_util.h>

#if !defined(BOTAN_HAS_SPHINCS_PLUS_WITH_SHA2) and !defined(BOTAN_HAS_SPHINCS_PLUS_WITH_SHAKE)
static_assert(
   false,
   "botan module 'sphincsplus_common' is useful only when enabling at least 'sphincsplus_sha2' or 'sphincsplus_shake'");
#endif

namespace Botan {

class SphincsPlus_PublicKeyInternal final {
   public:
      SphincsPlus_PublicKeyInternal(Sphincs_Parameters params,
                                    SphincsPublicSeed public_seed,
                                    SphincsTreeNode sphincs_root) :
            m_params(params), m_public_seed(std::move(public_seed)), m_sphincs_root(std::move(sphincs_root)) {}

      SphincsPlus_PublicKeyInternal(Sphincs_Parameters params, std::span<const uint8_t> key_bits) : m_params(params) {
         if(key_bits.size() != m_params.public_key_bytes()) {
            throw Decoding_Error("Sphincs Public Key doesn't have the expected length");
         }

         BufferSlicer s(key_bits);
         m_public_seed = s.copy<SphincsPublicSeed>(params.n());
         m_sphincs_root = s.copy<SphincsTreeNode>(params.n());

         BOTAN_ASSERT_NOMSG(s.empty());
      }

      std::vector<uint8_t> key_bits() const { return concat<std::vector<uint8_t>>(m_public_seed, m_sphincs_root); }

      const SphincsPublicSeed& seed() const { return m_public_seed; }

      const SphincsTreeNode& root() const { return m_sphincs_root; }

      const Sphincs_Parameters& parameters() const { return m_params; }

   private:
      Sphincs_Parameters m_params;
      SphincsPublicSeed m_public_seed;
      SphincsTreeNode m_sphincs_root;
};

class SphincsPlus_PrivateKeyInternal final {
   public:
      SphincsPlus_PrivateKeyInternal(SphincsSecretSeed secret_seed, SphincsSecretPRF prf) :
            m_secret_seed(std::move(secret_seed)), m_prf(std::move(prf)) {}

      SphincsPlus_PrivateKeyInternal(const Sphincs_Parameters& params, std::span<const uint8_t> key_bits) {
         if(key_bits.size() != params.private_key_bytes() - params.public_key_bytes()) {
            throw Decoding_Error("Sphincs Private Key doesn't have the expected length");
         }

         BufferSlicer s(key_bits);
         m_secret_seed = s.copy<SphincsSecretSeed>(params.n());
         m_prf = s.copy<SphincsSecretPRF>(params.n());

         BOTAN_ASSERT_NOMSG(s.empty());
      }

      const SphincsSecretSeed& seed() const { return m_secret_seed; }

      const SphincsSecretPRF& prf() const { return m_prf; }

      secure_vector<uint8_t> key_bits() const { return concat<secure_vector<uint8_t>>(m_secret_seed, m_prf); }

   private:
      SphincsSecretSeed m_secret_seed;
      SphincsSecretPRF m_prf;
};

SphincsPlus_PublicKey::SphincsPlus_PublicKey(std::span<const uint8_t> pub_key,
                                             Sphincs_Parameter_Set type,
                                             Sphincs_Hash_Type hash) :
      m_public(std::make_shared<SphincsPlus_PublicKeyInternal>(Sphincs_Parameters::create(type, hash), pub_key)) {}

SphincsPlus_PublicKey::SphincsPlus_PublicKey(std::span<const uint8_t> pub_key, Sphincs_Parameters params) :
      m_public(std::make_shared<SphincsPlus_PublicKeyInternal>(params, pub_key)) {}

SphincsPlus_PublicKey::SphincsPlus_PublicKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) :
      m_public(std::make_shared<SphincsPlus_PublicKeyInternal>(Sphincs_Parameters::create(alg_id.oid()), key_bits)) {}

SphincsPlus_PublicKey::~SphincsPlus_PublicKey() = default;

size_t SphincsPlus_PublicKey::key_length() const {
   return m_public->parameters().n() * 8;
}

size_t SphincsPlus_PublicKey::estimated_strength() const {
   return m_public->parameters().bitsec();
}

AlgorithmIdentifier SphincsPlus_PublicKey::algorithm_identifier() const {
   return m_public->parameters().algorithm_identifier();
}

OID SphincsPlus_PublicKey::object_identifier() const {
   return m_public->parameters().object_identifier();
}

bool SphincsPlus_PublicKey::check_key(RandomNumberGenerator&, bool) const {
   // Nothing to check. It's literally just hashes. :-)
   return true;
}

std::vector<uint8_t> SphincsPlus_PublicKey::raw_public_key_bits() const {
   return m_public->key_bits();
}

std::vector<uint8_t> SphincsPlus_PublicKey::public_key_bits() const {
   // Currently, there isn't a finalized definition of an ASN.1 structure for
   // SPHINCS+ aka SLH-DSA public keys. Therefore, we return the raw public key bits.
   return raw_public_key_bits();
}

std::unique_ptr<Private_Key> SphincsPlus_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<SphincsPlus_PrivateKey>(rng, m_public->parameters());
}

class SphincsPlus_Verification_Operation final : public PK_Ops::Verification {
   public:
      SphincsPlus_Verification_Operation(std::shared_ptr<SphincsPlus_PublicKeyInternal> pub_key) :
            m_public(std::move(pub_key)),
            m_hashes(Botan::Sphincs_Hash_Functions::create(m_public->parameters(), m_public->seed())) {}

      /**
       * Add more data to the message currently being signed
       * @param msg the message
       * @param msg_len the length of msg in bytes
       */
      void update(const uint8_t msg[], size_t msg_len) override {
         m_msg_buffer.insert(m_msg_buffer.end(), msg, msg + msg_len);
      }

      /*
      * Perform a verification operation
      * @param rng a random number generator
      */
      bool is_valid_signature(const uint8_t* sig, size_t sig_len) override {
         const auto& p = m_public->parameters();
         if(sig_len != p.sphincs_signature_bytes()) {
            m_msg_buffer.clear();
            return false;
         }

         BufferSlicer s({sig, sig_len});
         // Compute leaf and tree index from R
         const auto msg_random_s = s.take<SphincsMessageRandomness>(p.n());
         auto [mhash, tree_idx, leaf_idx] = m_hashes->H_msg(msg_random_s, m_public->root(), m_msg_buffer);
         // Clear the message buffer, the data is not needed anymore
         m_msg_buffer.clear();

         // Reconstruct the FORS tree
         Sphincs_Address fors_addr(Sphincs_Address_Type::ForsTree);
         fors_addr.set_tree(tree_idx).set_keypair(leaf_idx);
         const auto fors_sig_s = s.take<ForsSignature>(p.fors_signature_bytes());
         auto fors_root = fors_public_key_from_signature(mhash, fors_sig_s, fors_addr, p, *m_hashes);

         // Verify the hypertree signature
         const auto ht_sig_s = s.take<SphincsHypertreeSignature>(p.ht_signature_bytes());
         BOTAN_ASSERT_NOMSG(s.empty());
         return ht_verify(fors_root, ht_sig_s, m_public->root(), tree_idx, leaf_idx, p, *m_hashes);
      }

      std::string hash_function() const override { return m_hashes->msg_hash_function_name(); }

   private:
      std::shared_ptr<SphincsPlus_PublicKeyInternal> m_public;
      std::unique_ptr<Sphincs_Hash_Functions> m_hashes;
      std::vector<uint8_t> m_msg_buffer;
};

std::unique_ptr<PK_Ops::Verification> SphincsPlus_PublicKey::create_verification_op(std::string_view /*params*/,
                                                                                    std::string_view provider) const {
   if(provider.empty() || provider == "base") {
      return std::make_unique<SphincsPlus_Verification_Operation>(m_public);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

std::unique_ptr<PK_Ops::Verification> SphincsPlus_PublicKey::create_x509_verification_op(
   const AlgorithmIdentifier& signature_algorithm, std::string_view provider) const {
   if(provider.empty() || provider == "base") {
      if(signature_algorithm != this->algorithm_identifier()) {
         throw Decoding_Error("Unexpected AlgorithmIdentifier for SPHINCS+ signature");
      }
      return std::make_unique<SphincsPlus_Verification_Operation>(m_public);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

bool SphincsPlus_PublicKey::supports_operation(PublicKeyOperation op) const {
   return op == PublicKeyOperation::Signature;
}

namespace {

std::span<const uint8_t> slice_off_public_key(const OID& oid, std::span<const uint8_t> key_bits) {
   const auto params = Sphincs_Parameters::create(oid);
   // Note: We need to transiently instantiate the `Sphincs_Parameters` object
   //       to know the size of the public/private key. That's slightly
   //       inefficient but was the best we could do. Once we get rid of the
   //       PublicKey-PrivateKey inheritance, we might want to reconsider this
   //       control flow.
   if(key_bits.size() != params.private_key_bytes()) {
      throw Decoding_Error("Sphincs Private Key doesn't have the expected length");
   }

   return key_bits.subspan(params.private_key_bytes() - params.public_key_bytes());
}

}  // namespace

SphincsPlus_PrivateKey::SphincsPlus_PrivateKey(std::span<const uint8_t> private_key,
                                               Sphincs_Parameter_Set type,
                                               Sphincs_Hash_Type hash) :
      SphincsPlus_PrivateKey(private_key, Sphincs_Parameters::create(type, hash)) {}

SphincsPlus_PrivateKey::SphincsPlus_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) :
      SphincsPlus_PrivateKey(key_bits, Sphincs_Parameters::create(alg_id.oid())) {}

SphincsPlus_PrivateKey::SphincsPlus_PrivateKey(std::span<const uint8_t> private_key, Sphincs_Parameters params) :
      SphincsPlus_PublicKey(slice_off_public_key(params.object_identifier(), private_key), params) {
   const auto private_portion_bytes = params.private_key_bytes() - params.public_key_bytes();
   BOTAN_ASSERT_NOMSG(private_key.size() >= private_portion_bytes);

   m_private = std::make_shared<SphincsPlus_PrivateKeyInternal>(params, private_key.first(private_portion_bytes));
}

SphincsPlus_PrivateKey::SphincsPlus_PrivateKey(RandomNumberGenerator& rng,
                                               Sphincs_Parameter_Set type,
                                               Sphincs_Hash_Type hash) :
      SphincsPlus_PrivateKey(rng, Sphincs_Parameters::create(type, hash)) {}

SphincsPlus_PrivateKey::SphincsPlus_PrivateKey(RandomNumberGenerator& rng, Sphincs_Parameters params) {
   auto sk_seed = rng.random_vec<SphincsSecretSeed>(params.n());
   auto sk_prf = rng.random_vec<SphincsSecretPRF>(params.n());

   m_private = std::make_shared<SphincsPlus_PrivateKeyInternal>(std::move(sk_seed), std::move(sk_prf));

   auto pub_seed = rng.random_vec<SphincsPublicSeed>(params.n());
   auto hashes = Sphincs_Hash_Functions::create(params, pub_seed);
   auto root = xmss_gen_root(params, m_private->seed(), *hashes);

   m_public = std::make_shared<SphincsPlus_PublicKeyInternal>(params, std::move(pub_seed), std::move(root));
}

SphincsPlus_PrivateKey::~SphincsPlus_PrivateKey() = default;

secure_vector<uint8_t> SphincsPlus_PrivateKey::private_key_bits() const {
   return concat(m_private->key_bits(), m_public->key_bits());
}

secure_vector<uint8_t> SphincsPlus_PrivateKey::raw_private_key_bits() const {
   return this->private_key_bits();
}

std::unique_ptr<Public_Key> SphincsPlus_PrivateKey::public_key() const {
   return std::make_unique<SphincsPlus_PublicKey>(*this);
}

class SphincsPlus_Signature_Operation final : public PK_Ops::Signature {
   public:
      SphincsPlus_Signature_Operation(std::shared_ptr<SphincsPlus_PrivateKeyInternal> private_key,
                                      std::shared_ptr<SphincsPlus_PublicKeyInternal> public_key,
                                      bool randomized) :
            m_private(std::move(private_key)),
            m_public(std::move(public_key)),
            m_hashes(Botan::Sphincs_Hash_Functions::create(m_public->parameters(), m_public->seed())),
            m_randomized(randomized) {}

      void update(const uint8_t msg[], size_t msg_len) override {
         m_msg_buffer.insert(m_msg_buffer.end(), msg, msg + msg_len);
      }

      secure_vector<uint8_t> sign(RandomNumberGenerator& rng) override {
         const auto& p = m_public->parameters();

         secure_vector<uint8_t> sphincs_sig_buffer(p.sphincs_signature_bytes());
         BufferStuffer sphincs_sig(sphincs_sig_buffer);

         // Compute and append the digest randomization value (R of spec).
         SphincsOptionalRandomness opt_rand(m_public->seed());
         if(m_randomized) {
            opt_rand = rng.random_vec<SphincsOptionalRandomness>(p.n());
         }
         auto msg_random_s = sphincs_sig.next<SphincsMessageRandomness>(p.n());
         m_hashes->PRF_msg(msg_random_s, m_private->prf(), opt_rand, m_msg_buffer);

         // Derive the message digest and leaf index from R, PK and M.
         auto [mhash, tree_idx, leaf_idx] = m_hashes->H_msg(msg_random_s, m_public->root(), m_msg_buffer);

         // Clear the message buffer, the data is not needed anymore
         m_msg_buffer.clear();

         // Compute and append the FORS signature
         Sphincs_Address fors_addr(Sphincs_Address_Type::ForsTree);
         fors_addr.set_tree(tree_idx).set_keypair(leaf_idx);
         auto fors_root = fors_sign_and_pkgen(sphincs_sig.next<ForsSignature>(p.fors_signature_bytes()),
                                              mhash,
                                              m_private->seed(),
                                              fors_addr,
                                              p,
                                              *m_hashes);

         // Compute and append the XMSS hypertree signature
         ht_sign(sphincs_sig.next<SphincsHypertreeSignature>(p.ht_signature_bytes()),
                 fors_root,
                 m_private->seed(),
                 tree_idx,
                 leaf_idx,
                 p,
                 *m_hashes);

         BOTAN_ASSERT_NOMSG(sphincs_sig.full());
         return sphincs_sig_buffer;
      }

      size_t signature_length() const override { return m_public->parameters().sphincs_signature_bytes(); }

      AlgorithmIdentifier algorithm_identifier() const override {
         return m_public->parameters().algorithm_identifier();
      }

      std::string hash_function() const override { return m_hashes->msg_hash_function_name(); }

   private:
      std::shared_ptr<SphincsPlus_PrivateKeyInternal> m_private;
      std::shared_ptr<SphincsPlus_PublicKeyInternal> m_public;
      std::unique_ptr<Sphincs_Hash_Functions> m_hashes;
      std::vector<uint8_t> m_msg_buffer;
      bool m_randomized;
};

std::unique_ptr<PK_Ops::Signature> SphincsPlus_PrivateKey::create_signature_op(RandomNumberGenerator& rng,
                                                                               std::string_view params,
                                                                               std::string_view provider) const {
   BOTAN_UNUSED(rng);
   BOTAN_ARG_CHECK(params.empty() || params == "Deterministic" || params == "Randomized",
                   "Unexpected parameters for signing with SPHINCS+");

   const bool randomized = (params == "Randomized");
   if(provider.empty() || provider == "base") {
      return std::make_unique<SphincsPlus_Signature_Operation>(m_private, m_public, randomized);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

}  // namespace Botan
