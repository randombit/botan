/*
* Sphincs+
* (C) 2023 Jack Lloyd
*     2023 Fabian Albert, René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
**/

#include <botan/sphincsplus.h>
#include <botan/internal/sp_types.h>
#include <botan/internal/sp_hash.h>
#include <botan/internal/sp_fors.h>
#include <botan/internal/sp_xmss.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/internal/stl_util.h>

#include <botan/rng.h>

namespace Botan
{

class SphincsPlus_PublicKeyInternal
   {
   public:
      SphincsPlus_PublicKeyInternal(Sphincs_Parameters params, SphincsPublicSeed public_seed, SphincsXmssRootNode sphincs_root)
         : m_params(std::move(params))
         , m_public_seed(std::move(public_seed))
         , m_sphincs_root(std::move(sphincs_root)) {}

      SphincsPlus_PublicKeyInternal(Sphincs_Parameters params, std::span<const uint8_t> key_bits)
         : m_params(std::move(params))
         {
         if(key_bits.size() != m_params.public_key_bytes())
            {
            throw Decoding_Error("Sphincs Public Key doesn't have the expected length");
            }

         BufferSlicer s(key_bits);
         m_public_seed = s.take_as<SphincsPublicSeed>(params.n());
         m_sphincs_root = s.take_as<SphincsXmssRootNode>(params.n());

         BOTAN_ASSERT_NOMSG(s.empty());
         }

      std::vector<uint8_t> key_bits() const
         {
         return concat_as<std::vector<uint8_t>>(m_public_seed, m_sphincs_root);
         }

      const SphincsPublicSeed& seed() const { return m_public_seed; }
      const SphincsXmssRootNode& root() const { return m_sphincs_root; }
      const Sphincs_Parameters& parameters() const { return m_params; }

   private:
      Sphincs_Parameters m_params;
      SphincsPublicSeed m_public_seed;
      SphincsXmssRootNode m_sphincs_root;
   };

class SphincsPlus_PrivateKeyInternal
   {
   public:
      SphincsPlus_PrivateKeyInternal(SphincsSecretSeed secret_seed, SphincsSecretPRF prf)
         : m_secret_seed(std::move(secret_seed))
         , m_prf(std::move(prf))
         { }

      SphincsPlus_PrivateKeyInternal(const Sphincs_Parameters& params, std::span<const uint8_t> key_bits)
         {
         if(key_bits.size() != params.private_key_bytes() - params.public_key_bytes())
            {
            throw Decoding_Error("Sphincs Private Key doesn't have the expected length");
            }

         BufferSlicer s(key_bits);
         m_secret_seed = s.take_as<SphincsSecretSeed>(params.n());
         m_prf = s.take_as<SphincsSecretPRF>(params.n());

         BOTAN_ASSERT_NOMSG(s.empty());
         }

      const SphincsSecretSeed& seed() const { return m_secret_seed; }
      const SphincsSecretPRF& prf() const { return m_prf; }

      secure_vector<uint8_t> key_bits() const { return concat_as<secure_vector<uint8_t>>(m_secret_seed, m_prf); }

   private:
      SphincsSecretSeed m_secret_seed;
      SphincsSecretPRF m_prf;
   };

SphincsPlus_PublicKey::SphincsPlus_PublicKey(std::span<const uint8_t> pub_key, Sphincs_Parameter_Set type, Sphincs_Hash_Type hash)
   : m_public(std::make_shared<SphincsPlus_PublicKeyInternal>(Sphincs_Parameters::create(type, hash), pub_key)) {}

SphincsPlus_PublicKey::SphincsPlus_PublicKey(const AlgorithmIdentifier& alg_id,
                                             std::span<const uint8_t> key_bits)
   : m_public(std::make_shared<SphincsPlus_PublicKeyInternal>(Sphincs_Parameters::create(alg_id.oid()), key_bits)) {}

SphincsPlus_PublicKey::~SphincsPlus_PublicKey() = default;

size_t SphincsPlus_PublicKey::key_length() const
   {
   return m_public->parameters().n() * 8;
   }

size_t SphincsPlus_PublicKey::estimated_strength() const
   {
   return m_public->parameters().bitsec();
   }

AlgorithmIdentifier SphincsPlus_PublicKey::algorithm_identifier() const
   {
   return m_public->parameters().algorithm_identifier();
   }

OID SphincsPlus_PublicKey::object_identifier() const
   {
   return m_public->parameters().object_identifier();
   }

bool SphincsPlus_PublicKey::check_key(RandomNumberGenerator&, bool) const
   {
   // Nothing to check. It's literally just hashes. :-)
   return true;
   }

std::vector<uint8_t> SphincsPlus_PublicKey::public_key_bits() const
   {
   return m_public->key_bits();
   }

class SphincsPlus_Verification_Operation final : public PK_Ops::Verification
   {
   public:
      SphincsPlus_Verification_Operation(std::shared_ptr<SphincsPlus_PublicKeyInternal> pub_key)
         : m_public(std::move(pub_key))
         , m_hashes(Botan::Sphincs_Hash_Functions::create(m_public->parameters())) {}

      /*
      * Add more data to the message currently being signed
      * @param msg the message
      * @param msg_len the length of msg in bytes
      */
      void update(const uint8_t msg[], size_t msg_len) override
         {
         m_msg_buffer.insert(m_msg_buffer.end(), msg, msg + msg_len);
         }

      /*
      * Perform a verification operation
      * @param rng a random number generator
      */
      bool is_valid_signature(const uint8_t* sig, size_t sig_len) override
         {
         if(sig_len != m_public->parameters().sphincs_signature_bytes())
            {
            return false;
            }

         const auto& p = m_public->parameters();

         BufferSlicer s(std::span(sig, sig_len));
         const auto msg_random = s.take_as<SphincsMessageRandomness>(p.n());
         const auto fors_sig = s.take_as<ForsSignature>(p.fors_signature_bytes());

         WotsPublicKey wots_pk(m_public->parameters().wots_bytes());
         std::vector<uint8_t> leaf(m_public->parameters().n());

         /* This hook allows the hash function instantiation to do whatever
            preparation or computation it needs, based on the public seed. */
         Sphincs_Address wots_addr(Sphincs_Address_Type::WotsHash);
         Sphincs_Address tree_addr(Sphincs_Address_Type::HashTree);
         Sphincs_Address wots_pk_addr(Sphincs_Address_Type::WotsPublicKeyCompression);

         /* Derive the message digest and leaf index from R || PK || M. */
         /* The additional SPX_N is a result of the hash domain separator. */
         auto [mhash, tree_idx, leaf_idx] = m_hashes->H_msg(msg_random, m_public->seed(), m_public->root(), m_msg_buffer);

         /* Layer correctly defaults to 0, so no need to set_layer_addr */
         wots_addr.set_tree(tree_idx).set_keypair(leaf_idx);

         auto root = fors_public_key_from_signature(mhash, fors_sig, m_public->seed(), wots_addr, m_public->parameters(), *m_hashes);

         /* For each subtree.. */
         for (size_t i = 0; i < m_public->parameters().d(); i++)
            {
            tree_addr.set_layer(i);
            tree_addr.set_tree(tree_idx);

            wots_addr.copy_subtree_from(tree_addr);
            wots_addr.set_keypair(leaf_idx);

            wots_pk_addr.copy_keypair_from(wots_addr);

            const auto wots_signature = s.take_as<WotsSignature>(p.wots_bytes());

            wots_pk = wots_public_key_from_signature(root, wots_signature, m_public->seed(), wots_addr, m_public->parameters(), *m_hashes);

            /* Compute the leaf node using the WOTS public key. */
            m_hashes->T(leaf, m_public->seed(), wots_pk_addr, wots_pk);

            /* Compute the root node of this subtree. */
            const auto xmss_auth_path = s.take(m_public->parameters().xmss_tree_height() * m_public->parameters().n());
            compute_root_spec(root, m_public->parameters(), m_public->seed(), *m_hashes, leaf, leaf_idx, 0, xmss_auth_path, m_public->parameters().xmss_tree_height(), tree_addr);

            /* Update the indices for the next layer. */
            leaf_idx = (tree_idx & ((1 << m_public->parameters().xmss_tree_height())-1));
            tree_idx = tree_idx >> m_public->parameters().xmss_tree_height();
            }

         BOTAN_ASSERT_NOMSG(s.empty());

         m_msg_buffer.clear();

         /* Check if the root node equals the root node in the public key. */
         return root == m_public->root();
         }

      std::string hash_function() const override { return m_hashes->msg_hash_function_name(); }

   private:
      std::shared_ptr<SphincsPlus_PublicKeyInternal> m_public;
      std::unique_ptr<Sphincs_Hash_Functions> m_hashes;
      std::vector<uint8_t> m_msg_buffer;
   };

std::unique_ptr<PK_Ops::Verification>
   SphincsPlus_PublicKey::create_verification_op(std::string_view /*params*/,
                                                 std::string_view provider) const
   {
   if(provider.empty() || provider == "base")
      return std::make_unique<SphincsPlus_Verification_Operation>(m_public);
   throw Provider_Not_Found(algo_name(), provider);
   }

std::unique_ptr<PK_Ops::Verification>
   SphincsPlus_PublicKey::create_x509_verification_op(const AlgorithmIdentifier& signature_algorithm,
                                                      std::string_view provider) const
   {
   if(provider.empty() || provider == "base")
      {
      if(signature_algorithm != this->algorithm_identifier())
         throw Decoding_Error("Unexpected AlgorithmIdentifier for SPHINCS+ signature");
      return std::make_unique<SphincsPlus_Verification_Operation>(m_public);
      }
   throw Provider_Not_Found(algo_name(), provider);
   }

bool SphincsPlus_PublicKey::supports_operation(PublicKeyOperation op) const
   {
   return op == PublicKeyOperation::Signature;
   }

namespace {

std::span<const uint8_t> slice_off_public_key(const Sphincs_Parameters& params, std::span<const uint8_t> key_bits)
   {
   // Note: We need to transiently instantiate the `Sphincs_Parameters` object
   //       to know the size of the public/private key. That's slightly
   //       inefficient but was the best we could do. Once we get rid of the
   //       PublicKey-PrivateKey inheritance, we might want to reconsider this
   //       control flow.
   if(key_bits.size() != params.private_key_bytes())
      {
      throw Decoding_Error("Sphincs Private Key doesn't have the expected length");
      }

   return key_bits.subspan(params.private_key_bytes() - params.public_key_bytes());
   }

std::span<const uint8_t> slice_off_public_key(const OID& oid, std::span<const uint8_t> key_bits)
   {
      const auto params = Sphincs_Parameters::create(oid);
      return slice_off_public_key(params, key_bits);
   }

std::span<const uint8_t> slice_off_public_key(const Sphincs_Parameter_Set type, const Sphincs_Hash_Type hash, std::span<const uint8_t> key_bits)
   {
      const auto params = Sphincs_Parameters::create(type, hash);
      return slice_off_public_key(params, key_bits);
   }

}

SphincsPlus_PrivateKey::SphincsPlus_PrivateKey(std::span<const uint8_t> private_key, Sphincs_Parameter_Set type, Sphincs_Hash_Type hash)
   : SphincsPlus_PrivateKey(Sphincs_Parameters::create(type, hash).algorithm_identifier(), private_key)
   {}

SphincsPlus_PrivateKey::SphincsPlus_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits)
   : SphincsPlus_PublicKey(alg_id, slice_off_public_key(alg_id.oid(), key_bits))
   {
   const auto& params = m_public->parameters();
   const auto private_portion_bytes = params.private_key_bytes() - params.public_key_bytes();
   BOTAN_ASSERT_NOMSG(key_bits.size() >= private_portion_bytes);

   m_private.reset(new SphincsPlus_PrivateKeyInternal(params, key_bits.subspan(0, private_portion_bytes)));
   }

SphincsPlus_PrivateKey::SphincsPlus_PrivateKey(RandomNumberGenerator& rng, Sphincs_Parameter_Set type, Sphincs_Hash_Type hash)
   : SphincsPlus_PrivateKey(rng, Sphincs_Parameters::create(type, hash))
   {}

SphincsPlus_PrivateKey::SphincsPlus_PrivateKey(RandomNumberGenerator& rng, Sphincs_Parameters params)
   {
   auto sk_seed = rng.random_vec<SphincsSecretSeed>(params.n());
   auto sk_prf = rng.random_vec<SphincsSecretPRF>(params.n());

   m_private = std::make_shared<SphincsPlus_PrivateKeyInternal>(sk_seed, sk_prf);

   SphincsPublicSeed pub_seed(rng.random_vec(params.n()));
   auto hashes = Sphincs_Hash_Functions::create(params);
   auto root = xmss_gen_root(params, pub_seed, m_private->seed(), *hashes);

   m_public = std::make_shared<SphincsPlus_PublicKeyInternal>(std::move(params), pub_seed, root);
   }

SphincsPlus_PrivateKey::~SphincsPlus_PrivateKey() = default;

secure_vector<uint8_t> SphincsPlus_PrivateKey::private_key_bits() const
   {
   return concat(m_private->key_bits(), m_public->key_bits());
   }

std::unique_ptr<Public_Key> SphincsPlus_PrivateKey::public_key() const
   {
   return std::make_unique<SphincsPlus_PublicKey>(*this);
   }


class SphincsPlus_Signature_Operation final : public PK_Ops::Signature
   {
   public:
      SphincsPlus_Signature_Operation(std::shared_ptr<SphincsPlus_PrivateKeyInternal> private_key,
                                      std::shared_ptr<SphincsPlus_PublicKeyInternal> public_key, bool randomized)
      : m_private(std::move(private_key))
      , m_public(std::move(public_key))
      , m_hashes(Botan::Sphincs_Hash_Functions::create(m_public->parameters())), m_randomized(randomized) {}

      void update(const uint8_t msg[], size_t msg_len) override
         {
         m_msg_buffer.insert(m_msg_buffer.end(), msg, msg + msg_len);
         }

      secure_vector<uint8_t> sign(RandomNumberGenerator& rng) override
         {
            secure_vector<uint8_t> sphincs_sig(m_public->parameters().sphincs_signature_bytes());

            /* Compute the digest randomization value (R of spec). */
            auto msg_random_location = std::span(sphincs_sig).subspan(0, m_public->parameters().n());

            SphincsOptionalRandomness opt_rand(m_public->seed());
            if(m_randomized) {
               opt_rand = rng.random_vec<SphincsOptionalRandomness>(m_public->parameters().n());
            }

            const auto msg_random = m_hashes->PRF_msg(m_private->prf(), opt_rand, m_msg_buffer);
            std::copy(msg_random.begin(), msg_random.end(), msg_random_location.begin());

            /* Derive the message digest and leaf index from R, PK and M. */
            auto [mhash, tree_idx, leaf_idx] = m_hashes->H_msg(msg_random,
                                                      m_public->seed(),
                                                      m_public->root(),
                                                      m_msg_buffer);

            Sphincs_Address wots_addr(Sphincs_Address_Type::WotsHash);
            wots_addr.set_tree(tree_idx).set_keypair(leaf_idx);

            Sphincs_Address tree_addr(Sphincs_Address_Type::HashTree);

            /* Sign the message hash using FORS. */
            auto fors_sig_location = std::span(sphincs_sig).subspan(msg_random_location.size(), m_public->parameters().fors_signature_bytes());

            auto current_xmss_root = fors_sign(fors_sig_location, mhash, m_private->seed(), m_public->seed(), wots_addr, m_public->parameters(), *m_hashes);

            for (size_t i = 0; i < m_public->parameters().d(); i++)
               {
               tree_addr.set_layer(i).set_tree(tree_idx);
               wots_addr.copy_subtree_from(tree_addr).set_keypair(leaf_idx);

               auto xmss_sig_location = std::span(sphincs_sig).subspan(msg_random_location.size() + fors_sig_location.size() +
                                                                     i * (m_public->parameters().xmss_signature_bytes()),
                                                                     m_public->parameters().xmss_signature_bytes());

               current_xmss_root = xmss_sign(xmss_sig_location, current_xmss_root, m_public->seed(), m_private->seed(), wots_addr, tree_addr, leaf_idx, m_public->parameters(), *m_hashes);

               /* Update the indices for the next layer. */
               leaf_idx = (tree_idx & ((1 << m_public->parameters().xmss_tree_height()) - 1));
               tree_idx = tree_idx >> m_public->parameters().xmss_tree_height();
               }

            m_msg_buffer.clear();

            return sphincs_sig;

         }

      size_t signature_length() const override
         {
         return m_public->parameters().sphincs_signature_bytes();
         }

      AlgorithmIdentifier algorithm_identifier() const override
         {
         m_public->parameters().algorithm_identifier();
         }

      std::string hash_function() const override
      {
      return m_hashes->msg_hash_function_name();
      }

   private:
      std::shared_ptr<SphincsPlus_PrivateKeyInternal> m_private;
      std::shared_ptr<SphincsPlus_PublicKeyInternal> m_public;
      std::unique_ptr<Sphincs_Hash_Functions> m_hashes;
      std::vector<uint8_t> m_msg_buffer;
      bool m_randomized;
   };


std::unique_ptr<PK_Ops::Signature>
   SphincsPlus_PrivateKey::create_signature_op(RandomNumberGenerator& rng,
                                               std::string_view params,
                                               std::string_view provider) const
   {
   BOTAN_UNUSED(rng);

   BOTAN_ARG_CHECK(params.empty() || params == "Deterministic" || params == "Randomized",
                   "Unexpected parameters for signing with SPHINCS+");

   const bool randomized = (params == "Randomized");
   if(provider.empty() || provider == "base") // ? ?
      return std::make_unique<SphincsPlus_Signature_Operation>(m_private, m_public, randomized);
   throw Provider_Not_Found(algo_name(), provider);
   }

}