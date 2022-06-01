/**
* Composite key pair that exposes the Public/Private key API but combines
* multiple key agreement schemes into a hybrid algorithm.
*
* (C) 2022 Jack Lloyd
*     2022 René Meusel - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <iterator>

#include <botan/ecdh.h>
#include <botan/tls_policy.h>

#include <botan/internal/composite_public_key.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tls_reader.h>

#if defined(BOTAN_HAS_TLS_13_PQC)

#if defined(BOTAN_HAS_CURVE_25519)
  #include <botan/curve25519.h>
#endif

#if defined(BOTAN_HAS_KYBER) || defined(BOTAN_HAS_KYBER_90S)
  #include <botan/kyber.h>
#endif

namespace Botan::TLS {

namespace {

template <typename RetT, typename KeyT, typename ReducerT>
RetT reduce(const std::vector<KeyT>& keys, RetT acc, ReducerT reducer)
   {
   for(const KeyT& key : keys)
      {
      acc = reducer(std::move(acc), key);
      }
   return acc;
   }

}  // namespace

Composite_PublicKey::Composite_PublicKey(std::vector<std::unique_ptr<Public_Key>> pks)
   : m_public_keys(std::move(pks))
   {
   BOTAN_ASSERT_NOMSG(m_public_keys.size() >= 2);
   }

std::string Composite_PublicKey::algo_name() const
   {
   std::string algo_name = "Composite(";
   for(size_t i = 0; i < m_public_keys.size(); ++i)
      {
      algo_name += m_public_keys[i]->algo_name();
      if(i < m_public_keys.size() - 1)
         {
         algo_name += ",";
         }
      }
   algo_name += ")";
   return algo_name;
   }

size_t Composite_PublicKey::estimated_strength() const
   {
   return reduce(m_public_keys, size_t(0), [](size_t es, const auto& key)
      {
      return std::max(es, key->estimated_strength());
      });
   }

size_t Composite_PublicKey::key_length() const
   {
   return reduce(m_public_keys, size_t(0), [](size_t kl, const auto& key)
      {
      return kl + key->key_length();
      });
   }

bool Composite_PublicKey::check_key(RandomNumberGenerator& rng, bool strong) const
   {
   return reduce(m_public_keys, true, [&](bool ckr, const auto& key)
      {
      return ckr && key->check_key(rng, strong);
      });
   }

AlgorithmIdentifier Composite_PublicKey::algorithm_identifier() const
   {
   return {}; // TODO
   }

std::vector<uint8_t> Composite_PublicKey::public_key_bits() const
   {
   return reduce(m_public_keys, std::vector<uint8_t>(), [](auto pkb, const auto& key)
      {
      // draft-ietf-tls-hybrid-design-03 3.2
      //   The values are directly concatenated, without any additional encoding
      //   or length fields; this assumes that the representation and length of
      //   elements is fixed once the algorithm is fixed.  If concatenation were
      //   to be used with values that are not fixed-length, a length prefix or
      //   other unambiguous encoding must be used to ensure that the composition
      //   of the two values is injective.
      //
      // Note: we concatenate the values with two-byte length indicators. That's
      //       what Amazon's s2n-tls implementation is doing as well.
      //  See: https://github.com/aws/s2n-tls/blob/e378cd8260931a87a55aac79574d91de77c7757b/tls/extensions/s2n_client_key_share.c#L321-L348
      append_tls_length_value(pkb, key->public_key_bits(), 2);
      return pkb;
      });
   }

class Composite_KEM_Encryption_Operation final : public PK_Ops::KEM_Encryption_with_KDF
   {
   public:
      Composite_KEM_Encryption_Operation(const Composite_PublicKey& key,
                                         RandomNumberGenerator& rng,
                                         const std::string& kdf,
                                         const std::string& provider) :
         PK_Ops::KEM_Encryption_with_KDF(kdf)
         {
         BOTAN_UNUSED(key, rng, provider);
         // TODO: implement when adding a TLS 1.3 server
         throw Not_Implemented("Composite key encapsulation is not yet implemented");
         }

   private:
      void raw_kem_encrypt(secure_vector<uint8_t>& out_encapsulated_key,
                           secure_vector<uint8_t>& raw_shared_key,
                           Botan::RandomNumberGenerator& rng) override
         {
         BOTAN_UNUSED(out_encapsulated_key, raw_shared_key, rng);
         // TODO: implement when adding a TLS 1.3 server
         throw Not_Implemented("Composite key encapsulation is not yet implemented");
         }
   };

std::unique_ptr<Botan::PK_Ops::KEM_Encryption>
Composite_PublicKey::create_kem_encryption_op(RandomNumberGenerator& rng,
                                              const std::string& kdf,
                                              const std::string& provider) const
   {
   if(provider.empty() || provider == "base")
      return std::make_unique<Composite_KEM_Encryption_Operation>(*this, rng, kdf, provider);
   throw Provider_Not_Found(algo_name(), provider);
   }


namespace {

[[maybe_unused]] std::unique_ptr<ECDH_PrivateKey> make_ec_key(RandomNumberGenerator& rng, EC_Group group)
   {
   auto key = std::make_unique<ECDH_PrivateKey>(rng, group);
   key->set_point_encoding(PointGFp::UNCOMPRESSED);
   return key;
   }

#if defined(BOTAN_HAS_KYBER) || defined(BOTAN_HAS_KYBER_90S)

std::unique_ptr<Kyber_PrivateKey> make_kyber_key(RandomNumberGenerator& rng, KyberMode mode)
   {
   auto key = std::make_unique<Kyber_PrivateKey>(rng, mode);
   key->set_binary_encoding(KyberKeyEncoding::Raw);
   return key;
   }

#endif

}

Composite_PrivateKey::Composite_PrivateKey(RandomNumberGenerator& rng,
                                           Group_Params groups,
                                           const Policy& policy)
   : Composite_PublicKey(groups)
   , m_policy(policy)
   {
   // draft-ietf-tls-hybrid-design-04
   //    The order of shares in the concatenation is the same as the order of
   //    algorithms indicated in the definition of the NamedGroup.
   switch(groups)
      {
#if defined(BOTAN_HAS_KYBER)
#if defined(BOTAN_HAS_CURVE_25519)
      case Group_Params::X25519_KYBER_R3_512:
         m_private_keys.emplace_back(std::make_unique<X25519_PrivateKey>(rng));
         m_private_keys.emplace_back(make_kyber_key(rng, KyberMode::Kyber512));
         break;
#endif

      case Group_Params::SECP256R1_KYBER_R3_512:
         m_private_keys.emplace_back(make_ec_key(rng, EC_Group("secp256r1")));
         m_private_keys.emplace_back(make_kyber_key(rng, KyberMode::Kyber512));
         break;

      case Group_Params::SECP384R1_KYBER_R3_768:
         m_private_keys.emplace_back(make_ec_key(rng, EC_Group("secp384r1")));
         m_private_keys.emplace_back(make_kyber_key(rng, KyberMode::Kyber768));
         break;

      case Group_Params::SECP521R1_KYBER_R3_1024:
         m_private_keys.emplace_back(make_ec_key(rng, EC_Group("secp521r1")));
         m_private_keys.emplace_back(make_kyber_key(rng, KyberMode::Kyber1024));
         break;
#endif

#if defined(BOTAN_HAS_KYBER_90S)
      case Group_Params::SECP256R1_KYBER_90s_R3_512:
         m_private_keys.emplace_back(make_ec_key(rng, EC_Group("secp256r1")));
         m_private_keys.emplace_back(make_kyber_key(rng, KyberMode::Kyber512_90s));
         break;

      case Group_Params::SECP384R1_KYBER_90s_R3_768:
         m_private_keys.emplace_back(make_ec_key(rng, EC_Group("secp384r1")));
         m_private_keys.emplace_back(make_kyber_key(rng, KyberMode::Kyber768_90s));
         break;

      case Group_Params::SECP521R1_KYBER_90s_R3_1024:
         m_private_keys.emplace_back(make_ec_key(rng, EC_Group("secp521r1")));
         m_private_keys.emplace_back(make_kyber_key(rng, KyberMode::Kyber1024_90s));
         break;
#endif

      default:
         throw Invalid_Argument("failed to create a composite private key for " + group_param_to_string(groups));
      }

   BOTAN_ASSERT_NOMSG(m_private_keys.size() >= 2);
   BOTAN_UNUSED(rng);

   m_public_keys = public_keys();
   }

secure_vector<uint8_t> Composite_PrivateKey::private_key_bits() const
   {
   throw Not_Implemented("Composite private keys cannot be serialized");
   }

std::vector<std::unique_ptr<Public_Key>> Composite_PrivateKey::public_keys() const
   {
   std::vector<std::unique_ptr<Public_Key>> pks;
   std::transform(m_private_keys.cbegin(), m_private_keys.cend(), std::back_inserter(pks),
                  [] (const auto &sk) { return sk->public_key(); });
   return pks;
   }

std::unique_ptr<Public_Key> Composite_PrivateKey::public_key() const
   {
   return std::make_unique<Composite_PublicKey>(public_keys());
   }

bool Composite_PrivateKey::check_key(RandomNumberGenerator& rng, bool strong) const
   {
   return reduce(m_public_keys, true, [&](bool ckr, const auto& key)
      {
      return ckr && key->check_key(rng, strong);
      });
   }

class Composite_KEM_Decryption final : public PK_Ops::KEM_Decryption_with_KDF
   {
   public:
      Composite_KEM_Decryption(const Composite_PrivateKey& key,
                               RandomNumberGenerator& rng,
                               const std::string& kdf,
                               const std::string& provider) :
         PK_Ops::KEM_Decryption_with_KDF(kdf),
         m_key(key),
         m_provider(provider),
         m_rng(rng)
         {}

      secure_vector<uint8_t>
      raw_kem_decrypt(const uint8_t encap_key[], size_t len) override
         {
         auto cts = std::vector<uint8_t>(encap_key, encap_key + len);
         TLS_Data_Reader reader("composite ciphertexts", cts);

         std::vector<std::vector<uint8_t>> ciphertexts;
         while(reader.has_remaining())
            {
            ciphertexts.emplace_back(reader.get_tls_length_value(2));
            }

         reader.assert_done();

         return m_key.decapsulate(ciphertexts, m_rng, m_provider);
         }

   private:
      const Composite_PrivateKey& m_key;
      std::string m_provider;
      RandomNumberGenerator& m_rng;
   };

std::unique_ptr<Botan::PK_Ops::KEM_Decryption>
   Composite_PrivateKey::create_kem_decryption_op(RandomNumberGenerator& rng,
                                                  const std::string& kdf,
                                                  const std::string& provider) const
   {
   if(provider.empty() || provider == "base")
      return std::make_unique<Composite_KEM_Decryption>(*this, rng, kdf, provider);
   throw Provider_Not_Found(algo_name(), provider);
   }

secure_vector<uint8_t>
Composite_PrivateKey::decapsulate(const std::vector<std::vector<uint8_t>>& ciphertexts,
                                  RandomNumberGenerator& rng,
                                  const std::string& provider) const
   {
   // draft-ietf-tls-hybrid-design-04
   //    The order of shares in the concatenation is the same as the order of
   //    algorithms indicated in the definition of the NamedGroup.
   if(ciphertexts.size() != m_private_keys.size())
      {
      throw Invalid_Argument("unexpected number of composite ciphertexts: " + std::to_string(ciphertexts.size()));
      }

   std::vector<secure_vector<uint8_t>> shared_secrets;

   std::transform(m_private_keys.cbegin(), m_private_keys.cend(),
                  ciphertexts.cbegin(), std::back_inserter(shared_secrets),
      [&](const auto& private_key, const auto& ciphertext)
         {
         if(private_key->algo_name() == "ECDH")
            {
            auto ecdh_key = dynamic_cast<const ECDH_PrivateKey*>(private_key.get());
            auto group = ecdh_key->domain();
            ECDH_PublicKey peer_key(group, group.OS2ECP(ciphertext));
            m_policy.check_peer_key_acceptable(peer_key);

            return
               PK_Key_Agreement(*private_key, rng, "Raw", provider)
                  .derive_key(0, ciphertext).bits_of();
            }

#if defined(BOTAN_HAS_CURVE_25519)
         if(private_key->algo_name() == "Curve25519")
            {
            Curve25519_PublicKey peer_key(ciphertexts.at(0));
            m_policy.check_peer_key_acceptable(peer_key);

            return
               PK_Key_Agreement(*private_key, rng, "Raw", provider)
                  .derive_key(0, ciphertext).bits_of();
            }
#endif

#if defined(BOTAN_HAS_KYBER) || defined(BOTAN_HAS_KYBER_90S)
         if(private_key->algo_name() == "Kyber-r3")
            {
            return
               PK_KEM_Decryptor(*private_key, rng, "Raw", provider)
                  .decrypt(ciphertext, 0, std::vector<uint8_t>());
            }
#endif

         throw Invalid_State("Encountered an unknown private key");
      });

      // draft-ietf-tls-hybrid-design-04
      //    Here we also take a simple "concatenation approach": the two shared
      //    secrets are concatenated together and used as the shared secret in
      //    the existing TLS 1.3 key schedule.
      return reduce(shared_secrets, secure_vector<uint8_t>(),
         [] (auto acc, const auto& ss) { return concat(acc, ss); });
   }

}  // namespace Botan::TLS

#endif
