#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/kdf.h>
#include <botan/pk_algs.h>
#include <botan/pk_ops.h>
#include <botan/pubkey.h>

#include <iostream>
#include <memory>

/**
 * This class is an example of a custom public-key algorithm in Botan.
 *
 * It combines a classic key exchange algorithm like Diffie-Hellman and a key
 * encapsulation mechanism (KEM) to provide a "hybrid" key encapsulation
 * mechanism (KEM).
 *
 * This approach is useful as an intermediate step towards post-quantum secure
 * cryptography as it combines the historical confidence in a classic algorithm
 * with the future-proofness of a post-quantum algorithm.
 *
 * Other use cases for such a custom public-key algorithm class include:
 *   - adding support for a new public-key algorithm that Botan doesn't support
 *   - writing a wrapper to offload public-key operations to a hardware device
 */
class Hybrid_PublicKey : public virtual Botan::Public_Key {
   public:
      explicit Hybrid_PublicKey(std::unique_ptr<Botan::Public_Key> kex, std::unique_ptr<Botan::Public_Key> kem) :
            m_kex_pk(std::move(kex)), m_kem_pk(std::move(kem)) {
         BOTAN_ASSERT_NONNULL(m_kex_pk);
         BOTAN_ASSERT_NONNULL(m_kem_pk);
         BOTAN_ASSERT_NOMSG(m_kex_pk->supports_operation(Botan::PublicKeyOperation::KeyAgreement));
         BOTAN_ASSERT_NOMSG(m_kem_pk->supports_operation(Botan::PublicKeyOperation::KeyEncapsulation));
      }

      std::string algo_name() const override {
         return "Hybrid-KEM(" + m_kex_pk->algo_name() + "," + m_kem_pk->algo_name() + ")";
      }

      /**
       * This returns an object of a custom sub-class of
       * Botan::PK_Ops::KEM_Encryption. See below for the implementation of that
       * class, where the actual hybrid operation is performed.
       *
       * Note, that applications typically don't call this directly, but they
       * use the Botan::PK_KEM_Encryptor class, which in turn calls this method.
       * See the main() function below for an example.
       */
      std::unique_ptr<Botan::PK_Ops::KEM_Encryption> create_kem_encryption_op(std::string_view params,
                                                                              std::string_view provider) const override;

      /**
       * In an actual implementation, when you want to use this key in a
       * protocol like X.509, this may return an algorithm identifier that fits
       * your needs. For instance, using a custom OID.
       */
      Botan::AlgorithmIdentifier algorithm_identifier() const override {
         throw Botan::Not_Implemented("Hybrid-KEM does not have an algorithm identifier");
      }

      /**
       * In an actual implementation, this may return a serialized
       * representation of the public keys. For instance, a mere concatenation
       * of the two public keys.
       */
      std::vector<uint8_t> raw_public_key_bits() const override {
         throw Botan::Not_Implemented("Raw key serialization is not supported");
      }

      /**
       * In an actual implementation, this may return a serialized
       * representation of the public keys. For instance, using some ASN.1
       * encoding to combine the two public keys.
       */
      std::vector<uint8_t> public_key_bits() const override {
         throw Botan::Not_Implemented("Key serialization is not supported");
      }

      std::unique_ptr<Botan::Private_Key> generate_another(Botan::RandomNumberGenerator& rng) const override;

      bool supports_operation(Botan::PublicKeyOperation op) const override {
         return op == Botan::PublicKeyOperation::KeyEncapsulation;
      }

      size_t estimated_strength() const override {
         return std::max(m_kex_pk->estimated_strength(), m_kem_pk->estimated_strength());
      }

      size_t key_length() const override { return m_kex_pk->key_length() + m_kem_pk->key_length(); }

      bool check_key(Botan::RandomNumberGenerator& rng, bool strong) const override {
         return m_kex_pk->check_key(rng, strong) && m_kem_pk->check_key(rng, strong);
      }

      const Botan::Public_Key& kex_public_key() const { return *m_kex_pk; }

      const Botan::Public_Key& kem_public_key() const { return *m_kem_pk; }

   private:
      std::unique_ptr<Botan::Public_Key> m_kex_pk;
      std::unique_ptr<Botan::Public_Key> m_kem_pk;
};

/**
 * This is the private key class for the custom public-key algorithm.
 */
class Hybrid_PrivateKey : public virtual Botan::Private_Key,
                          public virtual Hybrid_PublicKey {
   public:
      explicit Hybrid_PrivateKey(std::unique_ptr<Botan::Private_Key> kex, std::unique_ptr<Botan::Private_Key> kem) :
            Hybrid_PublicKey(kex->public_key(), kem->public_key()),
            m_kex_sk(std::move(kex)),
            m_kem_sk(std::move(kem)) {}

      /**
       * This returns an object of a custom sub-class of Botan::PK_Ops::KEM_Decryption.
       * See below for the implementation of that class, where the actual hybrid operation
       * is performed.
       *
       * Note, that applications typically don't call this directly, but they
       * use the Botan::PK_KEM_Decryptor class, which in turn calls this method.
       * See the main() function below for an example.
       */
      std::unique_ptr<Botan::PK_Ops::KEM_Decryption> create_kem_decryption_op(Botan::RandomNumberGenerator& rng,
                                                                              std::string_view params,
                                                                              std::string_view provider) const override;

      /**
       * In an actual implementation, this should return a serialized
       * representation of the private keys. For instance, using some ASN.1
       * encoding to combine the two private keys.
       */
      Botan::secure_vector<uint8_t> private_key_bits() const override {
         throw Botan::Not_Implemented("Key serialization is not supported");
      }

      std::unique_ptr<Botan::Public_Key> public_key() const override {
         return std::make_unique<Hybrid_PublicKey>(m_kex_sk->public_key(), m_kem_sk->public_key());
      }

      const Botan::Private_Key& kex_private_key() const { return *m_kex_sk; }

      const Botan::Private_Key& kem_private_key() const { return *m_kem_sk; }

   private:
      std::unique_ptr<Botan::Private_Key> m_kex_sk;
      std::unique_ptr<Botan::Private_Key> m_kem_sk;
};

namespace {

/**
 * This implements the actual hybrid key encapsulation operation. It derives
 * shared secrets from the key exchange algorithm (KEX) and the key
 * encapsulation mechanism (KEM), and combines them using a Key Derivation
 * Function (KDF).
 */
class Hybrid_Encryption_Operation : public Botan::PK_Ops::KEM_Encryption {
   public:
      Hybrid_Encryption_Operation(const Hybrid_PublicKey& hybrid_pk, std::string_view kdf) :
            m_hybrid_pk(hybrid_pk),
            m_kem_encryptor(hybrid_pk.kem_public_key(), "Raw"),
            m_kdf(Botan::KDF::create_or_throw(kdf)) {
         BOTAN_ASSERT_NONNULL(m_kdf);
      }

      /**
       * This returns the length of the encapsulated key in bytes. For such a
       * hybrid key encapsulation, this comprises the length of the KEX's public
       * key (ephemeral key pair) and the length of the KEM's encapsulated key.
       */
      size_t encapsulated_key_length() const override {
         return m_hybrid_pk.kex_public_key().raw_public_key_bits().size() + m_kem_encryptor.encapsulated_key_length();
      }

      /**
       * This returns the length of the output shared secret in bytes. It is
       * the output length of the KDF, which acts as the "combiner" of the
       * shared secrets of both algorithms.
       */
      size_t shared_key_length(size_t desired_shared_key_length) const override { return desired_shared_key_length; }

      /**
       * This method performs the actual hybrid key encapsulation operation.
       */
      void kem_encrypt(std::span<uint8_t> out_encapsed_key,
                       std::span<uint8_t> out_shared_key,
                       Botan::RandomNumberGenerator& rng,
                       size_t desired_shared_key_length,
                       std::span<const uint8_t> salt) override {
         // The basic idea of the hybrid operation:
         //   1. Generate an ephemeral key pair for the key exchange algorithm,
         //   2. and agree on a shared secret using the KEX's public key of the
         //      other party and the ephemeral private key,
         //   3. Encapsulate a shared secret using the KEM's public key of the
         //      other party, resulting in a shared secret and its encapsulation,
         //   4. Concatenate the ephemeral public key and the encapsulation to
         //      form a "hybrid encapsulation" (to be sent to the other party),
         //   5. Concatenate the shared secrets of both algorithms and pass the
         //      result through a user-defined key derivation function to form a
         //      "hybrid shared secret" (to be used by the application).

         // 1. KEX: Generate an ephemeral key pair with the same parameters as
         //         the provided key exchange public key.
         auto ephemeral_keypair = m_hybrid_pk.kex_public_key().generate_another(rng);

         // Note: Currently, we cannot pre-create the PK_Key_Agreement object in
         //       the constructor, because it requires an RNG object.
         //
         // TODO: fix this upstream by harmonizing the constructors of the
         //       PK_Key_Agreement and PK_KEM_Encryptor classes.
         Botan::PK_Key_Agreement kex(*ephemeral_keypair, rng, "Raw");

         // 2. KEX: Agree on a shared secret using the public key of the other
         //         party and our ephemeral private key. The ephemeral public
         //         key acts as the "encapsulation" of the key agreement.
         //
         // Note: kex.derive_key() does not have a std::span<> based overload to
         //       write straight into the output buffer.
         //
         // TODO: kex.derive_key() should allow a std::span<>-based out param,
         //       which would save a copy in this case. (See GH #3318)
         const auto kex_shared_key =
            kex.derive_key(0 /* no KDF */, m_hybrid_pk.kex_public_key().raw_public_key_bits()).bits_of();
         const auto kex_encapsed_key = ephemeral_keypair->raw_public_key_bits();

         // 3. KEX: Encapsulate a shared secret using the KEM's public key,
         //         yielding a shared secret and its encapsulation.
         const auto [kem_encapsed_key, kem_shared_key] =
            Botan::KEM_Encapsulation::destructure(m_kem_encryptor.encrypt(rng));

         // 4. Hybrid: Concatenate the ephemeral public key and the KEM's
         //            encapsulation to form a combined "hybrid encapsulation".
         BOTAN_ASSERT_NOMSG(out_encapsed_key.size() == kex_encapsed_key.size() + kem_encapsed_key.size());
         std::copy(kex_encapsed_key.begin(), kex_encapsed_key.end(), out_encapsed_key.begin());
         std::copy(
            kem_encapsed_key.begin(), kem_encapsed_key.end(), out_encapsed_key.begin() + kex_encapsed_key.size());

         // 5. Hybrid: Combine the shared secrets of both algorithms.
         Botan::secure_vector<uint8_t> concat_shared_key;
         concat_shared_key.insert(concat_shared_key.end(), kex_shared_key.begin(), kex_shared_key.end());
         concat_shared_key.insert(concat_shared_key.end(), kem_shared_key.begin(), kem_shared_key.end());

         BOTAN_ASSERT_NOMSG(out_shared_key.size() >= desired_shared_key_length);
         m_kdf->derive_key(out_shared_key.first(desired_shared_key_length), concat_shared_key, salt, {});
      }

   private:
      const Hybrid_PublicKey& m_hybrid_pk;
      Botan::PK_KEM_Encryptor m_kem_encryptor;
      const std::unique_ptr<Botan::KDF> m_kdf;
};

/**
 * This implements the actual hybrid key decapsulation operation. It derives
 * the shared secrets from the key exchange algorithm (KEX) and the key
 * encapsulation mechanism (KEM), and combines them using a Key Derivation
 * Function (KDF).
 */
class Hybrid_Decryption_Operation : public Botan::PK_Ops::KEM_Decryption {
   public:
      Hybrid_Decryption_Operation(const Hybrid_PrivateKey& hybrid_sk,
                                  Botan::RandomNumberGenerator& rng,
                                  std::string_view kdf) :
            m_hybrid_sk(hybrid_sk),
            m_key_agreement(hybrid_sk.kex_private_key(), rng, "Raw"),
            m_kem_decryptor(hybrid_sk.kem_private_key(), rng, "Raw"),
            m_kdf(Botan::KDF::create_or_throw(kdf)) {
         BOTAN_ASSERT_NONNULL(m_kdf);
      }

      /**
       * This returns the length of the encapsulated key in bytes. For such a
       * hybrid key encapsulation, this comprises the length of the KEX's public
       * key (ephemeral key pair) and the length of the KEM's encapsulated key.
       */
      size_t encapsulated_key_length() const override {
         return m_hybrid_sk.kex_public_key().raw_public_key_bits().size() + m_kem_decryptor.encapsulated_key_length();
      }

      /**
       * This returns the length of the output shared secret in bytes. It is
       * the output length of the KDF, which acts as the "combiner" of the
       * shared secrets of both algorithms.
       */
      size_t shared_key_length(size_t desired_shared_key_length) const override { return desired_shared_key_length; }

      /**
       * This method performs the actual hybrid key decapsulation operation.
       */
      void kem_decrypt(std::span<uint8_t> out_shared_key,
                       std::span<const uint8_t> encapsulated_key,
                       size_t desired_shared_key_length,
                       std::span<const uint8_t> salt) override {
         BOTAN_ASSERT_NOMSG(encapsulated_key.size() == encapsulated_key_length());

         // The basic idea of the hybrid operation:
         //  1. Extract the ephemeral public key and the KEM's encapsulation
         //     from the hybrid encapsulation,
         //  2. Agree on a shared secret using the KEX's private key and the
         //     ephemeral public key (from the other party),
         //  3. Decapsulate a shared secret using the KEM's private key and
         //     the KEM's encapsulation (from the other party),
         //  4. Concatenate the shared secrets of both algorithms and pass the
         //     result through a user-defined key derivation function to form a
         //     "hybrid shared secret" (to be used by the application).

         // 1. Hybrid: Extract the ephemeral public key and the encapsulation.
         const auto kex_encapsed_key =
            encapsulated_key.subspan(0, m_hybrid_sk.kex_public_key().raw_public_key_bits().size());
         const auto kem_encapsed_key = encapsulated_key.subspan(kex_encapsed_key.size());

         // 2. KEX: Agree on a shared secret using the KEX's private key and the
         //         ephemeral public key of the other party.
         const auto kex_shared_key = m_key_agreement.derive_key(0 /* no KDF */, kex_encapsed_key).bits_of();

         // 3. KEM: Decapsulate a shared secret using the KEM's private key and
         //         the encapsulation of the other party.
         const auto kem_shared_key = m_kem_decryptor.decrypt(kem_encapsed_key);

         // 4. Hybrid: Combine the shared secrets of both algorithms.
         Botan::secure_vector<uint8_t> concat_shared_key;
         concat_shared_key.insert(concat_shared_key.end(), kex_shared_key.begin(), kex_shared_key.end());
         concat_shared_key.insert(concat_shared_key.end(), kem_shared_key.begin(), kem_shared_key.end());

         BOTAN_ASSERT_NOMSG(out_shared_key.size() >= desired_shared_key_length);
         m_kdf->derive_key(out_shared_key.first(desired_shared_key_length), concat_shared_key, salt, {});
      }

   private:
      const Hybrid_PrivateKey& m_hybrid_sk;
      Botan::PK_Key_Agreement m_key_agreement;
      Botan::PK_KEM_Decryptor m_kem_decryptor;
      std::unique_ptr<Botan::KDF> m_kdf;
};

}  // namespace

std::unique_ptr<Botan::PK_Ops::KEM_Encryption> Hybrid_PublicKey::create_kem_encryption_op(std::string_view params,
                                                                                          std::string_view) const {
   return std::make_unique<Hybrid_Encryption_Operation>(*this, params);
}

std::unique_ptr<Botan::PK_Ops::KEM_Decryption> Hybrid_PrivateKey::create_kem_decryption_op(
   Botan::RandomNumberGenerator& rng, std::string_view params, std::string_view) const {
   return std::make_unique<Hybrid_Decryption_Operation>(*this, rng, params);
}

std::unique_ptr<Botan::Private_Key> Hybrid_PublicKey::generate_another(Botan::RandomNumberGenerator& rng) const {
   return std::make_unique<Hybrid_PrivateKey>(m_kex_pk->generate_another(rng), m_kem_pk->generate_another(rng));
}

int main() {
   Botan::AutoSeeded_RNG rng;

   // Alice generates two key pairs suitable for:
   //   1) key exchange (X25519), and
   //   2) key encapsulation (Kyber).
   //
   // She then combines them into a custom "hybrid" key pair that acts
   // like a key encapsulation mechanism (KEM).
   const auto private_key_of_alice = std::make_unique<Hybrid_PrivateKey>(
      Botan::create_private_key("X25519", rng), Botan::create_private_key("Kyber", rng, "Kyber-768-r3"));
   const auto public_key_of_alice = private_key_of_alice->public_key();

   // Bob uses Alice's public key to encapsulate a shared secret, and
   // derives a shared key from it using HKDF.
   Botan::PK_KEM_Encryptor kem_enc(*public_key_of_alice, "HKDF(SHA-256)");
   const auto encapsulation_by_bob = kem_enc.encrypt(rng);

   // Alice decapsulates the shared secret from Bob's encapsulation using her
   // private key, and derives a matching shared key using HKDF.
   Botan::PK_KEM_Decryptor kem_dec(*private_key_of_alice, rng, "HKDF(SHA-256)");
   const auto shared_key = kem_dec.decrypt(encapsulation_by_bob.encapsulated_shared_key());

   // Check that Alice and Bob now share the same secret
   std::cout << "Alice's shared key: " << Botan::hex_encode(shared_key) << "\n"
             << "Bob's shared key:   " << Botan::hex_encode(encapsulation_by_bob.shared_key()) << "\n";

   if(shared_key == encapsulation_by_bob.shared_key()) {
      std::cout << '\n' << "Alice and Bob share the same secret!\n";
      return 0;
   } else {
      return 1;
   }
}
