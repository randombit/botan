/*
* PKCS#11 ECDSA
* (C) 2016 Daniel Neus, Sirrix AG
* (C) 2016 Philipp Weber, Sirrix AG
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/p11_ecdsa.h>

#if defined(BOTAN_HAS_ECDSA)

   #include <botan/assert.h>
   #include <botan/p11_mechanism.h>
   #include <botan/pk_ops.h>
   #include <botan/pk_options_readers.h>
   #include <botan/rng.h>
   #include <botan/internal/keypair.h>
   #include <botan/internal/p11_object_guard.h>
   #include <botan/internal/p11_sig_stream.h>
   #include <botan/internal/pk_options_impl.h>

namespace Botan::PKCS11 {

ECDSA_PublicKey PKCS11_ECDSA_PublicKey::export_key() const {
   return ECDSA_PublicKey(domain(), _public_ec_point());
}

bool PKCS11_ECDSA_PrivateKey::check_key(RandomNumberGenerator& rng, bool strong) const {
   if(!strong) {
      return true;
   }

   const ECDSA_PublicKey pubkey(domain(), public_ec_point());
   return KeyPair::signature_consistency_check(rng, *this, pubkey, "SHA-256");
}

ECDSA_PrivateKey PKCS11_ECDSA_PrivateKey::export_key() const {
   auto priv_key = get_attribute_value(AttributeType::Value);

   Null_RNG rng;
   return ECDSA_PrivateKey(rng, domain(), BigInt::from_bytes(priv_key));
}

secure_vector<uint8_t> PKCS11_ECDSA_PrivateKey::private_key_bits() const {
   return export_key().private_key_bits();
}

std::unique_ptr<Public_Key> PKCS11_ECDSA_PrivateKey::public_key() const {
   return std::make_unique<ECDSA_PublicKey>(domain(), public_ec_point());
}

namespace {

/*
* The mechanism hashes the input itself, unless the caller provides the
* digest, in which case the plain CKM_ECDSA mechanism is used
*/
std::string p11_ecdsa_mechanism_hash(const PK_Signature_Options_Reader& options) {
   if(options.using_externally_computed_prehash()) {
      return "Raw";
   }
   return options.hash_function_name();
}

std::string p11_ecdsa_hash_name(const PK_Signature_Options_Reader& options, const MechanismWrapper& mechanism) {
   if(options.using_externally_computed_prehash()) {
      return externally_computed_prehash_name(options).value_or("Raw");
   }

   // Derived from the mechanism so that aliases accepted by
   // create_ecdsa_mechanism are reported under their canonical name
   switch(mechanism.mechanism_type()) {
      case MechanismType::EcdsaSha1:
         return "SHA-1";
      case MechanismType::EcdsaSha224:
         return "SHA-224";
      case MechanismType::EcdsaSha256:
         return "SHA-256";
      case MechanismType::EcdsaSha384:
         return "SHA-384";
      case MechanismType::EcdsaSha512:
         return "SHA-512";
      default:
         return "Raw";
   }
}

class PKCS11_ECDSA_Signature_Operation final : public PK_Ops::Signature {
   public:
      PKCS11_ECDSA_Signature_Operation(const PKCS11_ECDSA_PrivateKey& key, const PK_Signature_Options_Reader& options) :
            PK_Ops::Signature(),
            m_key(key),
            m_order_bytes(key.domain().get_order_bytes()),
            m_mechanism(MechanismWrapper::create_ecdsa_mechanism(p11_ecdsa_mechanism_hash(options))),
            m_hash(p11_ecdsa_hash_name(options, m_mechanism)),
            m_stream(Signature_Stream::Direction::Sign, m_key, m_mechanism) {}

      void update(std::span<const uint8_t> input) override { m_stream.update(input); }

      std::vector<uint8_t> sign(RandomNumberGenerator& /*rng*/) override {
         auto signature = m_stream.sign();
         if(signature.size() != signature_length()) {
            throw PKCS11_Error("PKCS #11 module returned an ECDSA signature of unexpected length");
         }
         return signature;
      }

      size_t signature_length() const override { return 2 * m_order_bytes; }

      AlgorithmIdentifier algorithm_identifier() const override;

      std::string hash_function() const override { return m_hash; }

   private:
      const PKCS11_ECDSA_PrivateKey m_key;
      const size_t m_order_bytes;
      MechanismWrapper m_mechanism;
      const std::string m_hash;
      Signature_Stream m_stream;
};

AlgorithmIdentifier PKCS11_ECDSA_Signature_Operation::algorithm_identifier() const {
   const std::string full_name = "ECDSA/" + hash_function();
   const OID oid = OID::from_string(full_name);
   return AlgorithmIdentifier(oid, AlgorithmIdentifier::USE_EMPTY_PARAM);
}

class PKCS11_ECDSA_Verification_Operation final : public PK_Ops::Verification {
   public:
      PKCS11_ECDSA_Verification_Operation(const PKCS11_ECDSA_PublicKey& key,
                                          const PK_Signature_Options_Reader& options) :
            PK_Ops::Verification(),
            m_key(key),
            m_mechanism(MechanismWrapper::create_ecdsa_mechanism(p11_ecdsa_mechanism_hash(options))),
            m_hash(p11_ecdsa_hash_name(options, m_mechanism)),
            m_stream(Signature_Stream::Direction::Verify, m_key, m_mechanism) {}

      void update(std::span<const uint8_t> input) override { m_stream.update(input); }

      bool is_valid_signature(std::span<const uint8_t> sig) override { return m_stream.verify(sig); }

      std::string hash_function() const override { return m_hash; }

   private:
      const PKCS11_ECDSA_PublicKey m_key;
      MechanismWrapper m_mechanism;
      const std::string m_hash;
      Signature_Stream m_stream;
};

}  // namespace

std::unique_ptr<PK_Ops::Verification> PKCS11_ECDSA_PublicKey::_create_verification_op(
   const PK_Signature_Options_Reader& options) const {
   require_hardware_provider(options, algo_name(), "pkcs11");
   return std::make_unique<PKCS11_ECDSA_Verification_Operation>(*this, options);
}

std::unique_ptr<PK_Ops::Signature> PKCS11_ECDSA_PrivateKey::_create_signature_op(
   RandomNumberGenerator& rng, const PK_Signature_Options_Reader& options) const {
   BOTAN_UNUSED(rng);
   require_hardware_provider(options, algo_name(), "pkcs11");
   return std::make_unique<PKCS11_ECDSA_Signature_Operation>(*this, options);
}

PKCS11_ECDSA_KeyPair generate_ecdsa_keypair(Session& session,
                                            const EC_PublicKeyGenerationProperties& pub_props,
                                            const EC_PrivateKeyGenerationProperties& priv_props) {
   ObjectHandle pub_key_handle = 0;
   ObjectHandle priv_key_handle = 0;

   const Mechanism mechanism = {static_cast<CK_MECHANISM_TYPE>(MechanismType::EcKeyPairGen), nullptr, 0};

   session.module()->C_GenerateKeyPair(session.handle(),
                                       &mechanism,
                                       pub_props.data(),
                                       checked_ulong_cast(pub_props.count()),
                                       priv_props.data(),
                                       checked_ulong_cast(priv_props.count()),
                                       &pub_key_handle,
                                       &priv_key_handle);

   Object_Creation_Guard guard(session, {pub_key_handle, priv_key_handle});
   PKCS11_ECDSA_PublicKey public_key(session, pub_key_handle);  // NOLINT(*-const-correctness) clang-tidy bug
   PKCS11_ECDSA_PrivateKey private_key(session, priv_key_handle);
   // The private key object does not include the public point. Rebind it to
   // the private key's domain since unregistered explicit groups are decoded
   // independently for the two token objects.
   const EC_AffinePoint public_point(private_key.domain(), public_key.raw_public_key_bits());
   private_key.set_public_point(public_point, private_key.point_encoding());
   guard.release();
   return std::make_pair(std::move(public_key), std::move(private_key));
}

}  // namespace Botan::PKCS11

#endif
