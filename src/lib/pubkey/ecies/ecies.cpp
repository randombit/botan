/*
* ECIES
* (C) 2016 Philipp Weber
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ecies.h>
#include <botan/cipher_mode.h>

#include <botan/internal/ct_utils.h>
#include <botan/internal/pk_ops_impl.h>

namespace Botan {

namespace {

/**
* Private key type for ECIES_ECDH_KA_Operation
*/
class ECIES_PrivateKey : public EC_PrivateKey, public PK_Key_Agreement_Key {
public:
  explicit ECIES_PrivateKey(const ECDH_PrivateKey& private_key) :
    EC_PublicKey(private_key),
    EC_PrivateKey(private_key),
    PK_Key_Agreement_Key(),
    m_key(private_key) {
  }

  std::vector<uint8_t> public_value() const override {
    return m_key.public_value();
  }

  std::string algo_name() const override {
    return "ECIES";
  }

  std::unique_ptr<PK_Ops::Key_Agreement>
  create_key_agreement_op(RandomNumberGenerator& rng,
                          const std::string& params,
                          const std::string& provider) const override;

private:
  ECDH_PrivateKey m_key;
};

/**
* Implements ECDH key agreement without using the cofactor mode
*/
class ECIES_ECDH_KA_Operation : public PK_Ops::Key_Agreement_with_KDF {
public:
  ECIES_ECDH_KA_Operation(const ECIES_PrivateKey& private_key) :
    PK_Ops::Key_Agreement_with_KDF("Raw"),
    m_key(private_key) {
  }

  secure_vector<uint8_t> raw_agree(const uint8_t w[], size_t w_len) override {
    const CurveGFp& curve = m_key.domain().get_curve();
    PointGFp point = OS2ECP(w, w_len, curve);
    PointGFp S = point * m_key.private_value();
    BOTAN_ASSERT(S.on_the_curve(), "ECDH agreed value was on the curve");
    return BigInt::encode_1363(S.get_affine_x(), curve.get_p().bytes());
  }

private:
  ECIES_PrivateKey m_key;
};

std::unique_ptr<PK_Ops::Key_Agreement>
ECIES_PrivateKey::create_key_agreement_op(RandomNumberGenerator& /*rng*/,
    const std::string& /*params*/,
    const std::string& /*provider*/) const {
  return std::unique_ptr<PK_Ops::Key_Agreement>(new ECIES_ECDH_KA_Operation(*this));
}

/**
* Creates a PK_Key_Agreement instance for the given key and ecies_params
* Returns either ECIES_ECDH_KA_Operation or the default implementation for the given key,
* depending on the key and ecies_params
* @param private_key the private key used for the key agreement
* @param ecies_params settings for ecies
* @param for_encryption disable cofactor mode if the secret will be used for encryption
* (according to ISO 18033 cofactor mode is only used during decryption)
*/
PK_Key_Agreement create_key_agreement(const PK_Key_Agreement_Key& private_key,
                                      const ECIES_KA_Params& ecies_params,
                                      bool for_encryption,
                                      RandomNumberGenerator& rng) {
  const ECDH_PrivateKey* ecdh_key = dynamic_cast<const ECDH_PrivateKey*>(&private_key);

  if (ecdh_key == nullptr && (ecies_params.cofactor_mode() || ecies_params.old_cofactor_mode()
                              || ecies_params.check_mode())) {
    // assume we have a private key from an external provider (e.g. pkcs#11):
    // there is no way to determine or control whether the provider uses cofactor mode or not.
    // ISO 18033 does not allow cofactor mode in combination with old cofactor mode or check mode
    // => disable cofactor mode, old cofactor mode and check mode for unknown keys/providers (as a precaution).
    throw Invalid_Argument("ECIES: cofactor, old cofactor and check mode are only supported for ECDH_PrivateKey");
  }

  if (ecdh_key && (for_encryption || !ecies_params.cofactor_mode())) {
    // ECDH_KA_Operation uses cofactor mode: use own key agreement method if cofactor should not be used.
    return PK_Key_Agreement(ECIES_PrivateKey(*ecdh_key), rng, "Raw");
  }

  return PK_Key_Agreement(private_key, rng, "Raw");    // use default implementation
}
}

ECIES_KA_Operation::ECIES_KA_Operation(const PK_Key_Agreement_Key& private_key,
                                       const ECIES_KA_Params& ecies_params,
                                       bool for_encryption,
                                       RandomNumberGenerator& rng) :
  m_ka(create_key_agreement(private_key, ecies_params, for_encryption, rng)),
  m_params(ecies_params) {
}

/**
* ECIES secret derivation according to ISO 18033-2
*/
SymmetricKey ECIES_KA_Operation::derive_secret(const std::vector<uint8_t>& eph_public_key_bin,
    const PointGFp& other_public_key_point) const {
  if (other_public_key_point.is_zero()) {
    throw Invalid_Argument("ECIES: other public key point is zero");
  }

  std::unique_ptr<KDF> kdf = Botan::KDF::create_or_throw(m_params.kdf_spec());

  PointGFp other_point = other_public_key_point;

  // ISO 18033: step b
  if (m_params.old_cofactor_mode()) {
    other_point *= m_params.domain().get_cofactor();
  }

  secure_vector<uint8_t> derivation_input;

  // ISO 18033: encryption step e / decryption step g
  if (!m_params.single_hash_mode()) {
    derivation_input += eph_public_key_bin;
  }

  // ISO 18033: encryption step f / decryption step h
  secure_vector<uint8_t> other_public_key_bin = EC2OSP(other_point, static_cast<uint8_t>(m_params.compression_type()));
  // Note: the argument `m_params.secret_length()` passed for `key_len` will only be used by providers because
  // "Raw" is passed to the `PK_Key_Agreement` if the implementation of botan is used.
  const SymmetricKey peh = m_ka.derive_key(m_params.domain().get_order().bytes(), other_public_key_bin.data(),
                           other_public_key_bin.size());
  derivation_input.insert(derivation_input.end(), peh.begin(), peh.end());

  // ISO 18033: encryption step g / decryption step i
  return kdf->derive_key(m_params.secret_length(), derivation_input);
}


ECIES_KA_Params::ECIES_KA_Params(const EC_Group& domain, const std::string& kdf_spec, size_t length,
                                 PointGFp::Compression_Type compression_type, ECIES_Flags flags) :
  m_domain(domain),
  m_kdf_spec(kdf_spec),
  m_length(length),
  m_compression_mode(compression_type),
  m_flags(flags) {
}

ECIES_System_Params::ECIES_System_Params(const EC_Group& domain, const std::string& kdf_spec,
    const std::string& dem_algo_spec, size_t dem_key_len,
    const std::string& mac_spec, size_t mac_key_len,
    PointGFp::Compression_Type compression_type, ECIES_Flags flags) :
  ECIES_KA_Params(domain, kdf_spec, dem_key_len + mac_key_len, compression_type, flags),
  m_dem_spec(dem_algo_spec),
  m_dem_keylen(dem_key_len),
  m_mac_spec(mac_spec),
  m_mac_keylen(mac_key_len) {
  // ISO 18033: "At most one of CofactorMode, OldCofactorMode, and CheckMode may be 1."
  if (cofactor_mode() + old_cofactor_mode() + check_mode() > 1) {
    throw Invalid_Argument("ECIES: only one of cofactor_mode, old_cofactor_mode and check_mode can be set");
  }
}

ECIES_System_Params::ECIES_System_Params(const EC_Group& domain, const std::string& kdf_spec,
    const std::string& dem_algo_spec, size_t dem_key_len,
    const std::string& mac_spec, size_t mac_key_len) :
  ECIES_System_Params(domain, kdf_spec, dem_algo_spec, dem_key_len, mac_spec, mac_key_len, PointGFp::UNCOMPRESSED,
                      ECIES_Flags::NONE) {
}

std::unique_ptr<MessageAuthenticationCode> ECIES_System_Params::create_mac() const {
  return Botan::MessageAuthenticationCode::create_or_throw(m_mac_spec);
}

std::unique_ptr<Cipher_Mode> ECIES_System_Params::create_cipher(Botan::Cipher_Dir direction) const {
  Cipher_Mode* cipher = get_cipher_mode(m_dem_spec, direction);
  if (cipher == nullptr) {
    throw Algorithm_Not_Found(m_dem_spec);
  }
  return std::unique_ptr<Cipher_Mode>(cipher);
}


/*
* ECIES_Encryptor Constructor
*/
ECIES_Encryptor::ECIES_Encryptor(const PK_Key_Agreement_Key& private_key,
                                 const ECIES_System_Params& ecies_params,
                                 RandomNumberGenerator& rng) :
  m_ka(private_key, ecies_params, true, rng),
  m_params(ecies_params),
  m_eph_public_key_bin(private_key.public_value()),  // returns the uncompressed public key, see conversion below
  m_iv(),
  m_other_point(),
  m_label() {
  if (ecies_params.compression_type() != PointGFp::UNCOMPRESSED) {
    // ISO 18033: step d
    // convert only if necessary; m_eph_public_key_bin has been initialized with the uncompressed format
    m_eph_public_key_bin = unlock(EC2OSP(OS2ECP(m_eph_public_key_bin, m_params.domain().get_curve()),
                                         static_cast<uint8_t>(ecies_params.compression_type())));
  }
}

/*
* ECIES_Encryptor Constructor
*/
ECIES_Encryptor::ECIES_Encryptor(RandomNumberGenerator& rng, const ECIES_System_Params& ecies_params) :
  ECIES_Encryptor(ECDH_PrivateKey(rng, ecies_params.domain()), ecies_params, rng) {
}


/*
* ECIES Encryption according to ISO 18033-2
*/
std::vector<uint8_t> ECIES_Encryptor::enc(const uint8_t data[], size_t length, RandomNumberGenerator&) const {
  if (m_other_point.is_zero()) {
    throw Invalid_State("ECIES: the other key is zero");
  }

  const SymmetricKey secret_key = m_ka.derive_secret(m_eph_public_key_bin, m_other_point);

  // encryption
  std::unique_ptr<Cipher_Mode> cipher = m_params.create_cipher(ENCRYPTION);
  BOTAN_ASSERT(cipher != nullptr, "Cipher is found");

  cipher->set_key(SymmetricKey(secret_key.begin(), m_params.dem_keylen()));
  if (m_iv.size() != 0) {
    cipher->start(m_iv.bits_of());
  }
  secure_vector<uint8_t> encrypted_data(data, data + length);
  cipher->finish(encrypted_data);

  // concat elements
  std::unique_ptr<MessageAuthenticationCode> mac = m_params.create_mac();
  BOTAN_ASSERT(mac != nullptr, "MAC is found");

  secure_vector<uint8_t> out(m_eph_public_key_bin.size() + encrypted_data.size() + mac->output_length());
  buffer_insert(out, 0, m_eph_public_key_bin);
  buffer_insert(out, m_eph_public_key_bin.size(), encrypted_data);

  // mac
  mac->set_key(secret_key.begin() + m_params.dem_keylen(), m_params.mac_keylen());
  mac->update(encrypted_data);
  if (!m_label.empty()) {
    mac->update(m_label);
  }
  mac->final(out.data() + m_eph_public_key_bin.size() + encrypted_data.size());

  return unlock(out);
}


ECIES_Decryptor::ECIES_Decryptor(const PK_Key_Agreement_Key& key,
                                 const ECIES_System_Params& ecies_params,
                                 RandomNumberGenerator& rng) :
  m_ka(key, ecies_params, false, rng),
  m_params(ecies_params),
  m_iv(),
  m_label() {
  // ISO 18033: "If v > 1 and CheckMode = 0, then we must have gcd(u, v) = 1." (v = index, u= order)
  if (!ecies_params.check_mode()) {
    Botan::BigInt cofactor = m_params.domain().get_cofactor();
    if (cofactor > 1 && Botan::gcd(cofactor, m_params.domain().get_order()) != 1) {
      throw Invalid_Argument("ECIES: gcd of cofactor and order must be 1 if check_mode is 0");
    }
  }
}

/**
* ECIES Decryption according to ISO 18033-2
*/
secure_vector<uint8_t> ECIES_Decryptor::do_decrypt(uint8_t& valid_mask, const uint8_t in[], size_t in_len) const {
  size_t point_size = m_params.domain().get_curve().get_p().bytes();
  if (m_params.compression_type() != PointGFp::COMPRESSED) {
    point_size *= 2;    // uncompressed and hybrid contains x AND y
  }
  point_size += 1;     // format byte

  std::unique_ptr<MessageAuthenticationCode> mac = m_params.create_mac();
  BOTAN_ASSERT(mac != nullptr, "MAC is found");

  if (in_len < point_size + mac->output_length()) {
    throw Decoding_Error("ECIES decryption: ciphertext is too short");
  }

  // extract data
  const std::vector<uint8_t> other_public_key_bin(in, in + point_size);  // the received (ephemeral) public key
  const std::vector<uint8_t> encrypted_data(in + point_size, in + in_len - mac->output_length());
  const std::vector<uint8_t> mac_data(in + in_len - mac->output_length(), in + in_len);

  // ISO 18033: step a
  PointGFp other_public_key = OS2ECP(other_public_key_bin, m_params.domain().get_curve());

  // ISO 18033: step b
  if (m_params.check_mode() && !other_public_key.on_the_curve()) {
    throw Decoding_Error("ECIES decryption: received public key is not on the curve");
  }

  // ISO 18033: step e (and step f because get_affine_x (called by ECDH_KA_Operation::raw_agree)
  // throws Illegal_Transformation if the point is zero)
  const SymmetricKey secret_key = m_ka.derive_secret(other_public_key_bin, other_public_key);

  // validate mac
  mac->set_key(secret_key.begin() + m_params.dem_keylen(), m_params.mac_keylen());
  mac->update(encrypted_data);
  if (!m_label.empty()) {
    mac->update(m_label);
  }
  const secure_vector<uint8_t> calculated_mac = mac->final();
  valid_mask = CT::expand_mask<uint8_t>(same_mem(mac_data.data(), calculated_mac.data(), mac_data.size()));

  if (valid_mask) {
    // decrypt data
    std::unique_ptr<Cipher_Mode> cipher = m_params.create_cipher(DECRYPTION);
    BOTAN_ASSERT(cipher != nullptr, "Cipher is found");

    cipher->set_key(SymmetricKey(secret_key.begin(), m_params.dem_keylen()));
    if (m_iv.size() != 0) {
      cipher->start(m_iv.bits_of());
    }

    try {
      // the decryption can fail:
      // e.g. Integrity_Failure is thrown if GCM is used and the message does not have a valid tag
      secure_vector<uint8_t> decrypted_data(encrypted_data.begin(), encrypted_data.end());
      cipher->finish(decrypted_data);
      return decrypted_data;
    }
    catch (...) {
      valid_mask = 0;
    }
  }
  return secure_vector<uint8_t>();
}

}
