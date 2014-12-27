/*
* Curve25519
* (C) 2014 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_CURVE_25519_H__
#define BOTAN_CURVE_25519_H__

#include <botan/pk_keys.h>
#include <botan/pk_ops.h>

namespace Botan {

class BOTAN_DLL Curve25519_PublicKey : public virtual Public_Key
   {
   public:
      std::string algo_name() const override { return "Curve25519"; }

      size_t estimated_strength() const override { return 128; }

      size_t max_input_bits() const { return 256; }

      bool check_key(RandomNumberGenerator& rng, bool strong) const override;

      AlgorithmIdentifier algorithm_identifier() const override;

      std::vector<byte> x509_subject_public_key() const override;

      std::vector<byte> public_value() const { return unlock(m_public); }

      Curve25519_PublicKey(const AlgorithmIdentifier& alg_id,
                           const secure_vector<byte>& key_bits);

      Curve25519_PublicKey(const secure_vector<byte>& pub) : m_public(pub) {}
   protected:
      Curve25519_PublicKey() {}
      secure_vector<byte> m_public;
   };

class BOTAN_DLL Curve25519_PrivateKey : public Curve25519_PublicKey,
                                        public virtual Private_Key,
                                        public virtual PK_Key_Agreement_Key
   {
   public:
      Curve25519_PrivateKey(const AlgorithmIdentifier& alg_id,
                            const secure_vector<byte>& key_bits,
                            RandomNumberGenerator& rng);

      Curve25519_PrivateKey(RandomNumberGenerator& rng);

      Curve25519_PrivateKey(const secure_vector<byte>& secret_key);

      std::vector<byte> public_value() const override { return Curve25519_PublicKey::public_value(); }

      secure_vector<byte> agree(const byte w[], size_t w_len) const;

      const secure_vector<byte>& get_x() const { return m_private; }

      secure_vector<byte> pkcs8_private_key() const override;

      bool check_key(RandomNumberGenerator& rng, bool strong) const override;
   private:
      secure_vector<byte> m_private;
   };

/**
* Curve25519 operation
*/
class BOTAN_DLL Curve25519_KA_Operation : public PK_Ops::Key_Agreement
   {
   public:
      Curve25519_KA_Operation(const Curve25519_PrivateKey& key) : m_key(key) {}

      secure_vector<byte> agree(const byte w[], size_t w_len)
         {
         return m_key.agree(w, w_len);
         }
   private:
      const Curve25519_PrivateKey& m_key;
   };

/*
* The types above are just wrappers for curve25519_donna, plus defining
* encodings for public and private keys.
*/
int BOTAN_DLL curve25519_donna(uint8_t mypublic[32],
                               const uint8_t secret[32],
                               const uint8_t basepoint[32]);

}

#endif
