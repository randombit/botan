/**
* (C) 2014 cryptosource GmbH
* (C) 2014 Falko Strenzke fstrenzke@cryptosource.de
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*
*/

#include <botan/internal/mce_internal.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/internal/pk_utils.h>

namespace Botan {

class MCE_KEM_Encryptor : public PK_Ops::KEM_Encryption_with_KDF
   {
   public:
      typedef McEliece_PublicKey Key_Type;

      MCE_KEM_Encryptor(const McEliece_PublicKey& key,
                        const std::string& kdf) :
         KEM_Encryption_with_KDF(kdf), m_key(key) {}

   private:
      void raw_kem_encrypt(secure_vector<byte>& out_encapsulated_key,
                           secure_vector<byte>& raw_shared_key,
                           Botan::RandomNumberGenerator& rng) override
         {
         secure_vector<byte> plaintext = m_key.random_plaintext_element(rng);

         secure_vector<byte> ciphertext, error_mask;
         mceliece_encrypt(ciphertext, error_mask, plaintext, m_key, rng);

         raw_shared_key.clear();
         raw_shared_key += plaintext;
         raw_shared_key += error_mask;

         out_encapsulated_key.swap(ciphertext);
         }

      const McEliece_PublicKey& m_key;
   };

class MCE_KEM_Decryptor : public PK_Ops::KEM_Decryption_with_KDF
   {
   public:
      typedef McEliece_PrivateKey Key_Type;

      MCE_KEM_Decryptor(const McEliece_PrivateKey& key,
                        const std::string& kdf) :
         KEM_Decryption_with_KDF(kdf), m_key(key) {}

   private:
      secure_vector<byte>
      raw_kem_decrypt(const byte encap_key[], size_t len) override
         {
         secure_vector<byte> plaintext, error_mask;
         mceliece_decrypt(plaintext, error_mask, encap_key, len, m_key);

         secure_vector<byte> output;
         output.reserve(plaintext.size() + error_mask.size());
         output.insert(output.end(), plaintext.begin(), plaintext.end());
         output.insert(output.end(), error_mask.begin(), error_mask.end());
         return output;
         }

      const McEliece_PrivateKey& m_key;
   };

BOTAN_REGISTER_PK_KEM_ENCRYPTION_OP("McEliece", MCE_KEM_Encryptor);
BOTAN_REGISTER_PK_KEM_DECRYPTION_OP("McEliece", MCE_KEM_Decryptor);

}
