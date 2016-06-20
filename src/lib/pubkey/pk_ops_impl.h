/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PK_OPERATION_IMPL_H__
#define BOTAN_PK_OPERATION_IMPL_H__

#include <botan/pk_ops.h>

namespace Botan {

namespace PK_Ops {

class Encryption_with_EME : public Encryption
   {
   public:
      size_t max_input_bits() const override;

      secure_vector<byte> encrypt(const byte msg[], size_t msg_len,
                                  RandomNumberGenerator& rng) override;

      ~Encryption_with_EME();
   protected:
      explicit Encryption_with_EME(const std::string& eme);
   private:
      virtual size_t max_raw_input_bits() const = 0;

      virtual secure_vector<byte> raw_encrypt(const byte msg[], size_t len,
                                              RandomNumberGenerator& rng) = 0;
      std::unique_ptr<EME> m_eme;
   };

class Decryption_with_EME : public Decryption
   {
   public:
      size_t max_input_bits() const override;

      secure_vector<byte> decrypt(byte& valid_mask,
                                  const byte msg[], size_t msg_len) override;

      ~Decryption_with_EME();
   protected:
      explicit Decryption_with_EME(const std::string& eme);
   private:
      virtual size_t max_raw_input_bits() const = 0;
      virtual secure_vector<byte> raw_decrypt(const byte msg[], size_t len) = 0;
      std::unique_ptr<EME> m_eme;
   };

class Verification_with_EMSA : public Verification
   {
   public:
      void update(const byte msg[], size_t msg_len) override;
      bool is_valid_signature(const byte sig[], size_t sig_len) override;

      bool do_check(const secure_vector<byte>& msg,
                    const byte sig[], size_t sig_len);

      std::string hash_for_signature() { return m_hash; }
   protected:

      explicit Verification_with_EMSA(const std::string& emsa);
      ~Verification_with_EMSA();

      /**
      * @return boolean specifying if this signature scheme uses
      * a message prefix returned by message_prefix()
      */
      virtual bool has_prefix() { return false; }

      /**
      * @return the message prefix if this signature scheme uses
      * a message prefix, signaled via has_prefix()
      */
      virtual secure_vector<byte> message_prefix() const { throw Exception( "No prefix" ); }

      /**
      * @return boolean specifying if this key type supports message
      * recovery and thus if you need to call verify() or verify_mr()
      */
      virtual bool with_recovery() const = 0;

      /*
      * Perform a signature check operation
      * @param msg the message
      * @param msg_len the length of msg in bytes
      * @param sig the signature
      * @param sig_len the length of sig in bytes
      * @returns if signature is a valid one for message
      */
      virtual bool verify(const byte[], size_t,
                          const byte[], size_t)
         {
         throw Invalid_State("Message recovery required");
         }

      /*
      * Perform a signature operation (with message recovery)
      * Only call this if with_recovery() returns true
      * @param msg the message
      * @param msg_len the length of msg in bytes
      * @returns recovered message
      */
      virtual secure_vector<byte> verify_mr(const byte[], size_t)
         {
         throw Invalid_State("Message recovery not supported");
         }

      std::unique_ptr<EMSA> m_emsa;

   private:
      const std::string m_hash;
      bool m_prefix_used;
   };

class Signature_with_EMSA : public Signature
   {
   public:
      void update(const byte msg[], size_t msg_len) override;

      secure_vector<byte> sign(RandomNumberGenerator& rng) override;
   protected:
      explicit Signature_with_EMSA(const std::string& emsa);
      ~Signature_with_EMSA();

      std::string hash_for_signature() { return m_hash; }

      /**
      * @return boolean specifying if this signature scheme uses
      * a message prefix returned by message_prefix()
      */
      virtual bool has_prefix() { return false; }

      /**
      * @return the message prefix if this signature scheme uses
      * a message prefix, signaled via has_prefix()
      */
      virtual secure_vector<byte> message_prefix() const { throw Exception( "No prefix" ); }

      std::unique_ptr<EMSA> m_emsa;
   private:

      /**
      * Get the maximum message size in bits supported by this public key.
      * @return maximum message in bits
      */
      virtual size_t max_input_bits() const = 0;

      bool self_test_signature(const std::vector<byte>& msg,
                               const std::vector<byte>& sig) const;

      virtual secure_vector<byte> raw_sign(const byte msg[], size_t msg_len,
                                           RandomNumberGenerator& rng) = 0;

      const std::string m_hash;
      bool m_prefix_used;
   };

class Key_Agreement_with_KDF : public Key_Agreement
   {
   public:
      secure_vector<byte> agree(size_t key_len,
                                const byte other_key[], size_t other_key_len,
                                const byte salt[], size_t salt_len) override;

   protected:
      explicit Key_Agreement_with_KDF(const std::string& kdf);
      ~Key_Agreement_with_KDF();
   private:
      virtual secure_vector<byte> raw_agree(const byte w[], size_t w_len) = 0;
      std::unique_ptr<KDF> m_kdf;
   };

class KEM_Encryption_with_KDF : public KEM_Encryption
   {
   public:
      void kem_encrypt(secure_vector<byte>& out_encapsulated_key,
                       secure_vector<byte>& out_shared_key,
                       size_t desired_shared_key_len,
                       Botan::RandomNumberGenerator& rng,
                       const uint8_t salt[],
                       size_t salt_len) override;

   protected:
      virtual void raw_kem_encrypt(secure_vector<byte>& out_encapsulated_key,
                                   secure_vector<byte>& raw_shared_key,
                                   Botan::RandomNumberGenerator& rng) = 0;

      explicit KEM_Encryption_with_KDF(const std::string& kdf);
      ~KEM_Encryption_with_KDF();
   private:
      std::unique_ptr<KDF> m_kdf;
   };

class KEM_Decryption_with_KDF : public KEM_Decryption
   {
   public:
      secure_vector<byte> kem_decrypt(const byte encap_key[],
                                      size_t len,
                                      size_t desired_shared_key_len,
                                      const uint8_t salt[],
                                      size_t salt_len) override;

   protected:
      virtual secure_vector<byte>
      raw_kem_decrypt(const byte encap_key[], size_t len) = 0;

      explicit KEM_Decryption_with_KDF(const std::string& kdf);
      ~KEM_Decryption_with_KDF();
   private:
      std::unique_ptr<KDF> m_kdf;
   };

}

}

#endif
