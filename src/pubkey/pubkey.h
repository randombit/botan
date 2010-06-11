/*
* Public Key Interface
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_PUBKEY_H__
#define BOTAN_PUBKEY_H__

#include <botan/pk_keys.h>
#include <botan/symkey.h>
#include <botan/rng.h>
#include <botan/eme.h>
#include <botan/emsa.h>
#include <botan/kdf.h>

namespace Botan {

/**
* The two types of signature format supported by Botan.
*/
enum Signature_Format { IEEE_1363, DER_SEQUENCE };

/**
* Public Key Encryptor
*/
class BOTAN_DLL PK_Encryptor
   {
   public:

      /**
      * Encrypt a message.
      * @param in the message as a byte array
      * @param length the length of the above byte array
      * @param rng the random number source to use
      * @return the encrypted message
      */
      SecureVector<byte> encrypt(const byte in[], u32bit length,
                                 RandomNumberGenerator& rng) const;

      /**
      * Encrypt a message.
      * @param in the message
      * @param rng the random number source to use
      * @return the encrypted message
      */
      SecureVector<byte> encrypt(const MemoryRegion<byte>& in,
                                 RandomNumberGenerator& rng) const;

      /**
      * Return the maximum allowed message size in bytes.
      * @return the maximum message size in bytes
      */
      virtual u32bit maximum_input_size() const = 0;

      virtual ~PK_Encryptor() {}
   private:
      virtual SecureVector<byte> enc(const byte[], u32bit,
                                     RandomNumberGenerator&) const = 0;
   };

/**
* Public Key Decryptor
*/
class BOTAN_DLL PK_Decryptor
   {
   public:
      /**
      * Decrypt a ciphertext.
      * @param in the ciphertext as a byte array
      * @param length the length of the above byte array
      * @return the decrypted message
      */
      SecureVector<byte> decrypt(const byte in[], u32bit length) const;

      /**
      * Decrypt a ciphertext.
      * @param in the ciphertext
      * @return the decrypted message
      */
      SecureVector<byte> decrypt(const MemoryRegion<byte>& in) const;

      virtual ~PK_Decryptor() {}
   private:
      virtual SecureVector<byte> dec(const byte[], u32bit) const = 0;
   };

/**
* Public Key Signer. Use the sign_message() functions for small
* messages. Use multiple calls update() to process large messages and
* generate the signature by finally calling signature().
*/
class BOTAN_DLL PK_Signer
   {
   public:
      /**
      * Sign a message.
      * @param in the message to sign as a byte array
      * @param length the length of the above byte array
      * @param rng the rng to use
      * @return the signature
      */
      SecureVector<byte> sign_message(const byte in[], u32bit length,
                                      RandomNumberGenerator& rng);

      /**
      * Sign a message.
      * @param in the message to sign
      * @param rng the rng to use
      * @return the signature
      */
      SecureVector<byte> sign_message(const MemoryRegion<byte>& in,
                                      RandomNumberGenerator& rng);

      /**
      * Add a message part (single byte).
      * @param the byte to add
      */
      void update(byte in);

      /**
      * Add a message part.
      * @param in the message part to add as a byte array
      * @param length the length of the above byte array
      */
      void update(const byte in[], u32bit length);

      /**
      * Add a message part.
      * @param in the message part to add
      */
      void update(const MemoryRegion<byte>& in);

      /**
      * Get the signature of the so far processed message (provided by the
      * calls to update()).
      * @param rng the rng to use
      * @return the signature of the total message
      */
      SecureVector<byte> signature(RandomNumberGenerator& rng);

      /**
      * Set the output format of the signature.
      * @param format the signature format to use
      */
      void set_output_format(Signature_Format format);

      /**
      * Construct a PK Signer.
      * @param key the key to use inside this signer
      * @param emsa the EMSA to use
      * An example would be "EMSA1(SHA-224)".
      */
      PK_Signer(const PK_Signing_Key& key, EMSA* emsa);

      ~PK_Signer() { delete emsa; }
   private:
      PK_Signer(const PK_Signer&);
      PK_Signer& operator=(const PK_Signer&);

      const PK_Signing_Key& key;
      Signature_Format sig_format;
      EMSA* emsa;
   };

/**
* Public Key Verifier. Use the verify_message() functions for small
* messages. Use multiple calls update() to process large messages and
* verify the signature by finally calling check_signature().
*/
class BOTAN_DLL PK_Verifier
   {
   public:
      /**
      * Verify a signature.
      * @param msg the message that the signature belongs to, as a byte array
      * @param msg_length the length of the above byte array msg
      * @param sig the signature as a byte array
      * @param sig_length the length of the above byte array sig
      * @return true if the signature is valid
      */
      bool verify_message(const byte msg[], u32bit msg_length,
                          const byte sig[], u32bit sig_length);
      /**
      * Verify a signature.
      * @param msg the message that the signature belongs to
      * @param sig the signature
      * @return true if the signature is valid
      */
      bool verify_message(const MemoryRegion<byte>& msg,
                          const MemoryRegion<byte>& sig);

      /**
      * Add a message part (single byte) of the message corresponding to the
      * signature to be verified.
      * @param msg_part the byte to add
      */
      void update(byte msg_part);

      /**
      * Add a message part of the message corresponding to the
      * signature to be verified.
      * @param msg_part the new message part as a byte array
      * @param length the length of the above byte array
      */
      void update(const byte msg_part[], u32bit length);

      /**
      * Add a message part of the message corresponding to the
      * signature to be verified.
      * @param msg_part the new message part
      */
      void update(const MemoryRegion<byte>& msg_part);

      /**
      * Check the signature of the buffered message, i.e. the one build
      * by successive calls to update.
      * @param sig the signature to be verified as a byte array
      * @param length the length of the above byte array
      * @return true if the signature is valid, false otherwise
      */
      bool check_signature(const byte sig[], u32bit length);

      /**
      * Check the signature of the buffered message, i.e. the one build
      * by successive calls to update.
      * @param sig the signature to be verified
      * @return true if the signature is valid, false otherwise
      */
      bool check_signature(const MemoryRegion<byte>& sig);

      /**
      * Set the format of the signatures fed to this verifier.
      * @param format the signature format to use
      */
      void set_input_format(Signature_Format format);

      /**
      * Construct a PK Verifier.
      * @param emsa the EMSA to use
      * An example would be new EMSA1(new SHA_224)
      */
      PK_Verifier(EMSA* emsa);

      virtual ~PK_Verifier();
   protected:
      virtual bool validate_signature(const MemoryRegion<byte>&,
                                      const byte[], u32bit) = 0;
      virtual u32bit key_message_parts() const = 0;
      virtual u32bit key_message_part_size() const = 0;

      Signature_Format sig_format;
      EMSA* emsa;
   private:
      PK_Verifier(const PK_Verifier&);
      PK_Verifier& operator=(const PK_Verifier&);
   };

/*
* Key Agreement
*/
class BOTAN_DLL PK_Key_Agreement
   {
   public:
      SymmetricKey derive_key(u32bit, const byte[], u32bit,
                              const std::string& = "") const;
      SymmetricKey derive_key(u32bit, const byte[], u32bit,
                              const byte[], u32bit) const;

      /**
      * Construct a PK Key Agreement.
      * @param key the key to use
      * @param kdf the KDF to use
      */
      PK_Key_Agreement(const PK_Key_Agreement_Key& key, KDF* kdf);

      ~PK_Key_Agreement() { delete kdf; }
   private:
      PK_Key_Agreement(const PK_Key_Agreement_Key&);
      PK_Key_Agreement& operator=(const PK_Key_Agreement&);

      const PK_Key_Agreement_Key& key;
      KDF* kdf;
   };

/**
* Encryption with an MR algorithm and an EME.
*/
class BOTAN_DLL PK_Encryptor_MR_with_EME : public PK_Encryptor
   {
   public:
      u32bit maximum_input_size() const;

      /**
      * Construct an instance.
      * @param key the key to use inside the decryptor
      * @param eme the EME to use
      */
      PK_Encryptor_MR_with_EME(const PK_Encrypting_Key& key,
                               EME* eme);

      ~PK_Encryptor_MR_with_EME() { delete encoder; }
   private:
      PK_Encryptor_MR_with_EME(const PK_Encryptor_MR_with_EME&);
      PK_Encryptor_MR_with_EME& operator=(const PK_Encryptor_MR_with_EME&);

      SecureVector<byte> enc(const byte[], u32bit,
                             RandomNumberGenerator& rng) const;

      const PK_Encrypting_Key& key;
      const EME* encoder;
   };

/**
* Decryption with an MR algorithm and an EME.
*/
class BOTAN_DLL PK_Decryptor_MR_with_EME : public PK_Decryptor
   {
   public:
     /**
      * Construct an instance.
      * @param key the key to use inside the encryptor
      * @param eme the EME to use
      */
      PK_Decryptor_MR_with_EME(const PK_Decrypting_Key& key,
                               EME* eme);

      ~PK_Decryptor_MR_with_EME() { delete encoder; }
   private:
      PK_Decryptor_MR_with_EME(const PK_Decryptor_MR_with_EME&);
      PK_Decryptor_MR_with_EME& operator=(const PK_Decryptor_MR_with_EME&);

      SecureVector<byte> dec(const byte[], u32bit) const;

      const PK_Decrypting_Key& key;
      const EME* encoder;
   };

/*
* Typedefs for easier transition between 1.8 and 1.9/1.10
*/
typedef PK_Encryptor_MR_with_EME PK_Encryptor_EME;
typedef PK_Decryptor_MR_with_EME PK_Decryptor_EME;

/**
* Public Key Verifier with Message Recovery.
*/
class BOTAN_DLL PK_Verifier_with_MR : public PK_Verifier
   {
   public:
      /**
      * Construct an instance.
      * @param key the key to use inside the verifier
      * @param emsa_name the name of the EMSA to use
      */
      PK_Verifier_with_MR(const PK_Verifying_with_MR_Key& k,
                          EMSA* emsa_obj) : PK_Verifier(emsa_obj), key(k) {}

   private:
      PK_Verifier_with_MR(const PK_Verifying_with_MR_Key&);
      PK_Verifier_with_MR& operator=(const PK_Verifier_with_MR&);

      bool validate_signature(const MemoryRegion<byte>&, const byte[], u32bit);
      u32bit key_message_parts() const { return key.message_parts(); }
      u32bit key_message_part_size() const { return key.message_part_size(); }

      const PK_Verifying_with_MR_Key& key;
   };

/**
* Public Key Verifier without Message Recovery
*/
class BOTAN_DLL PK_Verifier_wo_MR : public PK_Verifier
   {
   public:
      /**
      * Construct an instance.
      * @param key the key to use inside the verifier
      * @param emsa_name the name of the EMSA to use
      */
      PK_Verifier_wo_MR(const PK_Verifying_wo_MR_Key& k,
                        EMSA* emsa_obj) : PK_Verifier(emsa_obj), key(k) {}

   private:
      PK_Verifier_wo_MR(const PK_Verifying_wo_MR_Key&);
      PK_Verifier_wo_MR& operator=(const PK_Verifier_wo_MR&);

      bool validate_signature(const MemoryRegion<byte>&, const byte[], u32bit);
      u32bit key_message_parts() const { return key.message_parts(); }
      u32bit key_message_part_size() const { return key.message_part_size(); }

      const PK_Verifying_wo_MR_Key& key;
   };

}

#endif
