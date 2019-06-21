/*
* Ed25519
* (C) 2017 Ribose Inc
*
* Based on the public domain code from SUPERCOP ref10 by
* Peter Schwabe, Daniel J. Bernstein, Niels Duif, Tanja Lange, Bo-Yin Yang
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ed25519.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/hash.h>
#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/rng.h>

namespace Botan {

AlgorithmIdentifier Ed25519_PublicKey::algorithm_identifier() const
   {
   return AlgorithmIdentifier(get_oid(), AlgorithmIdentifier::USE_EMPTY_PARAM);
   }

bool Ed25519_PublicKey::check_key(RandomNumberGenerator&, bool) const
   {
   return true; // no tests possible?
   // TODO could check cofactor
   }

Ed25519_PublicKey::Ed25519_PublicKey(const uint8_t pub_key[], size_t pub_len)
   {
   if(pub_len != 32)
      throw Decoding_Error("Invalid length for Ed25519 key");
   m_public.assign(pub_key, pub_key + pub_len);
   }

Ed25519_PublicKey::Ed25519_PublicKey(const AlgorithmIdentifier&,
                                     const std::vector<uint8_t>& key_bits)
   {
   m_public = key_bits;

   if(m_public.size() != 32)
      throw Decoding_Error("Invalid size for Ed25519 public key");
   }

std::vector<uint8_t> Ed25519_PublicKey::public_key_bits() const
   {
   return m_public;
   }

Ed25519_PrivateKey::Ed25519_PrivateKey(const secure_vector<uint8_t>& secret_key)
   {
   if(secret_key.size() == 64)
      {
      m_private = secret_key;
      m_public.assign(m_private.begin() + 32, m_private.end());
      }
   else if(secret_key.size() == 32)
      {
      m_public.resize(32);
      m_private.resize(64);
      ed25519_gen_keypair(m_public.data(), m_private.data(), secret_key.data());
      }
   else
      throw Decoding_Error("Invalid size for Ed25519 private key");
   }

Ed25519_PrivateKey::Ed25519_PrivateKey(RandomNumberGenerator& rng)
   {
   const secure_vector<uint8_t> seed = rng.random_vec(32);
   m_public.resize(32);
   m_private.resize(64);
   ed25519_gen_keypair(m_public.data(), m_private.data(), seed.data());
   }

Ed25519_PrivateKey::Ed25519_PrivateKey(const AlgorithmIdentifier&,
                                       const secure_vector<uint8_t>& key_bits)
   {
   secure_vector<uint8_t> bits;
   BER_Decoder(key_bits).decode(bits, OCTET_STRING).discard_remaining();

   if(bits.size() != 32)
      throw Decoding_Error("Invalid size for Ed25519 private key");
   m_public.resize(32);
   m_private.resize(64);
   ed25519_gen_keypair(m_public.data(), m_private.data(), bits.data());
   }

secure_vector<uint8_t> Ed25519_PrivateKey::private_key_bits() const
   {
   secure_vector<uint8_t> bits(&m_private[0], &m_private[32]);
   return DER_Encoder().encode(bits, OCTET_STRING).get_contents();
   }

bool Ed25519_PrivateKey::check_key(RandomNumberGenerator&, bool) const
   {
   return true; // ???
   }

namespace {

/**
* Ed25519 verifying operation
*/
class Ed25519_Pure_Verify_Operation final : public PK_Ops::Verification
   {
   public:
      Ed25519_Pure_Verify_Operation(const Ed25519_PublicKey& key) : m_key(key)
         {
         }

      void update(const uint8_t msg[], size_t msg_len) override
         {
         m_msg.insert(m_msg.end(), msg, msg + msg_len);
         }

      bool is_valid_signature(const uint8_t sig[], size_t sig_len) override
         {
         if(sig_len != 64)
            return false;

         const std::vector<uint8_t>& pub_key = m_key.get_public_key();
         BOTAN_ASSERT_EQUAL(pub_key.size(), 32, "Expected size");
         const bool ok = ed25519_verify(m_msg.data(), m_msg.size(), sig, pub_key.data(), nullptr, 0);
         m_msg.clear();
         return ok;
         }

   private:
      std::vector<uint8_t> m_msg;
      const Ed25519_PublicKey& m_key;
   };

/**
* Ed25519 verifying operation with pre-hash
*/
class Ed25519_Hashed_Verify_Operation final : public PK_Ops::Verification
   {
   public:
      Ed25519_Hashed_Verify_Operation(const Ed25519_PublicKey& key, const std::string& hash, bool rfc8032) :
         m_key(key)
         {
         m_hash = HashFunction::create_or_throw(hash);

         if(rfc8032)
            {
            m_domain_sep = {
               0x53, 0x69, 0x67, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x20, 0x6E, 0x6F, 0x20, 0x45, 0x64,
               0x32, 0x35, 0x35, 0x31, 0x39, 0x20, 0x63, 0x6F, 0x6C, 0x6C, 0x69, 0x73, 0x69, 0x6F, 0x6E, 0x73,
               0x01, 0x00 };
            }
         }

      void update(const uint8_t msg[], size_t msg_len) override
         {
         m_hash->update(msg, msg_len);
         }

      bool is_valid_signature(const uint8_t sig[], size_t sig_len) override
         {
         if(sig_len != 64)
            return false;
         std::vector<uint8_t> msg_hash(m_hash->output_length());
         m_hash->final(msg_hash.data());

         const std::vector<uint8_t>& pub_key = m_key.get_public_key();
         BOTAN_ASSERT_EQUAL(pub_key.size(), 32, "Expected size");
         return ed25519_verify(msg_hash.data(), msg_hash.size(), sig, pub_key.data(), m_domain_sep.data(), m_domain_sep.size());
         }

   private:
      std::unique_ptr<HashFunction> m_hash;
      const Ed25519_PublicKey& m_key;
      std::vector<uint8_t> m_domain_sep;
   };

/**
* Ed25519 signing operation ('pure' - signs message directly)
*/
class Ed25519_Pure_Sign_Operation final : public PK_Ops::Signature
   {
   public:
      Ed25519_Pure_Sign_Operation(const Ed25519_PrivateKey& key) : m_key(key)
         {
         }

      void update(const uint8_t msg[], size_t msg_len) override
         {
         m_msg.insert(m_msg.end(), msg, msg + msg_len);
         }

      secure_vector<uint8_t> sign(RandomNumberGenerator&) override
         {
         secure_vector<uint8_t> sig(64);
         ed25519_sign(sig.data(), m_msg.data(), m_msg.size(), m_key.get_private_key().data(), nullptr, 0);
         m_msg.clear();
         return sig;
         }

      size_t signature_length() const override { return 64; }

   private:
      std::vector<uint8_t> m_msg;
      const Ed25519_PrivateKey& m_key;
   };

/**
* Ed25519 signing operation with pre-hash
*/
class Ed25519_Hashed_Sign_Operation final : public PK_Ops::Signature
   {
   public:
      Ed25519_Hashed_Sign_Operation(const Ed25519_PrivateKey& key, const std::string& hash, bool rfc8032) :
         m_key(key)
         {
         m_hash = HashFunction::create_or_throw(hash);

         if(rfc8032)
            {
            m_domain_sep = std::vector<uint8_t>{
               0x53, 0x69, 0x67, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x20, 0x6E, 0x6F, 0x20, 0x45, 0x64,
               0x32, 0x35, 0x35, 0x31, 0x39, 0x20, 0x63, 0x6F, 0x6C, 0x6C, 0x69, 0x73, 0x69, 0x6F, 0x6E, 0x73,
               0x01, 0x00 };
            }
         }

      size_t signature_length() const override { return 64; }

      void update(const uint8_t msg[], size_t msg_len) override
         {
         m_hash->update(msg, msg_len);
         }

      secure_vector<uint8_t> sign(RandomNumberGenerator&) override
         {
         secure_vector<uint8_t> sig(64);
         std::vector<uint8_t> msg_hash(m_hash->output_length());
         m_hash->final(msg_hash.data());
         ed25519_sign(sig.data(),
                      msg_hash.data(), msg_hash.size(),
                      m_key.get_private_key().data(),
                      m_domain_sep.data(), m_domain_sep.size());
         return sig;
         }

   private:
      std::unique_ptr<HashFunction> m_hash;
      const Ed25519_PrivateKey& m_key;
      std::vector<uint8_t> m_domain_sep;
   };

}

std::unique_ptr<PK_Ops::Verification>
Ed25519_PublicKey::create_verification_op(const std::string& params,
                                          const std::string& provider) const
   {
   if(provider == "base" || provider.empty())
      {
      if(params == "" || params == "Identity" || params == "Pure")
         return std::unique_ptr<PK_Ops::Verification>(new Ed25519_Pure_Verify_Operation(*this));
      else if(params == "Ed25519ph")
         return std::unique_ptr<PK_Ops::Verification>(new Ed25519_Hashed_Verify_Operation(*this, "SHA-512", true));
      else
         return std::unique_ptr<PK_Ops::Verification>(new Ed25519_Hashed_Verify_Operation(*this, params, false));
      }
   throw Provider_Not_Found(algo_name(), provider);
   }

std::unique_ptr<PK_Ops::Signature>
Ed25519_PrivateKey::create_signature_op(RandomNumberGenerator&,
                                        const std::string& params,
                                        const std::string& provider) const
   {
   if(provider == "base" || provider.empty())
      {
      if(params == "" || params == "Identity" || params == "Pure")
         return std::unique_ptr<PK_Ops::Signature>(new Ed25519_Pure_Sign_Operation(*this));
      else if(params == "Ed25519ph")
         return std::unique_ptr<PK_Ops::Signature>(new Ed25519_Hashed_Sign_Operation(*this, "SHA-512", true));
      else
         return std::unique_ptr<PK_Ops::Signature>(new Ed25519_Hashed_Sign_Operation(*this, params, false));
      }
   throw Provider_Not_Found(algo_name(), provider);
   }

}
