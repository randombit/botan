/*
* (C) 1999-2010,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pubkey.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/bigint.h>
#include <botan/pk_ops.h>
#include <botan/internal/ct_utils.h>

namespace Botan {

secure_vector<byte> PK_Decryptor::decrypt(const byte in[], size_t length) const
   {
   byte valid_mask = 0;

   secure_vector<byte> decoded = do_decrypt(valid_mask, in, length);

   if(valid_mask == 0)
      throw Decoding_Error("Invalid public key ciphertext, cannot decrypt");

   return decoded;
   }

secure_vector<byte>
PK_Decryptor::decrypt_or_random(const byte in[],
                                size_t length,
                                size_t expected_pt_len,
                                RandomNumberGenerator& rng,
                                const byte required_content_bytes[],
                                const byte required_content_offsets[],
                                size_t required_contents_length) const
   {
   const secure_vector<byte> fake_pms = rng.random_vec(expected_pt_len);

   byte valid_mask = 0;
   secure_vector<byte> decoded = do_decrypt(valid_mask, in, length);

   valid_mask &= CT::is_equal(decoded.size(), expected_pt_len);

   decoded.resize(expected_pt_len);

   for(size_t i = 0; i != required_contents_length; ++i)
      {
      /*
      These values are chosen by the application and for TLS are constants,
      so this early failure via assert is fine since we know 0,1 < 48

      If there is a protocol that has content checks on the key where
      the expected offsets are controllable by the attacker this could
      still leak.

      Alternately could always reduce the offset modulo the length?
      */

      const byte exp = required_content_bytes[i];
      const byte off = required_content_offsets[i];

      BOTAN_ASSERT(off < expected_pt_len, "Offset in range of plaintext");

      valid_mask &= CT::is_equal(decoded[off], exp);
      }

   CT::conditional_copy_mem(valid_mask,
                            /*output*/decoded.data(),
                            /*from0*/decoded.data(),
                            /*from1*/fake_pms.data(),
                            expected_pt_len);

   return decoded;
   }

secure_vector<byte>
PK_Decryptor::decrypt_or_random(const byte in[],
                                size_t length,
                                size_t expected_pt_len,
                                RandomNumberGenerator& rng) const
   {
   return decrypt_or_random(in, length, expected_pt_len, rng,
                            nullptr, nullptr, 0);
   }

PK_Encryptor_EME::PK_Encryptor_EME(const Public_Key& key,
                                   RandomNumberGenerator& rng,
                                   const std::string& padding,
                                   const std::string& provider)
   {
   m_op = key.create_encryption_op(rng, padding, provider);
   if(!m_op)
      throw Invalid_Argument("Key type " + key.algo_name() + " does not support encryption");
   }

PK_Encryptor_EME::~PK_Encryptor_EME() { /* for unique_ptr */ }

std::vector<byte>
PK_Encryptor_EME::enc(const byte in[], size_t length, RandomNumberGenerator& rng) const
   {
   return unlock(m_op->encrypt(in, length, rng));
   }

size_t PK_Encryptor_EME::maximum_input_size() const
   {
   return m_op->max_input_bits() / 8;
   }

PK_Decryptor_EME::PK_Decryptor_EME(const Private_Key& key,
                                   RandomNumberGenerator& rng,
                                   const std::string& padding,
                                   const std::string& provider)
   {
   m_op = key.create_decryption_op(rng, padding, provider);
   if(!m_op)
      throw Invalid_Argument("Key type " + key.algo_name() + " does not support decryption");
   }

PK_Decryptor_EME::~PK_Decryptor_EME() { /* for unique_ptr */ }

secure_vector<byte> PK_Decryptor_EME::do_decrypt(byte& valid_mask,
                                                 const byte in[], size_t in_len) const
   {
   return m_op->decrypt(valid_mask, in, in_len);
   }

PK_KEM_Encryptor::PK_KEM_Encryptor(const Public_Key& key,
                                   RandomNumberGenerator& rng,
                                   const std::string& param,
                                   const std::string& provider)
   {
   m_op = key.create_kem_encryption_op(rng, param, provider);
   if(!m_op)
      throw Invalid_Argument("Key type " + key.algo_name() + " does not support KEM encryption");
   }

PK_KEM_Encryptor::~PK_KEM_Encryptor() { /* for unique_ptr */ }

void PK_KEM_Encryptor::encrypt(secure_vector<byte>& out_encapsulated_key,
                               secure_vector<byte>& out_shared_key,
                               size_t desired_shared_key_len,
                               Botan::RandomNumberGenerator& rng,
                               const uint8_t salt[],
                               size_t salt_len)
   {
   m_op->kem_encrypt(out_encapsulated_key,
                     out_shared_key,
                     desired_shared_key_len,
                     rng,
                     salt,
                     salt_len);
   }

PK_KEM_Decryptor::PK_KEM_Decryptor(const Private_Key& key,
                                   RandomNumberGenerator& rng,
                                   const std::string& param,
                                   const std::string& provider)
   {
   m_op = key.create_kem_decryption_op(rng, param, provider);
   if(!m_op)
      throw Invalid_Argument("Key type " + key.algo_name() + " does not support KEM decryption");
   }

PK_KEM_Decryptor::~PK_KEM_Decryptor() { /* for unique_ptr */ }

secure_vector<byte> PK_KEM_Decryptor::decrypt(const byte encap_key[],
                                              size_t encap_key_len,
                                              size_t desired_shared_key_len,
                                              const uint8_t salt[],
                                              size_t salt_len)
   {
   return m_op->kem_decrypt(encap_key, encap_key_len,
                            desired_shared_key_len,
                            salt, salt_len);
   }

PK_Key_Agreement::PK_Key_Agreement(const Private_Key& key,
                                   RandomNumberGenerator& rng,
                                   const std::string& kdf,
                                   const std::string& provider)
   {
   m_op = key.create_key_agreement_op(rng, kdf, provider);
   if(!m_op)
      throw Invalid_Argument("Key type " + key.algo_name() + " does not support key agreement");
   }

PK_Key_Agreement::~PK_Key_Agreement() { /* for unique_ptr */ }

PK_Key_Agreement& PK_Key_Agreement::operator=(PK_Key_Agreement&& other)
   {
   if(this != &other)
      {
      m_op = std::move(other.m_op);
      }
   return (*this);
   }

PK_Key_Agreement::PK_Key_Agreement(PK_Key_Agreement&& other) :
   m_op(std::move(other.m_op))
   {}

SymmetricKey PK_Key_Agreement::derive_key(size_t key_len,
                                          const byte in[], size_t in_len,
                                          const byte salt[],
                                          size_t salt_len) const
   {
   return m_op->agree(key_len, in, in_len, salt, salt_len);
   }

PK_Signer::PK_Signer(const Private_Key& key,
                     RandomNumberGenerator& rng,
                     const std::string& emsa,
                     Signature_Format format,
                     const std::string& provider)
   {
   m_op = key.create_signature_op(rng, emsa, provider);
   if(!m_op)
      throw Invalid_Argument("Key type " + key.algo_name() + " does not support signature generation");
   m_sig_format = format;
   m_parts = key.message_parts();
   m_part_size = key.message_part_size();
   }

PK_Signer::~PK_Signer() { /* for unique_ptr */ }

void PK_Signer::update(const byte in[], size_t length)
   {
   m_op->update(in, length);
   }

std::vector<byte> PK_Signer::signature(RandomNumberGenerator& rng)
   {
   const std::vector<byte> sig = unlock(m_op->sign(rng));

   if(m_sig_format == IEEE_1363)
      {
      return sig;
      }
   else if(m_sig_format == DER_SEQUENCE)
      {
      if(sig.size() % m_parts != 0 || sig.size() != m_parts * m_part_size)
         throw Internal_Error("PK_Signer: DER signature sizes unexpected, cannot encode");

      std::vector<BigInt> sig_parts(m_parts);
      for(size_t i = 0; i != sig_parts.size(); ++i)
         sig_parts[i].binary_decode(&sig[m_part_size*i], m_part_size);

      return DER_Encoder()
         .start_cons(SEQUENCE)
         .encode_list(sig_parts)
         .end_cons()
         .get_contents_unlocked();
      }
   else
      throw Internal_Error("PK_Signer: Invalid signature format enum");
   }

PK_Verifier::PK_Verifier(const Public_Key& key,
                         const std::string& emsa,
                         Signature_Format format,
                         const std::string& provider)
   {
   m_op = key.create_verification_op(emsa, provider);
   if(!m_op)
      throw Invalid_Argument("Key type " + key.algo_name() + " does not support signature verification");
   m_sig_format = format;
   m_parts = key.message_parts();
   m_part_size = key.message_part_size();
   }

PK_Verifier::~PK_Verifier() { /* for unique_ptr */ }

void PK_Verifier::set_input_format(Signature_Format format)
   {
   if(format != IEEE_1363 && m_parts == 1)
      throw Invalid_Argument("PK_Verifier: This algorithm does not support DER encoding");
   m_sig_format = format;
   }

bool PK_Verifier::verify_message(const byte msg[], size_t msg_length,
                                 const byte sig[], size_t sig_length)
   {
   update(msg, msg_length);
   return check_signature(sig, sig_length);
   }

void PK_Verifier::update(const byte in[], size_t length)
   {
   m_op->update(in, length);
   }

bool PK_Verifier::check_signature(const byte sig[], size_t length)
   {
   try {
      if(m_sig_format == IEEE_1363)
         {
         return m_op->is_valid_signature(sig, length);
         }
      else if(m_sig_format == DER_SEQUENCE)
         {
         std::vector<byte> real_sig;
         BER_Decoder decoder(sig, length);
         BER_Decoder ber_sig = decoder.start_cons(SEQUENCE);

         size_t count = 0;
         while(ber_sig.more_items())
            {
            BigInt sig_part;
            ber_sig.decode(sig_part);
            real_sig += BigInt::encode_1363(sig_part, m_part_size);
            ++count;
            }

         if(count != m_parts)
            throw Decoding_Error("PK_Verifier: signature size invalid");

         return m_op->is_valid_signature(real_sig.data(), real_sig.size());
         }
      else
         throw Internal_Error("PK_Verifier: Invalid signature format enum");
      }
   catch(Invalid_Argument&) { return false; }
   }

}
