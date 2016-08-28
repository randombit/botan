/*
* (C) 1999-2010,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pubkey.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/bigint.h>
#include <botan/internal/algo_registry.h>
#include <botan/internal/ct_utils.h>

namespace Botan {

namespace {

template<typename T, typename Key>
T* get_pk_op(const std::string& what, const Key& key, const std::string& pad,
             const std::string& provider = "")
   {
   if(T* p = Algo_Registry<T>::global_registry().make(typename T::Spec(key, pad), provider))
      return p;

   const std::string err = what + " with " + key.algo_name() + "/" + pad + " not supported";
   if(!provider.empty())
      throw Lookup_Error(err + " with provider " + provider);
   else
      throw Lookup_Error(err);
   }

}

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

   //CT::poison(in, length);

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

   //CT::unpoison(in, length);
   //CT::unpoison(decoded.data(), decoded.size());

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
                                   const std::string& padding,
                                   const std::string& provider)
   {
   m_op.reset(get_pk_op<PK_Ops::Encryption>("Encryption", key, padding, provider));
   }

std::vector<byte>
PK_Encryptor_EME::enc(const byte in[], size_t length, RandomNumberGenerator& rng) const
   {
   return unlock(m_op->encrypt(in, length, rng));
   }

size_t PK_Encryptor_EME::maximum_input_size() const
   {
   return m_op->max_input_bits() / 8;
   }

PK_Decryptor_EME::PK_Decryptor_EME(const Private_Key& key, const std::string& padding,
                                   const std::string& provider)
   {
   m_op.reset(get_pk_op<PK_Ops::Decryption>("Decryption", key, padding, provider));
   }

secure_vector<byte> PK_Decryptor_EME::do_decrypt(byte& valid_mask,
                                                 const byte in[], size_t in_len) const
   {
   return m_op->decrypt(valid_mask, in, in_len);
   }

PK_KEM_Encryptor::PK_KEM_Encryptor(const Public_Key& key,
                                   const std::string& param,
                                   const std::string& provider)
   {
   m_op.reset(get_pk_op<PK_Ops::KEM_Encryption>("KEM", key, param, provider));
   }

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
                                   const std::string& param,
                                   const std::string& provider)
   {
   m_op.reset(get_pk_op<PK_Ops::KEM_Decryption>("KEM", key, param, provider));
   }

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
                                   const std::string& kdf,
                                   const std::string& provider)
   {
   m_op.reset(get_pk_op<PK_Ops::Key_Agreement>("Key agreement", key, kdf, provider));
   }

SymmetricKey PK_Key_Agreement::derive_key(size_t key_len,
                                          const byte in[], size_t in_len,
                                          const byte salt[],
                                          size_t salt_len) const
   {
   return m_op->agree(key_len, in, in_len, salt, salt_len);
   }

namespace {

std::vector<byte> der_encode_signature(const std::vector<byte>& sig, size_t parts)
   {
   if(sig.size() % parts)
      throw Encoding_Error("PK_Signer: strange signature size found");
   const size_t SIZE_OF_PART = sig.size() / parts;

   std::vector<BigInt> sig_parts(parts);
   for(size_t j = 0; j != sig_parts.size(); ++j)
      sig_parts[j].binary_decode(&sig[SIZE_OF_PART*j], SIZE_OF_PART);

   return DER_Encoder()
      .start_cons(SEQUENCE)
      .encode_list(sig_parts)
      .end_cons()
      .get_contents_unlocked();
   }

std::vector<byte> der_decode_signature(const byte sig[], size_t len,
                                       size_t part_size, size_t parts)
   {
   std::vector<byte> real_sig;
   BER_Decoder decoder(sig, len);
   BER_Decoder ber_sig = decoder.start_cons(SEQUENCE);

   size_t count = 0;
   while(ber_sig.more_items())
      {
      BigInt sig_part;
      ber_sig.decode(sig_part);
      real_sig += BigInt::encode_1363(sig_part, part_size);
      ++count;
      }

   if(count != parts)
      throw Decoding_Error("PK_Verifier: signature size invalid");
   return real_sig;
   }

}

PK_Signer::PK_Signer(const Private_Key& key,
                     const std::string& emsa,
                     Signature_Format format,
                     const std::string& provider)
   {
   m_op.reset(get_pk_op<PK_Ops::Signature>("Signing", key, emsa, provider));
   m_sig_format = format;
   }

void PK_Signer::update(const byte in[], size_t length)
   {
   m_op->update(in, length);
   }

std::vector<byte> PK_Signer::signature(RandomNumberGenerator& rng)
   {
   const std::vector<byte> plain_sig = unlock(m_op->sign(rng));
   const size_t parts = m_op->message_parts();

   if(parts == 1 || m_sig_format == IEEE_1363)
      return plain_sig;
   else if(m_sig_format == DER_SEQUENCE)
      return der_encode_signature(plain_sig, parts);
   else
      throw Encoding_Error("PK_Signer: Unknown signature format " +
                           std::to_string(m_sig_format));
   }

PK_Verifier::PK_Verifier(const Public_Key& key,
                         const std::string& emsa_name,
                         Signature_Format format,
                         const std::string& provider)
   {
   m_op.reset(get_pk_op<PK_Ops::Verification>("Verification", key, emsa_name, provider));
   m_sig_format = format;
   }

void PK_Verifier::set_input_format(Signature_Format format)
   {
   if(m_op->message_parts() == 1 && format != IEEE_1363)
      throw Invalid_State("PK_Verifier: This algorithm always uses IEEE 1363");
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
         std::vector<byte> real_sig = der_decode_signature(sig, length,
                                                           m_op->message_part_size(),
                                                           m_op->message_parts());

         return m_op->is_valid_signature(real_sig.data(), real_sig.size());
         }
      else
         throw Decoding_Error("PK_Verifier: Unknown signature format " +
                              std::to_string(m_sig_format));
      }
   catch(Invalid_Argument&) { return false; }
   }

}
