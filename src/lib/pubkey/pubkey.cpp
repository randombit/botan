/*
* Public Key Base
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/pubkey.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/bigint.h>
#include <botan/parsing.h>
#include <botan/libstate.h>
#include <botan/engine.h>
#include <botan/internal/bit_ops.h>

namespace Botan {

/*
* PK_Encryptor_EME Constructor
*/
PK_Encryptor_EME::PK_Encryptor_EME(const Public_Key& key,
                                   const std::string& eme_name)
   {
   Algorithm_Factory::Engine_Iterator i(global_state().algorithm_factory());
   RandomNumberGenerator& rng = global_state().global_rng();

   while(const Engine* engine = i.next())
      {
      m_op.reset(engine->get_encryption_op(key, rng));
      if(m_op)
         break;
      }

   if(!m_op)
      throw Lookup_Error("Encryption with " + key.algo_name() + " not supported");

   m_eme.reset(get_eme(eme_name));
   }

/*
* Encrypt a message
*/
std::vector<byte>
PK_Encryptor_EME::enc(const byte in[],
                      size_t length,
                      RandomNumberGenerator& rng) const
   {
   if(m_eme)
      {
      secure_vector<byte> encoded =
         m_eme->encode(in, length, m_op->max_input_bits(), rng);

      if(8*(encoded.size() - 1) + high_bit(encoded[0]) > m_op->max_input_bits())
         throw Invalid_Argument("PK_Encryptor_EME: Input is too large");

      return unlock(m_op->encrypt(&encoded[0], encoded.size(), rng));
      }
   else
      {
      if(8*(length - 1) + high_bit(in[0]) > m_op->max_input_bits())
         throw Invalid_Argument("PK_Encryptor_EME: Input is too large");

      return unlock(m_op->encrypt(&in[0], length, rng));
      }
   }

/*
* Return the max size, in bytes, of a message
*/
size_t PK_Encryptor_EME::maximum_input_size() const
   {
   if(!m_eme)
      return (m_op->max_input_bits() / 8);
   else
      return m_eme->maximum_input_size(m_op->max_input_bits());
   }

/*
* PK_Decryptor_EME Constructor
*/
PK_Decryptor_EME::PK_Decryptor_EME(const Private_Key& key,
                                   const std::string& eme_name)
   {
   Algorithm_Factory::Engine_Iterator i(global_state().algorithm_factory());
   RandomNumberGenerator& rng = global_state().global_rng();

   while(const Engine* engine = i.next())
      {
      m_op.reset(engine->get_decryption_op(key, rng));
      if(m_op)
         break;
      }

   if(!m_op)
      throw Lookup_Error("Decryption with " + key.algo_name() + " not supported");

   m_eme.reset(get_eme(eme_name));
   }

/*
* Decrypt a message
*/
secure_vector<byte> PK_Decryptor_EME::dec(const byte msg[],
                                          size_t length) const
   {
   try {
      secure_vector<byte> decrypted = m_op->decrypt(msg, length);
      if(m_eme)
         return m_eme->decode(decrypted, m_op->max_input_bits());
      else
         return decrypted;
      }
   catch(Invalid_Argument)
      {
      throw Decoding_Error("PK_Decryptor_EME: Input is invalid");
      }
   }

/*
* PK_Signer Constructor
*/
PK_Signer::PK_Signer(const Private_Key& key,
                     const std::string& emsa_name,
                     Signature_Format format,
                     Fault_Protection prot)
   {
   Algorithm_Factory::Engine_Iterator i(global_state().algorithm_factory());
   RandomNumberGenerator& rng = global_state().global_rng();

   m_op = nullptr;
   m_verify_op = nullptr;

   while(const Engine* engine = i.next())
      {
      if(!m_op)
         m_op.reset(engine->get_signature_op(key, emsa_name, rng));

      if(!m_verify_op && prot == ENABLE_FAULT_PROTECTION)
         m_verify_op.reset(engine->get_verify_op(key, emsa_name, rng));

      if(m_op && (m_verify_op || prot == DISABLE_FAULT_PROTECTION))
         break;
      }

   if(!m_op || (!m_verify_op && prot == ENABLE_FAULT_PROTECTION))
      throw Lookup_Error("Signing with " + key.algo_name() + " not supported");

   m_emsa.reset(get_emsa(emsa_name));
   m_sig_format = format;
   }

/*
* Sign a message
*/
std::vector<byte> PK_Signer::sign_message(const byte msg[], size_t length,
                                           RandomNumberGenerator& rng)
   {
   update(msg, length);
   return signature(rng);
   }

/*
* Add more to the message to be signed
*/
void PK_Signer::update(const byte in[], size_t length)
   {
   m_emsa->update(in, length);
   }

/*
* Check the signature we just created, to help prevent fault attacks
*/
bool PK_Signer::self_test_signature(const std::vector<byte>& msg,
                                    const std::vector<byte>& sig) const
   {
   if(!m_verify_op)
      return true; // checking disabled, assume ok

   if(m_verify_op->with_recovery())
      {
      std::vector<byte> recovered =
         unlock(m_verify_op->verify_mr(&sig[0], sig.size()));

      if(msg.size() > recovered.size())
         {
         size_t extra_0s = msg.size() - recovered.size();

         for(size_t i = 0; i != extra_0s; ++i)
            if(msg[i] != 0)
               return false;

         return same_mem(&msg[extra_0s], &recovered[0], recovered.size());
         }

      return (recovered == msg);
      }
   else
      return m_verify_op->verify(&msg[0], msg.size(),
                               &sig[0], sig.size());
   }

/*
* Create a signature
*/
std::vector<byte> PK_Signer::signature(RandomNumberGenerator& rng)
   {
   std::vector<byte> encoded = unlock(m_emsa->encoding_of(m_emsa->raw_data(),
                                                 m_op->max_input_bits(),
                                                        rng));

   std::vector<byte> plain_sig = unlock(m_op->sign(&encoded[0], encoded.size(), rng));

   BOTAN_ASSERT(self_test_signature(encoded, plain_sig), "Signature was consistent");

   if(m_op->message_parts() == 1 || m_sig_format == IEEE_1363)
      return plain_sig;

   if(m_sig_format == DER_SEQUENCE)
      {
      if(plain_sig.size() % m_op->message_parts())
         throw Encoding_Error("PK_Signer: strange signature size found");
      const size_t SIZE_OF_PART = plain_sig.size() / m_op->message_parts();

      std::vector<BigInt> sig_parts(m_op->message_parts());
      for(size_t j = 0; j != sig_parts.size(); ++j)
         sig_parts[j].binary_decode(&plain_sig[SIZE_OF_PART*j], SIZE_OF_PART);

      return DER_Encoder()
         .start_cons(SEQUENCE)
            .encode_list(sig_parts)
         .end_cons()
      .get_contents_unlocked();
      }
   else
      throw Encoding_Error("PK_Signer: Unknown signature format " +
                           std::to_string(m_sig_format));
   }

/*
* PK_Verifier Constructor
*/
PK_Verifier::PK_Verifier(const Public_Key& key,
                         const std::string& emsa_name,
                         Signature_Format format)
   {
   Algorithm_Factory::Engine_Iterator i(global_state().algorithm_factory());
   RandomNumberGenerator& rng = global_state().global_rng();

   while(const Engine* engine = i.next())
      {
      m_op.reset(engine->get_verify_op(key, emsa_name, rng));
      if(m_op)
         break;
      }

   if(!m_op)
      throw Lookup_Error("Verification with " + key.algo_name() + " not supported");

   m_emsa.reset(get_emsa(emsa_name));
   m_sig_format = format;
   }

/*
* Set the signature format
*/
void PK_Verifier::set_input_format(Signature_Format format)
   {
   if(m_op->message_parts() == 1 && format != IEEE_1363)
      throw Invalid_State("PK_Verifier: This algorithm always uses IEEE 1363");
   m_sig_format = format;
   }

/*
* Verify a message
*/
bool PK_Verifier::verify_message(const byte msg[], size_t msg_length,
                                 const byte sig[], size_t sig_length)
   {
   update(msg, msg_length);
   return check_signature(sig, sig_length);
   }

/*
* Append to the message
*/
void PK_Verifier::update(const byte in[], size_t length)
   {
   m_emsa->update(in, length);
   }

/*
* Check a signature
*/
bool PK_Verifier::check_signature(const byte sig[], size_t length)
   {
   try {
      if(m_sig_format == IEEE_1363)
         return validate_signature(m_emsa->raw_data(), sig, length);
      else if(m_sig_format == DER_SEQUENCE)
         {
         BER_Decoder decoder(sig, length);
         BER_Decoder ber_sig = decoder.start_cons(SEQUENCE);

         size_t count = 0;
         std::vector<byte> real_sig;
         while(ber_sig.more_items())
            {
            BigInt sig_part;
            ber_sig.decode(sig_part);
            real_sig += BigInt::encode_1363(sig_part, m_op->message_part_size());
            ++count;
            }

         if(count != m_op->message_parts())
            throw Decoding_Error("PK_Verifier: signature size invalid");

         return validate_signature(m_emsa->raw_data(),
                                   &real_sig[0], real_sig.size());
         }
      else
         throw Decoding_Error("PK_Verifier: Unknown signature format " +
                              std::to_string(m_sig_format));
      }
   catch(Invalid_Argument) { return false; }
   }

/*
* Verify a signature
*/
bool PK_Verifier::validate_signature(const secure_vector<byte>& msg,
                                     const byte sig[], size_t sig_len)
   {
   if(m_op->with_recovery())
      {
      secure_vector<byte> output_of_key = m_op->verify_mr(sig, sig_len);
      return m_emsa->verify(output_of_key, msg, m_op->max_input_bits());
      }
   else
      {
      RandomNumberGenerator& rng = global_state().global_rng();

      secure_vector<byte> encoded =
         m_emsa->encoding_of(msg, m_op->max_input_bits(), rng);

      return m_op->verify(&encoded[0], encoded.size(), sig, sig_len);
      }
   }

/*
* PK_Key_Agreement Constructor
*/
PK_Key_Agreement::PK_Key_Agreement(const PK_Key_Agreement_Key& key,
                                   const std::string& kdf_name)
   {
   Algorithm_Factory::Engine_Iterator i(global_state().algorithm_factory());
   RandomNumberGenerator& rng = global_state().global_rng();

   while(const Engine* engine = i.next())
      {
      m_op.reset(engine->get_key_agreement_op(key, rng));
      if(m_op)
         break;
      }

   if(!m_op)
      throw Lookup_Error("Key agreement with " + key.algo_name() + " not supported");

   m_kdf.reset(get_kdf(kdf_name));
   }

SymmetricKey PK_Key_Agreement::derive_key(size_t key_len, const byte in[],
                                          size_t in_len, const byte params[],
                                          size_t params_len) const
   {
   secure_vector<byte> z = m_op->agree(in, in_len);

   if(!m_kdf)
      return z;

   return m_kdf->derive_key(key_len, z, params, params_len);
   }

}
