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
#include <botan/lookup.h>
#include <botan/internal/bit_ops.h>
#include <memory>

namespace Botan {

/*
* PK_Encryptor_EME Constructor
*/
PK_Encryptor_EME::PK_Encryptor_EME(const Public_Key& key,
                                   const std::string& eme_name)
   {
   Algorithm_Factory::Engine_Iterator i(global_state().algorithm_factory());

   while(const Engine* engine = i.next())
      {
      op = engine->get_encryption_op(key);
      if(op)
         break;
      }

   if(!op)
      throw Lookup_Error("PK_Encryptor_EME: No working engine for " +
                         key.algo_name());

   eme = get_eme(eme_name);
   }

/*
* Encrypt a message
*/
SecureVector<byte>
PK_Encryptor_EME::enc(const byte msg[],
                      u32bit length,
                      RandomNumberGenerator& rng) const
   {
   SecureVector<byte> message;
   if(eme)
      message = eme->encode(msg, length, op->max_input_bits(), rng);
   else
      message.set(msg, length);

   if(8*(message.size() - 1) + high_bit(message[0]) > op->max_input_bits())
      throw Invalid_Argument("PK_Encryptor_EME: Input is too large");

   return op->encrypt(message, message.size(), rng);
   }

/*
* Return the max size, in bytes, of a message
*/
u32bit PK_Encryptor_EME::maximum_input_size() const
   {
   if(!eme)
      return (op->max_input_bits() / 8);
   else
      return eme->maximum_input_size(op->max_input_bits());
   }

/*
* PK_Decryptor_EME Constructor
*/
PK_Decryptor_EME::PK_Decryptor_EME(const Private_Key& key,
                                   const std::string& eme_name)
   {
   Algorithm_Factory::Engine_Iterator i(global_state().algorithm_factory());

   while(const Engine* engine = i.next())
      {
      op = engine->get_decryption_op(key);
      if(op)
         break;
      }

   if(!op)
      throw Lookup_Error("PK_Decryptor_EME: No working engine for " +
                         key.algo_name());

   eme = get_eme(eme_name);
   }

/*
* Decrypt a message
*/
SecureVector<byte> PK_Decryptor_EME::dec(const byte msg[],
                                         u32bit length) const
   {
   try {
      SecureVector<byte> decrypted = op->decrypt(msg, length);
      if(eme)
         return eme->decode(decrypted, op->max_input_bits());
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
                     Signature_Format format)
   {
   Algorithm_Factory::Engine_Iterator i(global_state().algorithm_factory());

   op = 0;
   verify_op = 0;

   while(const Engine* engine = i.next())
      {
      if(!op)
         op = engine->get_signature_op(key);

      if(!verify_op)
         verify_op = engine->get_verify_op(key);

      if(op && verify_op)
         break;
      }

   if(!op || !verify_op)
      throw Lookup_Error("PK_Signer: No working engine for " +
                         key.algo_name());

   emsa = get_emsa(emsa_name);
   sig_format = format;
   }

/*
* Sign a message
*/
SecureVector<byte> PK_Signer::sign_message(const byte msg[], u32bit length,
                                           RandomNumberGenerator& rng)
   {
   update(msg, length);
   return signature(rng);
   }

/*
* Add more to the message to be signed
*/
void PK_Signer::update(const byte in[], u32bit length)
   {
   emsa->update(in, length);
   }

/*
* Check the signature we just created, to help prevent fault attacks
*/
bool PK_Signer::self_test_signature(const MemoryRegion<byte>& msg,
                                    const MemoryRegion<byte>& sig) const
   {
   if(verify_op->with_recovery())
      {
      SecureVector<byte> recovered =
         verify_op->verify_mr(&sig[0], sig.size());

      if(msg.size() > recovered.size())
         {
         u32bit extra_0s = msg.size() - recovered.size();

         for(size_t i = 0; i != extra_0s; ++i)
            if(msg[i] != 0)
               return false;

         return same_mem(&msg[extra_0s], &recovered[0], recovered.size());
         }

      return (recovered == msg);
      }
   else
      return verify_op->verify(&msg[0], msg.size(),
                               &sig[0], sig.size());
   }

/*
* Create a signature
*/
SecureVector<byte> PK_Signer::signature(RandomNumberGenerator& rng)
   {
   SecureVector<byte> encoded = emsa->encoding_of(emsa->raw_data(),
                                                  op->max_input_bits(),
                                                  rng);

   SecureVector<byte> plain_sig = op->sign(encoded, encoded.size(), rng);

   if(!self_test_signature(encoded, plain_sig))
      throw Internal_Error("PK_Signer consistency check failed");

   if(op->message_parts() == 1 || sig_format == IEEE_1363)
      return plain_sig;

   if(sig_format == DER_SEQUENCE)
      {
      if(plain_sig.size() % op->message_parts())
         throw Encoding_Error("PK_Signer: strange signature size found");
      const u32bit SIZE_OF_PART = plain_sig.size() / op->message_parts();

      std::vector<BigInt> sig_parts(op->message_parts());
      for(u32bit j = 0; j != sig_parts.size(); ++j)
         sig_parts[j].binary_decode(plain_sig + SIZE_OF_PART*j, SIZE_OF_PART);

      return DER_Encoder()
         .start_cons(SEQUENCE)
            .encode_list(sig_parts)
         .end_cons()
      .get_contents();
      }
   else
      throw Encoding_Error("PK_Signer: Unknown signature format " +
                           to_string(sig_format));
   }

/*
* PK_Verifier Constructor
*/
PK_Verifier::PK_Verifier(const Public_Key& key,
                         const std::string& emsa_name,
                         Signature_Format format)
   {
   Algorithm_Factory::Engine_Iterator i(global_state().algorithm_factory());

   while(const Engine* engine = i.next())
      {
      op = engine->get_verify_op(key);
      if(op)
         break;
      }

   if(!op)
      throw Lookup_Error("PK_Verifier: No working engine for " +
                         key.algo_name());

   emsa = get_emsa(emsa_name);
   sig_format = format;
   }

/*
* Set the signature format
*/
void PK_Verifier::set_input_format(Signature_Format format)
   {
   if(op->message_parts() == 1 && format != IEEE_1363)
      throw Invalid_State("PK_Verifier: This algorithm always uses IEEE 1363");
   sig_format = format;
   }

/*
* Verify a message
*/
bool PK_Verifier::verify_message(const byte msg[], u32bit msg_length,
                                 const byte sig[], u32bit sig_length)
   {
   update(msg, msg_length);
   return check_signature(sig, sig_length);
   }

/*
* Append to the message
*/
void PK_Verifier::update(const byte in[], u32bit length)
   {
   emsa->update(in, length);
   }

/*
* Check a signature
*/
bool PK_Verifier::check_signature(const byte sig[], u32bit length)
   {
   try {
      if(sig_format == IEEE_1363)
         return validate_signature(emsa->raw_data(), sig, length);
      else if(sig_format == DER_SEQUENCE)
         {
         BER_Decoder decoder(sig, length);
         BER_Decoder ber_sig = decoder.start_cons(SEQUENCE);

         u32bit count = 0;
         SecureVector<byte> real_sig;
         while(ber_sig.more_items())
            {
            BigInt sig_part;
            ber_sig.decode(sig_part);
            real_sig.append(BigInt::encode_1363(sig_part,
                                                op->message_part_size()));
            ++count;
            }

         if(count != op->message_parts())
            throw Decoding_Error("PK_Verifier: signature size invalid");

         return validate_signature(emsa->raw_data(),
                                   real_sig, real_sig.size());
         }
      else
         throw Decoding_Error("PK_Verifier: Unknown signature format " +
                              to_string(sig_format));
      }
   catch(Invalid_Argument) { return false; }
   }

/*
* Verify a signature
*/
bool PK_Verifier::validate_signature(const MemoryRegion<byte>& msg,
                                     const byte sig[], u32bit sig_len)
   {
   if(op->with_recovery())
      {
      SecureVector<byte> output_of_key = op->verify_mr(sig, sig_len);
      return emsa->verify(output_of_key, msg, op->max_input_bits());
      }
   else
      {
      Null_RNG rng;

      SecureVector<byte> encoded =
         emsa->encoding_of(msg, op->max_input_bits(), rng);

      return op->verify(encoded, encoded.size(), sig, sig_len);
      }
   }

/*
* PK_Key_Agreement Constructor
*/
PK_Key_Agreement::PK_Key_Agreement(const PK_Key_Agreement_Key& key,
                                   const std::string& kdf_name)
   {
   Algorithm_Factory::Engine_Iterator i(global_state().algorithm_factory());

   while(const Engine* engine = i.next())
      {
      op = engine->get_key_agreement_op(key);
      if(op)
         break;
      }

   if(!op)
      throw Lookup_Error("PK_Key_Agreement: No working engine for " +
                         key.algo_name());

   kdf = get_kdf(kdf_name);
   }

SymmetricKey PK_Key_Agreement::derive_key(u32bit key_len, const byte in[],
                                          u32bit in_len, const byte params[],
                                          u32bit params_len) const
   {
   SecureVector<byte> z = op->agree(in, in_len);

   if(!kdf)
      return z;

   return kdf->derive_key(key_len, z, params, params_len);
   }

}
