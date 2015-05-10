/*
* (C) 1999-2010,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pubkey.h>
#include <botan/internal/algo_registry.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/bigint.h>

namespace Botan {

namespace {

template<typename T, typename Key>
T* get_pk_op(const std::string& what, const Key& key, const std::string& pad)
   {
   T* p = Algo_Registry<T>::global_registry().make(typename T::Spec(key, pad));
   if(!p)
      throw Lookup_Error(what + " with " + key.algo_name() + "/" + pad + " not supported");
   return p;
   }

}

PK_Encryptor_EME::PK_Encryptor_EME(const Public_Key& key, const std::string& eme)
   {
   m_op.reset(get_pk_op<PK_Ops::Encryption>("Encryption", key, eme));
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

PK_Decryptor_EME::PK_Decryptor_EME(const Private_Key& key, const std::string& eme)
   {
   m_op.reset(get_pk_op<PK_Ops::Decryption>("Decryption", key, eme));
   }

secure_vector<byte> PK_Decryptor_EME::dec(const byte msg[], size_t length) const
   {
   return m_op->decrypt(msg, length);
   }

PK_Key_Agreement::PK_Key_Agreement(const Private_Key& key, const std::string& kdf)
   {
   m_op.reset(get_pk_op<PK_Ops::Key_Agreement>("Key agreement", key, kdf));
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
                     Signature_Format format)
   {
   m_op.reset(get_pk_op<PK_Ops::Signature>("Signing", key, emsa));
   m_sig_format = format;
   }

std::vector<byte> PK_Signer::sign_message(const byte in[], size_t length,
    RandomNumberGenerator& rng)
{
    this->update(in, length);
    return this->signature(rng);
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
                         Signature_Format format)
   {
   m_op.reset(get_pk_op<PK_Ops::Verification>("Verification", key, emsa_name));
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

         return m_op->is_valid_signature(&real_sig[0], real_sig.size());
         }
      else
         throw Decoding_Error("PK_Verifier: Unknown signature format " +
                              std::to_string(m_sig_format));
      }
   catch(Invalid_Argument) { return false; }
   }

}
