/*
* McEliece Integrated Encryption System
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/mceies.h>
#include <botan/aead.h>
#include <botan/mceliece.h>
#include <botan/mce_kem.h>

namespace Botan {

namespace {

secure_vector<byte> aead_key(const secure_vector<byte>& mk,
                             const AEAD_Mode& aead)
   {
   // Fold the key as required for the AEAD mode in use
   if(aead.valid_keylength(mk.size()))
      return mk;

   secure_vector<byte> r(aead.key_spec().maximum_keylength());
   for(size_t i = 0; i != mk.size(); ++i)
      r[i % r.size()] ^= mk[i];
   return r;
   }

}

secure_vector<byte>
mceies_encrypt(const McEliece_PublicKey& pubkey,
               const secure_vector<byte>& pt,
               byte ad[], size_t ad_len,
               RandomNumberGenerator& rng)
   {
   McEliece_KEM_Encryptor kem_op(pubkey);

   const std::pair<secure_vector<byte>,secure_vector<byte>> mce_ciphertext__key = kem_op.encrypt(rng);
   const secure_vector<byte>& mce_ciphertext = mce_ciphertext__key.first;
   const secure_vector<byte>& mce_key = mce_ciphertext__key.second;

   const size_t mce_code_bytes = (pubkey.get_code_length() + 7) / 8;

   BOTAN_ASSERT(mce_ciphertext.size() == mce_code_bytes, "Unexpected size");

   std::unique_ptr<AEAD_Mode> aead(get_aead("AES-256/OCB", ENCRYPTION));
   if(!aead)
      throw std::runtime_error("mce_encrypt unable to create AEAD instance");

   const size_t nonce_len = aead->default_nonce_length();

   aead->set_key(aead_key(mce_key, *aead));
   aead->set_associated_data(ad, ad_len);

   const secure_vector<byte> nonce = rng.random_vec(nonce_len);

   secure_vector<byte> msg(mce_ciphertext.size() + nonce.size() + pt.size());
   copy_mem(msg.data(), mce_ciphertext.data(), mce_ciphertext.size());
   copy_mem(&msg[mce_ciphertext.size()], nonce.data(), nonce.size());
   copy_mem(&msg[mce_ciphertext.size() + nonce.size()], pt.data(), pt.size());

   aead->start(nonce);
   aead->finish(msg, mce_ciphertext.size() + nonce.size());
   return msg;
   }

secure_vector<byte>
mceies_decrypt(const McEliece_PrivateKey& privkey,
               const secure_vector<byte>& ct,
               byte ad[], size_t ad_len)
   {
   try
      {
      McEliece_KEM_Decryptor kem_op(privkey);

      const size_t mce_code_bytes = (privkey.get_code_length() + 7) / 8;

      std::unique_ptr<AEAD_Mode> aead(get_aead("AES-256/OCB", DECRYPTION));
      if(!aead)
         throw std::runtime_error("Unable to create AEAD instance");

      const size_t nonce_len = aead->default_nonce_length();

      if(ct.size() < mce_code_bytes + nonce_len + aead->tag_size())
         throw std::runtime_error("Input message too small to be valid");

      const secure_vector<byte> mce_key = kem_op.decrypt(ct.data(), mce_code_bytes);

      aead->set_key(aead_key(mce_key, *aead));
      aead->set_associated_data(ad, ad_len);

      secure_vector<byte> pt(&ct[mce_code_bytes + nonce_len], &ct[ct.size()]);

      aead->start(&ct[mce_code_bytes], nonce_len);
      aead->finish(pt, 0);
      return pt;
      }
   catch(std::exception& e)
      {
      throw std::runtime_error("mce_decrypt failed: " + std::string(e.what()));
      }
   }

}
