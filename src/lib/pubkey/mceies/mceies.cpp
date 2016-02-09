/*
* McEliece Integrated Encryption System
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/mceies.h>
#include <botan/aead.h>
#include <botan/mceliece.h>
#include <botan/pubkey.h>

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
               const byte pt[], size_t pt_len,
               const byte ad[], size_t ad_len,
               RandomNumberGenerator& rng,
               const std::string& algo)
   {
   PK_KEM_Encryptor kem_op(pubkey, "KDF1(SHA-512)");

   secure_vector<byte> mce_ciphertext, mce_key;
   kem_op.encrypt(mce_ciphertext, mce_key, 64, rng);

   const size_t mce_code_bytes = (pubkey.get_code_length() + 7) / 8;

   BOTAN_ASSERT(mce_ciphertext.size() == mce_code_bytes, "Unexpected size");

   std::unique_ptr<AEAD_Mode> aead(get_aead(algo, ENCRYPTION));
   if(!aead)
      throw Exception("mce_encrypt unable to create AEAD instance '" + algo + "'");

   const size_t nonce_len = aead->default_nonce_length();

   aead->set_key(aead_key(mce_key, *aead));
   aead->set_associated_data(ad, ad_len);

   const secure_vector<byte> nonce = rng.random_vec(nonce_len);

   secure_vector<byte> msg(mce_ciphertext.size() + nonce.size() + pt_len);
   copy_mem(msg.data(), mce_ciphertext.data(), mce_ciphertext.size());
   copy_mem(msg.data() + mce_ciphertext.size(), nonce.data(), nonce.size());
   copy_mem(msg.data() + mce_ciphertext.size() + nonce.size(), pt, pt_len);

   aead->start(nonce);
   aead->finish(msg, mce_ciphertext.size() + nonce.size());
   return msg;
   }

secure_vector<byte>
mceies_decrypt(const McEliece_PrivateKey& privkey,
               const byte ct[], size_t ct_len,
               const byte ad[], size_t ad_len,
               const std::string& algo)
   {
   try
      {
      PK_KEM_Decryptor kem_op(privkey, "KDF1(SHA-512)");

      const size_t mce_code_bytes = (privkey.get_code_length() + 7) / 8;

      std::unique_ptr<AEAD_Mode> aead(get_aead(algo, DECRYPTION));
      if(!aead)
         throw Exception("Unable to create AEAD instance '" + algo + "'");

      const size_t nonce_len = aead->default_nonce_length();

      if(ct_len < mce_code_bytes + nonce_len + aead->tag_size())
         throw Exception("Input message too small to be valid");

      const secure_vector<byte> mce_key = kem_op.decrypt(ct, mce_code_bytes, 64);

      aead->set_key(aead_key(mce_key, *aead));
      aead->set_associated_data(ad, ad_len);

      secure_vector<byte> pt(ct + mce_code_bytes + nonce_len, ct + ct_len);

      aead->start(&ct[mce_code_bytes], nonce_len);
      aead->finish(pt, 0);
      return pt;
      }
   catch(Integrity_Failure&)
      {
      throw;
      }
   catch(std::exception& e)
      {
      throw Exception("mce_decrypt failed: " + std::string(e.what()));
      }
   }

}
