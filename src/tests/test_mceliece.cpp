#include "tests.h"

#include <botan/pubkey.h>
#include <botan/ecdsa.h>
#include <botan/rsa.h>
#include <botan/x509cert.h>
#include <botan/oids.h>
#include <botan/mceliece.h>
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <iostream>

#include <botan/mce_overbeck_cca2.h>
#include <botan/mce_kem.h>

#include <memory>

using namespace Botan;

#define CHECK_MESSAGE(expr, print)  do {if(!(expr)) {std::cout << print << "\n"; return 1;} }while(0)
#define CHECK(expr) do {if(!(expr)) { std::cout << #expr << "\n"; return 1; } }while(0)

namespace {

const size_t MCE_RUNS = 10;

size_t test_mceliece_message_parts(RandomNumberGenerator& rng, size_t code_length, size_t error_weight)
   {
   secure_vector<gf2m> err_pos1 = create_random_error_positions(code_length, error_weight, rng);
   secure_vector<byte> message1((code_length+7)/8);
   rng.randomize(&message1[0], message1.size() - 1);
   mceliece_message_parts parts1(err_pos1, message1, code_length);
   secure_vector<byte> err_vec1 = parts1.get_error_vector();

   secure_vector<byte> concat1 = parts1.get_concat();

   mceliece_message_parts parts2( &concat1[0], concat1.size(), code_length);

   secure_vector<byte> err_vec2 = parts2.get_error_vector();
   if(err_vec1 != err_vec2)
      {
      std::cout << "error with error vector from message parts" << std::endl;
      return 1;
      }

   secure_vector<byte> message2 = parts2.get_message_word();
   if(message1 != message2)
      {
      std::cout << "error with message word from message parts" << std::endl;
      return 1;
      }

   return 0;
   }

size_t test_mceliece_overbeck(RandomNumberGenerator& rng, size_t code_length, size_t t )
   {
   McEliece_PrivateKey sk1(rng, code_length, t);
   McEliece_PublicKey pk1(*dynamic_cast<McEliece_PublicKey*>(&sk1));

   McEliece_PublicKey pk(pk1.x509_subject_public_key());
   McEliece_PrivateKey sk(sk1.pkcs8_private_key());

   if(sk1 != sk)
      {
      std::cout << "decoded McEliece private key differs from original one" << std::endl;
      return 1;
      }

   if(!sk.check_key(rng, false))
      {
      std::cout << "error calling check key on McEliece key" << std::endl;
      return 1;
      }

   if(pk1 != pk)
      {
      std::cout << "decoded McEliece public key differs from original one" << std::endl;
      return 1;
      }

   McEliece_Overbeck_CCA2_Private_Operation priv_op(sk);
   McEliece_Overbeck_CCA2_Public_Operation pub_op(pk );
   size_t err_cnt = 0;

   for(size_t i = 0; i < 10; i++)
      {
      try
         {
         secure_vector<byte> plaintext(64);
         rng.randomize(&plaintext[0], plaintext.size() - 1);

         secure_vector<byte> ciphertext = pub_op.encrypt(&plaintext[0], plaintext.size(), rng);
         secure_vector<byte> decrypted = priv_op.decrypt(&ciphertext[0], ciphertext.size() );

         if(plaintext != decrypted)
            {
            std::cout << "ciphertext = " << hex_encode(ciphertext) << std::endl;
            std::cout << "original      plaintext = " << hex_encode(plaintext) << std::endl;
            std::cout << "decrypted     plaintext = " << hex_encode(decrypted) << std::endl;

            err_cnt++;
            std::cout << "mce overbeck test " << i << " failed, error during encryption/decryption" << std::endl;
            return err_cnt;
            }

#if 0
         // takes a long time:
         for(size_t j = 0; j < code_length; j++)
            {
            // flip the j-th bit in the ciphertext
            secure_vector<byte> wrong_ct(ciphertext);
            size_t byte_pos = j/8;
            size_t bit_pos = j % 8;
            wrong_ct[byte_pos] ^= 1 << bit_pos;
            try
               {
               secure_vector<byte> decrypted = priv_op.decrypt(&wrong_ct[0], wrong_ct.size());
               }
            catch(const Integrity_Failure)
               {
               continue;
               }
            std::cout << "manipulation in ciphertext not detected" << std::endl;
            err_cnt++;
            }
#endif
         }
      catch(std::exception& e)
         {
         std::cout << e.what() << "\n";
         ++err_cnt;
         }
      }

   return err_cnt;
   }

size_t test_mceliece_kem(RandomNumberGenerator& rng, u32bit code_length, u32bit t)
   {
   size_t fails = 0;

   McEliece_PrivateKey sk1(rng, code_length, t);
   McEliece_PublicKey& pk1 = dynamic_cast<McEliece_PrivateKey&>(sk1);

   const std::vector<byte> pk_enc = pk1.x509_subject_public_key();
   const secure_vector<byte> sk_enc = sk1.pkcs8_private_key();

   McEliece_PublicKey pk(pk_enc);
   McEliece_PrivateKey sk(sk_enc);

   if(pk1 != pk)
      {
      std::cout << "decoded McEliece public key differs from original one" << std::endl;
      ++fails;
      }

   if(sk1 != sk)
      {
      std::cout << "decoded McEliece private key differs from original one" << std::endl;
      ++fails;
      }

   if(!sk.check_key(rng, false))
      {
      std::cout << "error calling check key on McEliece key" << std::endl;
      ++fails;
      }

   McEliece_KEM_Encryptor pub_op(pk);
   McEliece_KEM_Decryptor priv_op(sk);

   for(size_t i = 0; i != MCE_RUNS; i++)
      {
      const std::pair<secure_vector<byte>,secure_vector<byte> > ciphertext__sym_key = pub_op.encrypt(rng);
      const secure_vector<byte>& ciphertext = ciphertext__sym_key.first;
      const secure_vector<byte>& sym_key_encr = ciphertext__sym_key.second;

      const secure_vector<byte> sym_key_decr = priv_op.decrypt(&ciphertext[0], ciphertext.size());

      if(sym_key_encr != sym_key_decr)
         {
         std::cout << "mce KEM test failed, error during encryption/decryption" << std::endl;
         ++fails;
         }
      }

   return fails;
   }

size_t test_mceliece_raw(RandomNumberGenerator& rng, size_t code_length, size_t t)
   {
   McEliece_PrivateKey sk(rng, code_length, t);
   McEliece_PublicKey* p_pk = dynamic_cast<McEliece_PublicKey*>(&sk);

   McEliece_Private_Operation priv_op(sk);
   McEliece_Public_Operation pub_op(*p_pk, code_length );
   size_t err_cnt = 0;

   for(size_t i = 0; i != MCE_RUNS; i++)
      {
      secure_vector<byte> plaintext((p_pk->get_message_word_bit_length()+7)/8);
      rng.randomize(&plaintext[0], plaintext.size() - 1);
      secure_vector<gf2m> err_pos = create_random_error_positions(p_pk->get_code_length(), p_pk->get_t(), rng);


      mceliece_message_parts parts(err_pos, plaintext, p_pk->get_code_length());
      secure_vector<byte> message_and_error_input = parts.get_concat();
      secure_vector<byte> ciphertext = pub_op.encrypt(&message_and_error_input[0], message_and_error_input.size(), rng);
      //std::cout << "ciphertext byte length = " << ciphertext.size() << std::endl;
      secure_vector<byte> message_and_error_output = priv_op.decrypt(&ciphertext[0], ciphertext.size() );
      if(message_and_error_input != message_and_error_output)
         {
         mceliece_message_parts combined(&message_and_error_input[0], message_and_error_input.size(), code_length);
         secure_vector<byte> orig_pt = combined.get_message_word();
         secure_vector<byte> orig_ev = combined.get_error_vector();

         mceliece_message_parts decr_combined(&message_and_error_output[0], message_and_error_output.size(), code_length);
         secure_vector<byte> decr_pt = decr_combined.get_message_word();
         secure_vector<byte> decr_ev = decr_combined.get_error_vector();
         std::cout << "ciphertext = " << hex_encode(ciphertext) << std::endl;
         std::cout << "original      plaintext = " << hex_encode(orig_pt) << std::endl;
         std::cout << "original   error vector = " << hex_encode(orig_ev) << std::endl;
         std::cout << "decrypted     plaintext = " << hex_encode(decr_pt) << std::endl;
         std::cout << "decrypted  error vector = " << hex_encode(decr_ev) << std::endl;
         err_cnt++;
         std::cout << "mce test failed, error during encryption/decryption" << std::endl;
         std::cout << "err pos during encryption = ";
         for(size_t j = 0; j < err_pos.size(); j++) std::printf("%u, ", err_pos[j]);
         printf("\n");
         return 1;
         continue;
         }
      }

   return err_cnt;
   }


}

size_t test_mceliece()
   {
   AutoSeeded_RNG rng;

   size_t  err_cnt = 0;
   size_t params__n__t_min_max[] = {
      256, 5, 15,
      512, 5, 33,
      1024, 15, 35,
      2048, 33, 50,
      2960, 50, 56,
      6624, 110, 115
   };

   size_t tests = 0;

   for(size_t i = 0; i < sizeof(params__n__t_min_max)/sizeof(params__n__t_min_max[0]); i+=3)
      {
      size_t code_length = params__n__t_min_max[i];
      for(size_t t = params__n__t_min_max[i+1]; t <= params__n__t_min_max[i+2]; t++)
         {
         //std::cout << "testing parameters n = " << code_length << ", t = " << t << std::endl;

         try
            {
            err_cnt += test_mceliece_message_parts(rng, code_length, t);
            }
         catch(std::exception& e)
            {
            std::cout << e.what();
            err_cnt++;
            }

         try
            {
            err_cnt += test_mceliece_raw(rng, code_length, t);
            }
         catch(std::exception& e)
            {
            std::cout << e.what();
            err_cnt++;
            }

         try
            {
            err_cnt += test_mceliece_kem(rng, code_length, t);
            }
         catch(std::exception& e)
            {
            std::cout << e.what();
            err_cnt++;
            }

         try
            {
            // otherwise conversion not applicable because k=dimension would be too small
            if(code_length >= 2048)
               err_cnt += test_mceliece_overbeck(rng, code_length, t);
            }
         catch(std::exception& e)
            {
            std::cout << e.what();
            err_cnt++;
            }

         tests += 3;
         }
      }

   test_report("McEliece", tests, err_cnt);
   return err_cnt;
   }
