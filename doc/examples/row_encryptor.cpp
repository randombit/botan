/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <string>
#include <memory>
#include <sstream>
#include <iostream>
#include <stdexcept>

#include <botan/botan.h>
#include <botan/filters.h>
#include <botan/eax.h>

using namespace Botan;

/*
* Encrypt and decrypt small rows
*/
class Row_Encryptor
   {
   public:
      Row_Encryptor(const std::string& passphrase,
                    RandomNumberGenerator& rng);

      Row_Encryptor(const std::string& passphrase,
                    const MemoryRegion<byte>& salt);

      std::string encrypt(const std::string& input,
                          const MemoryRegion<byte>& salt);

      std::string decrypt(const std::string& input,
                          const MemoryRegion<byte>& salt);

      SecureVector<byte> get_pbkdf_salt() const { return pbkdf_salt; }
   private:
      void init(const std::string& passphrase);

      Row_Encryptor(const Row_Encryptor&) {}
      Row_Encryptor& operator=(const Row_Encryptor&) { return (*this); }

      SecureVector<byte> pbkdf_salt;
      Pipe enc_pipe, dec_pipe;
      EAX_Encryption* eax_enc; // owned by enc_pipe
      EAX_Decryption* eax_dec; // owned by dec_pipe;
   };

Row_Encryptor::Row_Encryptor(const std::string& passphrase,
                             RandomNumberGenerator& rng)
   {
   pbkdf_salt.resize(10); // 80 bits
   rng.randomize(&pbkdf_salt[0], pbkdf_salt.size());
   init(passphrase);
   }

Row_Encryptor::Row_Encryptor(const std::string& passphrase,
                             const MemoryRegion<byte>& salt)
   {
   pbkdf_salt = salt;
   init(passphrase);
   }

void Row_Encryptor::init(const std::string& passphrase)
   {
   std::auto_ptr<PBKDF> pbkdf(get_pbkdf("PBKDF2(SHA-160)"));

   SecureVector<byte> key = pbkdf->derive_key(32, passphrase,
                                            &pbkdf_salt[0], pbkdf_salt.size(),
                                            10000).bits_of();

   /*
    Save pointers to the EAX objects so we can change the IV as needed
   */

   Algorithm_Factory& af = global_state().algorithm_factory();

   const BlockCipher* proto = af.prototype_block_cipher("Serpent");

   if(!proto)
      throw std::runtime_error("Could not get a Serpent proto object");

   enc_pipe.append(eax_enc = new EAX_Encryption(proto->clone()));
   dec_pipe.append(eax_dec = new EAX_Decryption(proto->clone()));

   eax_enc->set_key(key);
   eax_dec->set_key(key);
   }

std::string Row_Encryptor::encrypt(const std::string& input,
                                   const MemoryRegion<byte>& salt)
   {
   eax_enc->set_iv(salt);
   enc_pipe.process_msg(input);
   return enc_pipe.read_all_as_string(Pipe::LAST_MESSAGE);
   }

std::string Row_Encryptor::decrypt(const std::string& input,
                                   const MemoryRegion<byte>& salt)
   {
   eax_dec->set_iv(salt);
   dec_pipe.process_msg(input);
   return dec_pipe.read_all_as_string(Pipe::LAST_MESSAGE);
   }

/*
* Test code follows:
*/

int main()
   {
   Botan::LibraryInitializer init;

   AutoSeeded_RNG rng;

   const std::string secret_passphrase = "secret passphrase";

   Row_Encryptor encryptor("secret passphrase", rng);

   std::vector<std::string> original_inputs;

   for(u32bit i = 0; i != 50000; ++i)
      {
      std::ostringstream out;

      u32bit output_bytes = rng.next_byte();

      for(u32bit j = 0; j != output_bytes; ++j)
         out << std::hex << (int)rng.next_byte();

      original_inputs.push_back(out.str());
      }

   std::vector<std::string> encrypted_values;
   MemoryVector<byte> salt(4); // keep out of loop to avoid excessive dynamic allocation

   for(u32bit i = 0; i != original_inputs.size(); ++i)
      {
      std::string input = original_inputs[i];

      for(u32bit j = 0; j != 4; ++j)
         salt[j] = (i >> 8) & 0xFF;

      encrypted_values.push_back(encryptor.encrypt(input, salt));
      }

   for(u32bit i = 0; i != encrypted_values.size(); ++i)
      {
      std::string ciphertext = encrypted_values[i];

      // NOTE: same salt value as previous loop (index value)
      for(u32bit j = 0; j != 4; ++j)
         salt[j] = (i >> 8) & 0xFF;

      std::string output = encryptor.decrypt(ciphertext, salt);

      if(output != original_inputs[i])
         std::cout << "BOOM " << i << "\n";
      }

   Row_Encryptor test_pbkdf_salt_copy(secret_passphrase,
                                      encryptor.get_pbkdf_salt());

   zeroise(salt);
   std::string test = test_pbkdf_salt_copy.decrypt(encrypted_values[0], salt);
   if(test != original_inputs[0])
      std::cout << "PBKDF salt copy failed to decrypt properly\n";

   return 0;
   }
