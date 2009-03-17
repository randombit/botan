#include <string>
#include <memory>
#include <sstream>
#include <iostream>
#include <stdexcept>

#include <botan/botan.h>
#include <botan/filters.h>
#include <botan/eax.h>

using namespace Botan;

/**
Encrypt and decrypt small rows
*/
class Row_Encryptor
   {
   public:
      Row_Encryptor(const std::string& passphrase,
                    RandomNumberGenerator& rng);

      std::string encrypt(const std::string& input,
                          const MemoryRegion<byte>& salt);

      std::string decrypt(const std::string& input,
                          const MemoryRegion<byte>& salt);

   private:
      Row_Encryptor(const Row_Encryptor&) {}
      Row_Encryptor& operator=(const Row_Encryptor&) { return (*this); }

      Pipe enc_pipe, dec_pipe;
      EAX_Encryption* eax_enc; // owned by enc_pipe
      EAX_Decryption* eax_dec; // owned by dec_pipe;
   };

Row_Encryptor::Row_Encryptor(const std::string& passphrase,
                             RandomNumberGenerator& rng)
   {
   std::auto_ptr<S2K> s2k(get_s2k("PBKDF2(SHA-160)"));

   s2k->set_iterations(10000);

   s2k->new_random_salt(rng, 10); // 10 bytes == 80 bits

   SecureVector<byte> key = s2k->derive_key(32, passphrase).bits_of();

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

   enc_pipe.start_msg();
   enc_pipe.write(input);
   enc_pipe.end_msg();

   return enc_pipe.read_all_as_string(Pipe::LAST_MESSAGE);
   }

std::string Row_Encryptor::decrypt(const std::string& input,
                                   const MemoryRegion<byte>& salt)
   {
   eax_dec->set_iv(salt);

   dec_pipe.start_msg();
   dec_pipe.write(input);
   dec_pipe.end_msg();

   return dec_pipe.read_all_as_string(Pipe::LAST_MESSAGE);
   }

/*************************
  Test code follows:
*/

#include <botan/loadstor.h>

int main()
   {
   Botan::LibraryInitializer init;

   AutoSeeded_RNG rng;

   Row_Encryptor encryptor("secret passphrase", rng);

   std::vector<std::string> original_inputs;

   for(u32bit i = 0; i != 15000; ++i)
      {
      std::ostringstream out;

      // This will actually generate variable length inputs (when
      // there are leading 0s, which are skipped), which is good
      // since it assures performance is OK across a mix of lengths
      // TODO: Maybe randomize the length slightly?

      for(u32bit j = 0; j != 32; ++j)
         out << std::hex << (int)rng.next_byte();

      original_inputs.push_back(out.str());
      }

   std::vector<std::string> encrypted_values;
   MemoryVector<byte> salt(4); // keep out of loop to avoid excessive dynamic allocation

   for(u32bit i = 0; i != original_inputs.size(); ++i)
      {
      std::string input = original_inputs[i];
      store_le(i, salt);

      encrypted_values.push_back(encryptor.encrypt(input, salt));
      }

   for(u32bit i = 0; i != encrypted_values.size(); ++i)
      {
      std::string ciphertext = encrypted_values[i];
      store_le(i, salt); // NOTE: same salt value as previous loop (index value)

      std::string output = encryptor.decrypt(ciphertext, salt);

      if(output != original_inputs[i])
         std::cout << "BOOM " << i << "\n";
      }

   }
