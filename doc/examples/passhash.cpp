#include <botan/botan.h>
#include <botan/pbkdf2.h>
#include <botan/hmac.h>
#include <botan/sha160.h>
#include <iostream>
#include <memory>

using namespace Botan;

std::string password_hash(const std::string& pass,
                          RandomNumberGenerator& rng);
bool password_hash_ok(const std::string& pass, const std::string& hash);

int main(int argc, char* argv[])
   {
   if(argc != 2 && argc != 3)
      {
      std::cerr << "Usage: " << argv[0] << " password\n";
      std::cerr << "Usage: " << argv[0] << " password hash\n";
      return 1;
      }

   Botan::LibraryInitializer init;

   try
      {

      if(argc == 2)
         {
         AutoSeeded_RNG rng;

         std::cout << "H('" << argv[1] << "') = "
                   << password_hash(argv[1], rng) << '\n';
         }
      else
         {
         bool ok = password_hash_ok(argv[1], argv[2]);
         if(ok)
            std::cout << "Password and hash match\n";
         else
            std::cout << "Password and hash do not match\n";
         }
      }
   catch(std::exception& e)
      {
      std::cerr << e.what() << '\n';
      return 1;
      }
   return 0;
   }

std::string password_hash(const std::string& pass,
                          RandomNumberGenerator& rng)
   {
   PKCS5_PBKDF2 kdf(new HMAC(new SHA_160));

   kdf.set_iterations(10000);
   kdf.new_random_salt(rng, 6); // 48 bits

   Pipe pipe(new Base64_Encoder);
   pipe.start_msg();
   pipe.write(kdf.current_salt());
   pipe.write(kdf.derive_key(12, pass).bits_of());
   pipe.end_msg();

   return pipe.read_all_as_string();
   }

bool password_hash_ok(const std::string& pass, const std::string& hash)
   {
   Pipe pipe(new Base64_Decoder);
   pipe.start_msg();
   pipe.write(hash);
   pipe.end_msg();

   SecureVector<byte> hash_bin = pipe.read_all();

   PKCS5_PBKDF2 kdf(new HMAC(new SHA_160));

   kdf.set_iterations(10000);
   kdf.change_salt(hash_bin, 6);

   SecureVector<byte> cmp = kdf.derive_key(12, pass).bits_of();

   return same_mem(cmp.begin(), hash_bin.begin() + 6, 12);
   }
