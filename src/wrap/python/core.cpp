/*
* Boost.Python module definition
* (C) 1999-2007 Jack Lloyd
*/

#include <botan/init.h>
#include <botan/pipe.h>
#include <botan/lookup.h>
#include <botan/cryptobox.h>
#include <botan/pbkdf2.h>
#include <botan/hmac.h>
using namespace Botan;

#include "python_botan.h"

class Py_Cipher
   {
   public:
      Py_Cipher(std::string algo_name, std::string direction,
                std::string key);

      std::string cipher_noiv(const std::string& text);

      std::string cipher(const std::string& text,
                         const std::string& iv);

      std::string name() const { return algo_name; }
   private:
      std::string algo_name;
      Keyed_Filter* filter;
      Pipe pipe;
   };

std::string Py_Cipher::cipher(const std::string& input,
                              const std::string& iv_str)
   {
   if(iv_str.size())
      {
      const byte* iv_bytes = reinterpret_cast<const byte*>(iv_str.data());
      u32bit iv_len = iv_str.size();
      filter->set_iv(InitializationVector(iv_bytes, iv_len));
      }

   pipe.process_msg(input);
   return pipe.read_all_as_string(Pipe::LAST_MESSAGE);
   }

// For IV-less algorithms
std::string Py_Cipher::cipher_noiv(const std::string& input)
   {
   pipe.process_msg(input);
   return pipe.read_all_as_string(Pipe::LAST_MESSAGE);
   }

Py_Cipher::Py_Cipher(std::string algo_name,
                     std::string direction,
                     std::string key_str)
   {
   const byte* key_bytes = reinterpret_cast<const byte*>(key_str.data());
   u32bit key_len = key_str.size();

   Cipher_Dir dir;

   if(direction == "encrypt")
      dir = ENCRYPTION;
   else if(direction == "decrypt")
      dir = DECRYPTION;
   else
      throw std::invalid_argument("Bad cipher direction " + direction);

   filter = get_cipher(algo_name, dir);
   filter->set_key(SymmetricKey(key_bytes, key_len));
   pipe.append(filter);
   }

class Py_HashFunction
   {
   public:
      Py_HashFunction(const std::string& algo_name)
         {
         hash = get_hash(algo_name);
         }

      ~Py_HashFunction() { delete hash; }

      void update(const std::string& input)
         {
         hash->update(input);
         }

      std::string final()
         {
         std::string out(output_length(), 0);
         hash->final(reinterpret_cast<byte*>(&out[0]));
         return out;
         }

      std::string name() const
         {
         return hash->name();
         }

      u32bit output_length() const
         {
         return hash->output_length();
         }

   private:
      HashFunction* hash;
   };

class Py_MAC
   {
   public:

      Py_MAC(const std::string& name, const std::string& key_str)
         {
         mac = get_mac(name);

         mac->set_key(reinterpret_cast<const byte*>(key_str.data()),
                      key_str.size());
         }

      ~Py_MAC() { delete mac; }

      u32bit output_length() const { return mac->output_length(); }

      std::string name() const { return mac->name(); }

      void update(const std::string& in) { mac->update(in); }

      std::string final()
         {
         std::string out(output_length(), 0);
         mac->final(reinterpret_cast<byte*>(&out[0]));
         return out;
         }
   private:
      MessageAuthenticationCode* mac;
   };

std::string cryptobox_encrypt(const std::string& in,
                              const std::string& passphrase,
                              Python_RandomNumberGenerator& rng)
   {
   const byte* in_bytes = reinterpret_cast<const byte*>(in.data());

   return CryptoBox::encrypt(in_bytes, in.size(),
                             passphrase, rng.get_underlying_rng());
   }

std::string cryptobox_decrypt(const std::string& in,
                              const std::string& passphrase)
   {
   const byte* in_bytes = reinterpret_cast<const byte*>(in.data());

   return CryptoBox::decrypt(in_bytes, in.size(),
                             passphrase);
   }

std::string python_pbkdf2(const std::string& passphrase,
                          const std::string& salt,
                          u32bit iterations,
                          u32bit output_size,
                          const std::string& hash_fn)
   {
   PKCS5_PBKDF2 pbkdf2(new HMAC(get_hash(hash_fn)));

   return make_string(
      pbkdf2.derive_key(output_size,
                        passphrase,
                        reinterpret_cast<const byte*>(salt.data()),
                        salt.size(),
                        iterations).bits_of());
   }

std::string python_kdf2(const std::string& param,
                        const std::string& masterkey,
                        u32bit outputlength)
   {
   std::auto_ptr<KDF> kdf(get_kdf("KDF2(SHA-1)"));

   return make_string(
      kdf->derive_key(outputlength,
                      reinterpret_cast<const byte*>(masterkey.data()),
                      masterkey.length(),
                      param));
   }

BOOST_PYTHON_MODULE(_botan)
   {
   python::class_<LibraryInitializer>("LibraryInitializer")
      .def(python::init< python::optional<std::string> >());

   python::class_<Python_RandomNumberGenerator>("RandomNumberGenerator")
      .def(python::init<>())
      .def("__str__", &Python_RandomNumberGenerator::name)
      .def("name", &Python_RandomNumberGenerator::name)
      .def("reseed", &Python_RandomNumberGenerator::reseed)
      .def("add_entropy", &Python_RandomNumberGenerator::add_entropy)
      .def("gen_random_byte", &Python_RandomNumberGenerator::gen_random_byte)
      .def("gen_random", &Python_RandomNumberGenerator::gen_random);

   python::class_<Py_Cipher, boost::noncopyable>
      ("Cipher", python::init<std::string, std::string, std::string>())
      .def("name", &Py_Cipher::name)
      .def("cipher", &Py_Cipher::cipher)
      .def("cipher", &Py_Cipher::cipher_noiv);

   python::class_<Py_HashFunction, boost::noncopyable>
      ("HashFunction", python::init<std::string>())
      .def("update", &Py_HashFunction::update)
      .def("final", &Py_HashFunction::final)
      .def("name", &Py_HashFunction::name)
      .def("output_length", &Py_HashFunction::output_length);

   python::class_<Py_MAC, boost::noncopyable>
      ("MAC", python::init<std::string, std::string>())
      .def("update", &Py_MAC::update)
      .def("final", &Py_MAC::final)
      .def("name", &Py_MAC::name)
      .def("output_length", &Py_MAC::output_length);

   python::def("cryptobox_encrypt", cryptobox_encrypt);
   python::def("cryptobox_decrypt", cryptobox_decrypt);
   python::def("pbkdf2", python_pbkdf2);
   python::def("derive_key", python_kdf2);

   export_filters();
   export_rsa();
   export_x509();
   }
