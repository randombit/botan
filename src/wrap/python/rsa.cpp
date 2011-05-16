/*
* Boost.Python module definition
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/rsa.h>
#include <botan/look_pk.h>
#include <botan/pubkey.h>
#include <botan/x509_key.h>
using namespace Botan;

#include "python_botan.h"
#include <sstream>

std::string bigint2str(const BigInt& n)
   {
   std::ostringstream out;
   out << n;
   return out.str();
   }

class Py_RSA_PrivateKey
   {
   public:
      Py_RSA_PrivateKey(std::string pem_str,
                        Python_RandomNumberGenerator& rng,
                        std::string pass);
      Py_RSA_PrivateKey(std::string pem_str,
                        Python_RandomNumberGenerator& rng);

      Py_RSA_PrivateKey(u32bit bits, Python_RandomNumberGenerator& rng);
      ~Py_RSA_PrivateKey() { delete rsa_key; }

      std::string to_string() const
         {
         return PKCS8::PEM_encode(*rsa_key);
         }

      std::string to_ber() const
         {
         SecureVector<byte> bits = PKCS8::BER_encode(*rsa_key);

         return std::string(reinterpret_cast<const char*>(&bits[0]),
                            bits.size());
         }

      std::string get_N() const { return bigint2str(get_bigint_N()); }
      std::string get_E() const { return bigint2str(get_bigint_E()); }

      const BigInt& get_bigint_N() const { return rsa_key->get_n(); }
      const BigInt& get_bigint_E() const { return rsa_key->get_e(); }

      std::string decrypt(const std::string& in,
                          const std::string& padding);

      std::string sign(const std::string& in,
                       const std::string& padding,
                       Python_RandomNumberGenerator& rng);
   private:
      RSA_PrivateKey* rsa_key;
   };

std::string Py_RSA_PrivateKey::decrypt(const std::string& in,
                                       const std::string& padding)
   {
   PK_Decryptor_EME dec(*rsa_key, padding);

   const byte* in_bytes = reinterpret_cast<const byte*>(in.data());

   return make_string(dec.decrypt(in_bytes, in.size()));
   }

std::string Py_RSA_PrivateKey::sign(const std::string& in,
                                    const std::string& padding,
                                    Python_RandomNumberGenerator& rng)
   {
   PK_Signer sign(*rsa_key, padding);
   const byte* in_bytes = reinterpret_cast<const byte*>(in.data());
   sign.update(in_bytes, in.size());
   return make_string(sign.signature(rng.get_underlying_rng()));
   }

Py_RSA_PrivateKey::Py_RSA_PrivateKey(u32bit bits,
                                     Python_RandomNumberGenerator& rng)
   {
   rsa_key = new RSA_PrivateKey(rng.get_underlying_rng(), bits);
   }

Py_RSA_PrivateKey::Py_RSA_PrivateKey(std::string pem_str,
                                     Python_RandomNumberGenerator& rng)
   {
   DataSource_Memory in(pem_str);

   Private_Key* pkcs8_key =
      PKCS8::load_key(in,
                      rng.get_underlying_rng());

   rsa_key = dynamic_cast<RSA_PrivateKey*>(pkcs8_key);

   if(!rsa_key)
      throw std::invalid_argument("Key is not an RSA key");
   }

Py_RSA_PrivateKey::Py_RSA_PrivateKey(std::string pem_str,
                                     Python_RandomNumberGenerator& rng,
                                     std::string passphrase)
   {
   DataSource_Memory in(pem_str);

   Private_Key* pkcs8_key =
      PKCS8::load_key(in,
                      rng.get_underlying_rng(),
                      passphrase);

   rsa_key = dynamic_cast<RSA_PrivateKey*>(pkcs8_key);

   if(!rsa_key)
      throw std::invalid_argument("Key is not an RSA key");
   }

class Py_RSA_PublicKey
   {
   public:
      Py_RSA_PublicKey(std::string pem_str);
      Py_RSA_PublicKey(const Py_RSA_PrivateKey&);
      ~Py_RSA_PublicKey() { delete rsa_key; }

      std::string get_N() const { return bigint2str(get_bigint_N()); }
      std::string get_E() const { return bigint2str(get_bigint_E()); }

      const BigInt& get_bigint_N() const { return rsa_key->get_n(); }
      const BigInt& get_bigint_E() const { return rsa_key->get_e(); }

      std::string to_string() const
         {
         return X509::PEM_encode(*rsa_key);
         }

      std::string to_ber() const
         {
         SecureVector<byte> bits = X509::BER_encode(*rsa_key);

         return std::string(reinterpret_cast<const char*>(&bits[0]),
                            bits.size());
         }

      std::string encrypt(const std::string& in,
                          const std::string& padding,
                          Python_RandomNumberGenerator& rng);

      bool verify(const std::string& in,
                  const std::string& padding,
                  const std::string& signature);
   private:
      RSA_PublicKey* rsa_key;
   };

Py_RSA_PublicKey::Py_RSA_PublicKey(const Py_RSA_PrivateKey& priv)
   {
   rsa_key = new RSA_PublicKey(priv.get_bigint_N(), priv.get_bigint_E());
   }

Py_RSA_PublicKey::Py_RSA_PublicKey(std::string pem_str)
   {
   DataSource_Memory in(pem_str);
   Public_Key* x509_key = X509::load_key(in);

   rsa_key = dynamic_cast<RSA_PublicKey*>(x509_key);

   if(!rsa_key)
      throw std::invalid_argument("Key is not an RSA key");
   }

std::string Py_RSA_PublicKey::encrypt(const std::string& in,
                                      const std::string& padding,
                                      Python_RandomNumberGenerator& rng)
   {
   PK_Encryptor_EME enc(*rsa_key, padding);

   const byte* in_bytes = reinterpret_cast<const byte*>(in.data());

   return make_string(enc.encrypt(in_bytes, in.size(),
                                  rng.get_underlying_rng()));
   }

bool Py_RSA_PublicKey::verify(const std::string& in,
                              const std::string& signature,
                              const std::string& padding)
   {
   PK_Verifier ver(*rsa_key, padding);

   const byte* in_bytes = reinterpret_cast<const byte*>(in.data());
   const byte* sig_bytes = reinterpret_cast<const byte*>(signature.data());

   ver.update(in_bytes, in.size());
   return ver.check_signature(sig_bytes, signature.size());
   }

void export_rsa()
   {
   python::class_<Py_RSA_PublicKey>
      ("RSA_PublicKey", python::init<std::string>())
      .def(python::init<const Py_RSA_PrivateKey&>())
      .def("to_string", &Py_RSA_PublicKey::to_string)
      .def("to_ber", &Py_RSA_PublicKey::to_ber)
      .def("encrypt", &Py_RSA_PublicKey::encrypt)
      .def("verify", &Py_RSA_PublicKey::verify)
      .def("get_N", &Py_RSA_PublicKey::get_N)
      .def("get_E", &Py_RSA_PublicKey::get_E);

   python::class_<Py_RSA_PrivateKey>
      ("RSA_PrivateKey", python::init<std::string, Python_RandomNumberGenerator&, std::string>())
       .def(python::init<std::string, Python_RandomNumberGenerator&>())
       .def(python::init<u32bit, Python_RandomNumberGenerator&>())
       .def("to_string", &Py_RSA_PrivateKey::to_string)
       .def("to_ber", &Py_RSA_PrivateKey::to_ber)
       .def("decrypt", &Py_RSA_PrivateKey::decrypt)
       .def("sign", &Py_RSA_PrivateKey::sign)
       .def("get_N", &Py_RSA_PrivateKey::get_N)
       .def("get_E", &Py_RSA_PrivateKey::get_E);
   }
