/*************************************************
* Boost.Python module definition                 *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/rsa.h>
#include <botan/dsa.h>
#include <botan/dh.h>
#include <botan/look_pk.h>
using namespace Botan;

#include <boost/python.hpp>
namespace python = boost::python;

std::string encode_pub(const Public_Key* key,
                       const std::string& type)
   {
   if(type == "DER")
      {
      Pipe pipe;
      pipe.start_msg();
      X509::encode(*key, pipe, RAW_BER);
      pipe.end_msg();
      return pipe.read_all_as_string();
      }
   else if(type == "PEM")
      return X509::PEM_encode(*key);
   else
      throw Encoding_Error("Unknown key encoding method " + type);
   }

std::string encode_priv(const Private_Key* key,
                        const std::string& type)
   {
   if(type == "DER")
      {
      Pipe pipe;
      PKCS8::encode(*key, pipe, RAW_BER);
      return pipe.read_all_as_string();
      }
   else if(type == "PEM")
      return PKCS8::PEM_encode(*key);
   else
      throw Encoding_Error("Unknown key encoding method " + type);
   }

/*
Private_Key* load_priv(const std::string& file, const std::string& pass)
   {
   return PKCS8::load_key(file, pass);
   }

Public_Key* load_public(const std::string& file)
   {
   return X509::load_key(file);
   }
*/

/*
std::string encrypt_string(const PK_Encryptor* enc, const std::string& in)
   {
   SecureVector<byte> cipher = enc->encrypt((const byte*)in.data(), in.length());
   return std::string((const char*)cipher.begin(), cipher.size());
   }

std::string decrypt_string(const PK_Decryptor* dec, const std::string& in)
   {
   SecureVector<byte> plain = dec->decrypt((const byte*)in.data(), in.length());
   return std::string((const char*)plain.begin(), plain.size());
   }
*/

void export_pk()
   {
   /*
   python::def("private_key", load_priv,
               python::return_value_policy<python::manage_new_object>());
   python::def("public_key", load_public,
               python::return_value_policy<python::manage_new_object>());
   */

   python::class_<Public_Key, boost::noncopyable>
      ("Public_Key", python::no_init)
      .add_property("name", &Public_Key::algo_name)
      .add_property("max_input_bits", &Public_Key::max_input_bits)
      .def("public_key", encode_pub);

   python::class_<PK_Encrypting_Key, python::bases<Public_Key>, boost::noncopyable>
      ("PK_Encrypting_Key", python::no_init);

   python::class_<Private_Key, python::bases<Public_Key>, boost::noncopyable>
      ("Private_Key", python::no_init)
      .def("private_key", encode_priv);

   python::class_<PK_Decrypting_Key, python::bases<Private_Key>, boost::noncopyable>
      ("PK_Decrypting_Key", python::no_init);

   python::class_<RSA_PublicKey, python::bases<PK_Encrypting_Key> >
      ("RSA_PublicKey", python::no_init);

   python::class_<DSA_PublicKey, python::bases<Public_Key> >
      ("DSA_PublicKey", python::no_init);

   /*
   python::class_<RSA_PrivateKey, python::bases<RSA_PublicKey, PK_Decrypting_Key> >
      ("RSA_PrivateKey", python::init<u32bit>());
   */

   /*
   python::class_<PK_Encryptor, boost::noncopyable>
      ("PK_Encryptor", python::no_init)
      .def("__init__",
           python::make_constructor(get_pk_encryptor,
                                    python::with_custodian_and_ward_postcall<0, 1>()))
      .def("max_input", &PK_Encryptor::maximum_input_size)
      .def("encrypt", encrypt_string);
   */

   /*
   python::class_<PK_Decryptor, boost::noncopyable>
      ("PK_Decryptor", python::no_init)
      .def("__init__", python::make_constructor(get_pk_decryptor))
      .def("decrypt", decrypt_string);
   */
   }
