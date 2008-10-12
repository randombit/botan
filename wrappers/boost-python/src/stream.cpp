/*************************************************
* Boost.Python module definition                 *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/botan.h>
using namespace Botan;

#include "python_botan.h"

class Py_StreamCipher
   {
   public:
      u32bit keylength_min() const { return cipher->MINIMUM_KEYLENGTH; }
      u32bit keylength_max() const { return cipher->MAXIMUM_KEYLENGTH; }
      u32bit keylength_mod() const { return cipher->KEYLENGTH_MULTIPLE; }

      void set_key(const OctetString& key) { cipher->set_key(key); }
      bool valid_keylength(u32bit kl) const
         {
         return cipher->valid_keylength(kl);
         }

      std::string name() const { return cipher->name(); }
      void clear() throw() { cipher->clear(); }

      std::string crypt(const std::string& in) const
         {
         SecureVector<byte> out(in.size());
         cipher->encrypt((const byte*)in.data(), out.begin(), in.size());
         return std::string((const char*)out.begin(), out.size());
         }

      Py_StreamCipher(const std::string& name)
         {
         cipher = get_stream_cipher(name);
         }
      ~Py_StreamCipher() { delete cipher; }
   private:
      StreamCipher* cipher;
   };

void export_stream_ciphers()
   {
   python::class_<Py_StreamCipher>("StreamCipher", python::init<std::string>())
      .add_property("keylength_min", &Py_StreamCipher::keylength_min)
      .add_property("keylength_max", &Py_StreamCipher::keylength_max)
      .add_property("keylength_mod", &Py_StreamCipher::keylength_mod)
      .add_property("name", &Py_StreamCipher::name)
      .def("clear", &Py_StreamCipher::clear)
      .def("valid_keylength", &Py_StreamCipher::valid_keylength)
      .def("set_key", &Py_StreamCipher::set_key)
      .def("crypt", &Py_StreamCipher::crypt);
   }
