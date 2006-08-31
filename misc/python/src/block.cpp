/*************************************************
* Boost.Python module definition                 *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/botan.h>
using namespace Botan;

#include <boost/python.hpp>
namespace python = boost::python;

/* Encrypt or decrypt */
std::string process(const std::string& in, BlockCipher* cipher,
                    void (BlockCipher::* proc)(const byte[], byte[]) const)
   {
   if(in.size() != cipher->BLOCK_SIZE)
      throw Invalid_Argument("Input for cipher " + cipher->name() +
                             " must be " + to_string(cipher->BLOCK_SIZE) +
                             " bytes");

   const byte* in_data = (const byte*)in.data();

   SecureVector<byte> out(cipher->BLOCK_SIZE);
   (cipher->*proc)(in_data, out);

   return std::string((const char*)out.begin(), out.size());
   }

class Py_BlockCipher
   {
   public:
      u32bit block_size() const { return cipher->BLOCK_SIZE; }
      u32bit keylength_min() const { return cipher->MINIMUM_KEYLENGTH; }
      u32bit keylength_max() const { return cipher->MAXIMUM_KEYLENGTH; }
      u32bit keylength_mod() const { return cipher->KEYLENGTH_MULTIPLE; }

      bool valid_keylength(u32bit kl) const
         {
         return cipher->valid_keylength(kl);
         }

      std::string encrypt(const std::string& in) const
         {
         return process(in, cipher, &BlockCipher::encrypt);
         }
      std::string decrypt(const std::string& in) const
         {
         return process(in, cipher, &BlockCipher::decrypt);
         }

      void set_key(const OctetString& key)
         {
         cipher->set_key(key);
         }

      Py_BlockCipher(const std::string& name)
         {
         cipher = get_block_cipher(name);
         }
      ~Py_BlockCipher()
         {
         delete cipher;
         }
   private:
      BlockCipher* cipher;
   };

void export_block_ciphers()
   {
   python::class_<Py_BlockCipher>("BlockCipher", python::init<std::string>())
      .add_property("block_size", &Py_BlockCipher::block_size)
      .add_property("keylength_min", &Py_BlockCipher::keylength_min)
      .add_property("keylength_max", &Py_BlockCipher::keylength_max)
      .add_property("keylength_mod", &Py_BlockCipher::keylength_mod)
      .def("valid_keylength", &Py_BlockCipher::valid_keylength)
      .def("set_key", &Py_BlockCipher::set_key)
      .def("encrypt", &Py_BlockCipher::encrypt)
      .def("decrypt", &Py_BlockCipher::decrypt);
   }
