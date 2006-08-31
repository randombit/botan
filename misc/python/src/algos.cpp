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

      std::string name() const { return cipher->name(); }
      void clear() throw() { cipher->clear(); }

      std::string encrypt(const std::string& in) const
         {
         return process(in, cipher, &BlockCipher::encrypt);
         }
      std::string decrypt(const std::string& in) const
         {
         return process(in, cipher, &BlockCipher::decrypt);
         }

      void set_key(const OctetString& key) { cipher->set_key(key); }

      Py_BlockCipher(const std::string& name)
         {
         cipher = get_block_cipher(name);
         }
      ~Py_BlockCipher() { delete cipher; }
   private:
      BlockCipher* cipher;
   };

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

class Py_HashFunction
   {
   public:
      u32bit output_length() const { return hash->OUTPUT_LENGTH; }
      std::string name() const { return hash->name(); }
      void clear() throw() { hash->clear(); }

      void update(const std::string& in) { hash->update(in); }

      std::string final()
         {
         SecureVector<byte> result = hash->final();
         return std::string((const char*)result.begin(), result.size());
         }

      Py_HashFunction(const std::string& name)
         {
         hash = get_hash(name);
         }
      ~Py_HashFunction() { delete hash; }
   private:
      HashFunction* hash;
   };

class Py_MAC
   {
   public:
      u32bit output_length() const { return mac->OUTPUT_LENGTH; }
      u32bit keylength_min() const { return mac->MINIMUM_KEYLENGTH; }
      u32bit keylength_max() const { return mac->MAXIMUM_KEYLENGTH; }
      u32bit keylength_mod() const { return mac->KEYLENGTH_MULTIPLE; }
      std::string name() const { return mac->name(); }
      void clear() throw() { mac->clear(); }

      void set_key(const OctetString& key) { mac->set_key(key); }

      bool valid_keylength(u32bit kl) const
         {
         return mac->valid_keylength(kl);
         }

      void update(const std::string& in) { mac->update(in); }

      std::string final()
         {
         SecureVector<byte> result = mac->final();
         return std::string((const char*)result.begin(), result.size());
         }

      Py_MAC(const std::string& name)
         {
         mac = get_mac(name);
         }
      ~Py_MAC() { delete mac; }
   private:
      MessageAuthenticationCode* mac;
   };

void export_basic_algos()
   {
   python::class_<Py_BlockCipher>("BlockCipher", python::init<std::string>())
      .add_property("block_size", &Py_BlockCipher::block_size)
      .add_property("keylength_min", &Py_BlockCipher::keylength_min)
      .add_property("keylength_max", &Py_BlockCipher::keylength_max)
      .add_property("keylength_mod", &Py_BlockCipher::keylength_mod)
      .add_property("name", &Py_BlockCipher::name)
      .def("clear", &Py_BlockCipher::clear)
      .def("valid_keylength", &Py_BlockCipher::valid_keylength)
      .def("set_key", &Py_BlockCipher::set_key)
      .def("encrypt", &Py_BlockCipher::encrypt)
      .def("decrypt", &Py_BlockCipher::decrypt);

   python::class_<Py_StreamCipher>("StreamCipher", python::init<std::string>())
      .add_property("keylength_min", &Py_StreamCipher::keylength_min)
      .add_property("keylength_max", &Py_StreamCipher::keylength_max)
      .add_property("keylength_mod", &Py_StreamCipher::keylength_mod)
      .add_property("name", &Py_StreamCipher::name)
      .def("clear", &Py_StreamCipher::clear)
      .def("valid_keylength", &Py_StreamCipher::valid_keylength)
      .def("set_key", &Py_StreamCipher::set_key)
      .def("crypt", &Py_StreamCipher::crypt);

   python::class_<Py_HashFunction>("HashFunction", python::init<std::string>())
      .add_property("output_length", &Py_HashFunction::output_length)
      .add_property("name", &Py_HashFunction::name)
      .def("clear", &Py_HashFunction::clear)
      .def("update", &Py_HashFunction::update)
      .def("final", &Py_HashFunction::final);

   python::class_<Py_MAC>("MAC", python::init<std::string>())
      .add_property("output_length", &Py_MAC::output_length)
      .add_property("keylength_min", &Py_MAC::keylength_min)
      .add_property("keylength_max", &Py_MAC::keylength_max)
      .add_property("keylength_mod", &Py_MAC::keylength_mod)
      .add_property("name", &Py_MAC::name)
      .def("valid_keylength", &Py_MAC::valid_keylength)
      .def("set_key", &Py_MAC::set_key)
      .def("clear", &Py_MAC::clear)
      .def("update", &Py_MAC::update)
      .def("final", &Py_MAC::final);
   }
