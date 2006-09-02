/*************************************************
* Boost.Python module definition                 *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/botan.h>
using namespace Botan;

#include <boost/python.hpp>
namespace python = boost::python;

class Bad_Size : public Exception
   {
   public:
      Bad_Size(const std::string& name, u32bit got, u32bit expected) :
         Exception("Bad size encountered in " + name + "; got " +
                   to_string(got) + " bytes, expected " + to_string(expected))
         {}
   };

class Py_BlockCipher : public BlockCipher
   {
   public:
      virtual std::string enc_str(const std::string&) const = 0;
      virtual std::string dec_str(const std::string&) const = 0;
      virtual void set_key_obj(const OctetString&) = 0;

      void enc(const byte in[], byte out[]) const
         {
         std::string out_str = enc_str(
            std::string((const char*)in, BLOCK_SIZE)
            );
         if(out_str.size() != BLOCK_SIZE)
            throw Bad_Size(name(), out_str.size(), BLOCK_SIZE);
         std::memcpy(out, out_str.data(), BLOCK_SIZE);
         }

      void dec(const byte in[], byte out[]) const
         {
         std::string out_str = dec_str(
            std::string((const char*)in, BLOCK_SIZE)
            );
         if(out_str.size() != BLOCK_SIZE)
            throw Bad_Size(name(), out_str.size(), BLOCK_SIZE);
         std::memcpy(out, out_str.data(), BLOCK_SIZE);
         }

      void key(const byte key[], u32bit len)
         {
         set_key_obj(OctetString(key, len));
         }

      Py_BlockCipher(u32bit bs, u32bit kmin, u32bit kmax, u32bit kmod) :
         BlockCipher(bs, kmin, kmax, kmod)
         {
         }
   };

std::string encrypt_string(BlockCipher* cipher, const std::string& in)
   {
   if(in.size() != cipher->BLOCK_SIZE)
      throw Bad_Size(cipher->name(), in.size(), cipher->BLOCK_SIZE);

   SecureVector<byte> out(cipher->BLOCK_SIZE);
   cipher->encrypt((const byte*)in.data(), out);
   return std::string((const char*)out.begin(), out.size());
   }

std::string decrypt_string(BlockCipher* cipher, const std::string& in)
   {
   if(in.size() != cipher->BLOCK_SIZE)
      throw Bad_Size(cipher->name(), in.size(), cipher->BLOCK_SIZE);

   SecureVector<byte> out(cipher->BLOCK_SIZE);
   cipher->decrypt((const byte*)in.data(), out);
   return std::string((const char*)out.begin(), out.size());
   }

template<typename T>
python::object get_owner(T* me)
   {
   return python::object(
      python::handle<>(
         python::borrowed(python::detail::wrapper_base_::get_owner(*me))));
   }

class Wrapped_Block_Cipher : public BlockCipher
   {
   public:
      void enc(const byte in[], byte out[]) const { cipher->encrypt(in, out); }
      void dec(const byte in[], byte out[]) const { cipher->decrypt(in, out); }
      void key(const byte key[], u32bit len) { cipher->set_key(key, len); }
      std::string name() const { return cipher->name(); }
      BlockCipher* clone() const { return cipher->clone(); }

      Wrapped_Block_Cipher(python::object py_obj, BlockCipher* c) :
         BlockCipher(c->BLOCK_SIZE, c->MINIMUM_KEYLENGTH,
                     c->MAXIMUM_KEYLENGTH, c->KEYLENGTH_MULTIPLE),
         obj(py_obj), cipher(c) {}
   private:
      python::object obj;
      BlockCipher* cipher;
   };

class Py_BlockCipher_Wrapper : public Py_BlockCipher,
                               public python::wrapper<Py_BlockCipher>
   {
   public:
      BlockCipher* clone() const
         {
         python::object self = get_owner(this);
         python::object py_clone = self.attr("__class__")();
         BlockCipher* bc = python::extract<BlockCipher*>(py_clone);
         return new Wrapped_Block_Cipher(py_clone, bc);
         }

      std::string name() const
         {
         return this->get_override("name")();
         }

      std::string enc_str(const std::string& in) const
         {
         return this->get_override("encrypt")(in);
         }

      std::string dec_str(const std::string& in) const
         {
         return this->get_override("decrypt")(in);
         }

      void set_key_obj(const OctetString& key)
         {
         this->get_override("set_key")(key);
         }

      Py_BlockCipher_Wrapper(u32bit bs, u32bit kmin,
                             u32bit kmax, u32bit kmod) :
         Py_BlockCipher(bs, kmin, kmax, kmod) {}
   };

void export_block_ciphers()
   {
   void (BlockCipher::*set_key_ptr)(const OctetString&) =
      &BlockCipher::set_key;

   python::class_<BlockCipher, boost::noncopyable>
      ("BlockCipher", python::no_init)
      .def("__init__", python::make_constructor(get_block_cipher))
      .def_readonly("block_size", &BlockCipher::BLOCK_SIZE)
      .def_readonly("keylength_min", &BlockCipher::MINIMUM_KEYLENGTH)
      .def_readonly("keylength_max", &BlockCipher::MAXIMUM_KEYLENGTH)
      .def_readonly("keylength_mod", &BlockCipher::KEYLENGTH_MULTIPLE)
      .def("valid_keylength", &BlockCipher::valid_keylength)
      .def("name", &BlockCipher::name)
      .def("set_key", set_key_ptr)
      .def("encrypt", encrypt_string)
      .def("decrypt", decrypt_string);

   python::class_<Py_BlockCipher_Wrapper, python::bases<BlockCipher>,
                  boost::noncopyable>
      ("BlockCipherImpl", python::init<u32bit, u32bit, u32bit, u32bit>())
      .def("name", python::pure_virtual(&Py_BlockCipher::name))
      .def("encrypt", python::pure_virtual(&Py_BlockCipher::enc_str))
      .def("decrypt", python::pure_virtual(&Py_BlockCipher::dec_str))
      .def("set_key", python::pure_virtual(&Py_BlockCipher::set_key_obj));
   }
