/*************************************************
* OpenSSL Hash Functions Source File             *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/eng_ossl.h>
#include <botan/parsing.h>
#include <botan/libstate.h>
#include <openssl/evp.h>

namespace Botan {

namespace {

/*************************************************
* EVP Hash Function                              *
*************************************************/
class EVP_HashFunction : public HashFunction
   {
   public:
      void clear() throw();
      std::string name() const { return algo_name; }
      HashFunction* clone() const;
      EVP_HashFunction(const EVP_MD*, const std::string&);
      ~EVP_HashFunction();
   private:
      void add_data(const byte[], u32bit);
      void final_result(byte[]);

      std::string algo_name;
      EVP_MD_CTX md;
   };

/*************************************************
* Update an EVP Hash Calculation                 *
*************************************************/
void EVP_HashFunction::add_data(const byte input[], u32bit length)
   {
   EVP_DigestUpdate(&md, input, length);
   }

/*************************************************
* Finalize an EVP Hash Calculation               *
*************************************************/
void EVP_HashFunction::final_result(byte output[])
   {
   EVP_DigestFinal_ex(&md, output, 0);
   const EVP_MD* algo = EVP_MD_CTX_md(&md);
   EVP_DigestInit_ex(&md, algo, 0);
   }

/*************************************************
* Clear memory of sensitive data                 *
*************************************************/
void EVP_HashFunction::clear() throw()
   {
   const EVP_MD* algo = EVP_MD_CTX_md(&md);
   EVP_DigestInit_ex(&md, algo, 0);
   }

/*************************************************
* Return a clone of this object                  *
*************************************************/
HashFunction* EVP_HashFunction::clone() const
   {
   const EVP_MD* algo = EVP_MD_CTX_md(&md);
   return new EVP_HashFunction(algo, name());
   }

/*************************************************
* Create an EVP hash function                    *
*************************************************/
EVP_HashFunction::EVP_HashFunction(const EVP_MD* algo,
                                   const std::string& name) :
   HashFunction(EVP_MD_size(algo), EVP_MD_block_size(algo)),
   algo_name(name)
   {
   EVP_MD_CTX_init(&md);
   EVP_DigestInit_ex(&md, algo, 0);
   }

/*************************************************
* Destroy an EVP hash function                   *
*************************************************/
EVP_HashFunction::~EVP_HashFunction()
   {
   EVP_MD_CTX_cleanup(&md);
   }

}

/*************************************************
* Look for an algorithm with this name           *
*************************************************/
HashFunction* OpenSSL_Engine::find_hash(const std::string& algo_spec) const
   {
   std::vector<std::string> name = parse_algorithm_name(algo_spec);
   if(name.size() == 0)
      return 0;
   const std::string algo_name = global_state().deref_alias(name[0]);

#define HANDLE_EVP_MD(NAME, EVP)                 \
   if(algo_name == NAME)                         \
      {                                          \
      if(name.size() == 1)                       \
         return new EVP_HashFunction(EVP, NAME); \
      throw Invalid_Algorithm_Name(algo_spec);   \
      }

   HANDLE_EVP_MD("SHA-160", EVP_sha1());
   HANDLE_EVP_MD("MD2", EVP_md2());
   HANDLE_EVP_MD("MD4", EVP_md4());
   HANDLE_EVP_MD("MD5", EVP_md5());
   HANDLE_EVP_MD("RIPEMD-160", EVP_ripemd160());

#undef HANDLE_EVP_MD

   return 0;
   }

}
