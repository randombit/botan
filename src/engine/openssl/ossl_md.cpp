/*
* OpenSSL Hash Functions
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/eng_ossl.h>
#include <openssl/evp.h>

namespace Botan {

namespace {

/*
* EVP Hash Function
*/
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

/*
* Update an EVP Hash Calculation
*/
void EVP_HashFunction::add_data(const byte input[], u32bit length)
   {
   EVP_DigestUpdate(&md, input, length);
   }

/*
* Finalize an EVP Hash Calculation
*/
void EVP_HashFunction::final_result(byte output[])
   {
   EVP_DigestFinal_ex(&md, output, 0);
   const EVP_MD* algo = EVP_MD_CTX_md(&md);
   EVP_DigestInit_ex(&md, algo, 0);
   }

/*
* Clear memory of sensitive data
*/
void EVP_HashFunction::clear() throw()
   {
   const EVP_MD* algo = EVP_MD_CTX_md(&md);
   EVP_DigestInit_ex(&md, algo, 0);
   }

/*
* Return a clone of this object
*/
HashFunction* EVP_HashFunction::clone() const
   {
   const EVP_MD* algo = EVP_MD_CTX_md(&md);
   return new EVP_HashFunction(algo, name());
   }

/*
* Create an EVP hash function
*/
EVP_HashFunction::EVP_HashFunction(const EVP_MD* algo,
                                   const std::string& name) :
   HashFunction(EVP_MD_size(algo), EVP_MD_block_size(algo)),
   algo_name(name)
   {
   EVP_MD_CTX_init(&md);
   EVP_DigestInit_ex(&md, algo, 0);
   }

/*
* Destroy an EVP hash function
*/
EVP_HashFunction::~EVP_HashFunction()
   {
   EVP_MD_CTX_cleanup(&md);
   }

}

/*
* Look for an algorithm with this name
*/
HashFunction* OpenSSL_Engine::find_hash(const SCAN_Name& request,
                                        Algorithm_Factory&) const
   {
#ifndef OPENSSL_NO_SHA
   if(request.algo_name() == "SHA-160")
      return new EVP_HashFunction(EVP_sha1(), "SHA-160");
#endif

#ifndef OPENSSL_NO_MD2
   if(request.algo_name() == "MD2")
      return new EVP_HashFunction(EVP_md2(), "MD2");
#endif

#ifndef OPENSSL_NO_MD4
   if(request.algo_name() == "MD4")
      return new EVP_HashFunction(EVP_md4(), "MD4");
#endif

#ifndef OPENSSL_NO_MD5
   if(request.algo_name() == "MD5")
      return new EVP_HashFunction(EVP_md5(), "MD5");
#endif

#ifndef OPENSSL_NO_RIPEMD
   if(request.algo_name() == "RIPEMD-160")
      return new EVP_HashFunction(EVP_ripemd160(), "RIPEMD-160");
#endif

   return 0;
   }

}
