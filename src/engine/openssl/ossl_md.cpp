/*
* OpenSSL Hash Functions
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/openssl_engine.h>
#include <openssl/evp.h>

#if OPENSSL_VERSION_NUMBER >= 0x10100000
  #error "OpenSSL 1.1 API not supported in Botan 1.10, upgrade to 2.x"
#endif

namespace Botan {

namespace {

/*
* EVP Hash Function
*/
class EVP_HashFunction : public HashFunction
   {
   public:
      void clear();
      std::string name() const { return algo_name; }
      HashFunction* clone() const;

      size_t output_length() const
         {
         return EVP_MD_size(EVP_MD_CTX_md(&md));
         }

      size_t hash_block_size() const
         {
         return EVP_MD_block_size(EVP_MD_CTX_md(&md));
         }

      EVP_HashFunction(const EVP_MD*, const std::string&);
      ~EVP_HashFunction();
   private:
      void add_data(const byte[], size_t);
      void final_result(byte[]);

      size_t block_size;
      std::string algo_name;
      EVP_MD_CTX md;
   };

/*
* Update an EVP Hash Calculation
*/
void EVP_HashFunction::add_data(const byte input[], size_t length)
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
void EVP_HashFunction::clear()
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
#if !defined(OPENSSL_NO_SHA)
   if(request.algo_name() == "SHA-160")
      return new EVP_HashFunction(EVP_sha1(), "SHA-160");
#endif

#if !defined(OPENSSL_NO_SHA256)
   if(request.algo_name() == "SHA-224")
      return new EVP_HashFunction(EVP_sha224(), "SHA-224");
   if(request.algo_name() == "SHA-256")
      return new EVP_HashFunction(EVP_sha256(), "SHA-256");
#endif

#if !defined(OPENSSL_NO_SHA512)
   if(request.algo_name() == "SHA-384")
      return new EVP_HashFunction(EVP_sha384(), "SHA-384");
   if(request.algo_name() == "SHA-512")
      return new EVP_HashFunction(EVP_sha512(), "SHA-512");
#endif

#if !defined(OPENSSL_NO_MD2)
   if(request.algo_name() == "MD2")
      return new EVP_HashFunction(EVP_md2(), "MD2");
#endif

#if !defined(OPENSSL_NO_MD4)
   if(request.algo_name() == "MD4")
      return new EVP_HashFunction(EVP_md4(), "MD4");
#endif

#if !defined(OPENSSL_NO_MD5)
   if(request.algo_name() == "MD5")
      return new EVP_HashFunction(EVP_md5(), "MD5");
#endif

#if !defined(OPENSSL_NO_RIPEMD)
   if(request.algo_name() == "RIPEMD-160")
      return new EVP_HashFunction(EVP_ripemd160(), "RIPEMD-160");
#endif

   return 0;
   }

}
