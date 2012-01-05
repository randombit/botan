/*
* SRP-6a (RFC 5054 compatatible)
* (C) 2011 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_RFC5054_SRP6_H__
#define BOTAN_RFC5054_SRP6_H__

#include <botan/bigint.h>
#include <botan/hash.h>
#include <botan/rng.h>
#include <botan/symkey.h>
#include <string>

namespace Botan {

/**
* Represents a SRP-6a client session
*/
class BOTAN_DLL SRP6_Client_Session
   {
   public:

      /**
      * Client side step 1
      * @param username the username we are attempting login for
      * @param password the password we are attempting to use
      * @param group_id specifies the shared SRP group
      * @param hash_id specifies a secure hash function
      * @param salt is the salt value sent by the server
      * @param B is the server's public value
      * @param rng is a random number generator
      *
      * @return (A,K) the client public key and the shared secret key
      */
      std::pair<BigInt,SymmetricKey> step1(const std::string& username,
                                           const std::string& password,
                                           const std::string& group_id,
                                           const std::string& hash_id,
                                           const MemoryRegion<byte>& salt,
                                           const BigInt& B,
                                           RandomNumberGenerator& rng);

      /**
      * Generate a new SRP-6 verifier
      * @param identifier a username or other client identifier
      * @param password the secret used to authenticate user
      * @param salt a randomly chosen value, at least 128 bits long
      */
      static BigInt generate_verifier(const std::string& identifier,
                                      const std::string& password,
                                      const MemoryRegion<byte>& salt,
                                      const std::string& group_id,
                                      const std::string& hash_id);
   };

/**
* Represents a SRP-6a server session
*/
class BOTAN_DLL SRP6_Server_Session
   {
   public:
      /**
      * Server side step 1
      * @param v the verification value saved from client registration
      */
      BigInt step1(const BigInt& v,
                   const std::string& group_id,
                   const std::string& hash_id,
                   RandomNumberGenerator& rng);

      SymmetricKey step2(const BigInt& A);

   private:
      std::string hash_id;
      BigInt B, b, v, S, p;
      size_t p_bytes;
   };

}

#endif
