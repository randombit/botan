/*************************************************
* Public Key Operations Header File              *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_PK_OPS_H__
#define BOTAN_PK_OPS_H__

#include <botan/bigint.h>
#include <botan/dl_group.h>

namespace Botan {

/*************************************************
* IF Operation                                   *
*************************************************/
class BOTAN_DLL IF_Operation
   {
   public:
      virtual BigInt public_op(const BigInt&) const = 0;
      virtual BigInt private_op(const BigInt&) const = 0;
      virtual IF_Operation* clone() const = 0;
      virtual ~IF_Operation() {}
   };

/*************************************************
* DSA Operation                                  *
*************************************************/
class BOTAN_DLL DSA_Operation
   {
   public:
      virtual bool verify(const byte[], u32bit,
                          const byte[], u32bit) const = 0;
      virtual SecureVector<byte> sign(const byte[], u32bit,
                                      const BigInt&) const = 0;
      virtual DSA_Operation* clone() const = 0;
      virtual ~DSA_Operation() {}
   };

/*************************************************
* NR Operation                                   *
*************************************************/
class BOTAN_DLL NR_Operation
   {
   public:
      virtual SecureVector<byte> verify(const byte[], u32bit) const = 0;
      virtual SecureVector<byte> sign(const byte[], u32bit,
                                      const BigInt&) const = 0;
      virtual NR_Operation* clone() const = 0;
      virtual ~NR_Operation() {}
   };

/*************************************************
* ElGamal Operation                              *
*************************************************/
class BOTAN_DLL ELG_Operation
   {
   public:
      virtual SecureVector<byte> encrypt(const byte[], u32bit,
                                         const BigInt&) const = 0;
      virtual BigInt decrypt(const BigInt&, const BigInt&) const = 0;
      virtual ELG_Operation* clone() const = 0;
      virtual ~ELG_Operation() {}
   };

/*************************************************
* DH Operation                                   *
*************************************************/
class BOTAN_DLL DH_Operation
   {
   public:
      virtual BigInt agree(const BigInt&) const = 0;
      virtual DH_Operation* clone() const = 0;
      virtual ~DH_Operation() {}
   };

}

#endif
