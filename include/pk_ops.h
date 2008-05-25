/*************************************************
* Public Key Operations Header File              *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_PK_OPS_H__
#define BOTAN_PK_OPS_H__

#include <botan/pointers.h>
#include <botan/bigint.h>
#include <botan/dl_group.h>
#include <botan/point_gfp.h>
#include <botan/ecdsa.h>

namespace Botan {

/*************************************************
* IF Operation                                   *
*************************************************/
class IF_Operation
   {
   public:
	  virtual BigInt public_op(const BigInt&) const = 0;
      virtual BigInt private_op(const BigInt&) const = 0;
      virtual std::auto_ptr<IF_Operation> clone() const = 0;
      virtual ~IF_Operation() {}
   };

/*************************************************
* DSA Operation                                  *
*************************************************/
class DSA_Operation
   {
   public:
      virtual bool verify(const byte[], u32bit,
                          const byte[], u32bit) const = 0;
      virtual SecureVector<byte> sign(const byte[], u32bit,
                                      const BigInt&) const = 0;
      virtual std::auto_ptr<DSA_Operation> clone() const = 0;
      virtual ~DSA_Operation() {}
   };

/*************************************************
* NR Operation                                   *
*************************************************/
class NR_Operation
   {
   public:
      virtual SecureVector<byte> verify(const byte[], u32bit) const = 0;
      virtual SecureVector<byte> sign(const byte[], u32bit,
                                      const BigInt&) const = 0;
      virtual std::auto_ptr<NR_Operation> clone() const = 0;
      virtual ~NR_Operation() {}
   };

/*************************************************
* ElGamal Operation                              *
*************************************************/
class ELG_Operation
   {
   public:
      virtual SecureVector<byte> encrypt(const byte[], u32bit,
                                         const BigInt&) const = 0;
      virtual BigInt decrypt(const BigInt&, const BigInt&) const = 0;
      virtual std::auto_ptr<ELG_Operation> clone() const = 0;
      virtual ~ELG_Operation() {}
   };

/*************************************************
* DH Operation                                   *
*************************************************/
class DH_Operation
   {
   public:
      virtual BigInt agree(const BigInt&) const = 0;
      virtual std::auto_ptr<DH_Operation> clone() const = 0;
      virtual ~DH_Operation() {}
   };

/*************************************************
* ECDSA Operation                               *
*************************************************/
class ECDSA_Operation
   {
   public:
      virtual bool const verify(const byte signature[], u32bit sig_len, const byte message[], Botan::u32bit mess_len) const = 0;
          
      virtual SecureVector<byte> const sign( const byte message[], u32bit mess_len) const = 0;
      virtual std::auto_ptr<ECDSA_Operation> clone() const = 0;
      virtual ~ECDSA_Operation() {}
   };

/*************************************************
* ECKAEG Operation                               *
*************************************************/
class ECKAEG_Operation
   {
   public:
	  virtual SecureVector<byte> agree(const Botan::math::ec::PointGFp&) const = 0;
      virtual std::auto_ptr<ECKAEG_Operation> clone() const = 0;
      virtual ~ECKAEG_Operation() {}
   };

}

#endif
