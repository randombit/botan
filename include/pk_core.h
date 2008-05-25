/*************************************************
* PK Algorithm Core Header File                  *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_PK_CORE_H__
#define BOTAN_PK_CORE_H__

#include <botan/pointers.h>

#include <botan/dl_group.h>
#include <botan/blinding.h>
#include <botan/pk_ops.h>
#include <botan/bigint.h>
#include <botan/ec_dompar.h>
#include <botan/ecdsa.h>

namespace Botan {

/*************************************************
* IF Core                                        *
*************************************************/
class IF_Core
   {
   public:
	  BigInt public_op(const BigInt&) const;
      BigInt private_op(const BigInt&) const;

      IF_Core& operator=(const IF_Core&);

      IF_Core() : op() { }
      IF_Core(const IF_Core&);
      IF_Core(const BigInt&, const BigInt&,
              const BigInt& = 0, const BigInt& = 0, const BigInt& = 0,
              const BigInt& = 0, const BigInt& = 0, const BigInt& = 0);
      ~IF_Core() { } 
   private:
     std::tr1::shared_ptr<IF_Operation> op;
     Blinder blinder;
   };

/*************************************************
* DSA Core                                       *
*************************************************/
class DSA_Core
   {
   public:
      SecureVector<byte> sign(const byte[], u32bit, const BigInt&) const;
      bool verify(const byte[], u32bit, const byte[], u32bit) const;

      DSA_Core& operator=(const DSA_Core&);

      DSA_Core() : op() { }
      DSA_Core(const DSA_Core&);
      DSA_Core(const DL_Group&, const BigInt&, const BigInt& = 0);
      ~DSA_Core() {  }
   private:
     std::tr1::shared_ptr<DSA_Operation> op;
   };

/*************************************************
* NR Core                                        *
*************************************************/
class NR_Core
   {
   public:
      SecureVector<byte> sign(const byte[], u32bit, const BigInt&) const;
      SecureVector<byte> verify(const byte[], u32bit) const;

      NR_Core& operator=(const NR_Core&);

      NR_Core() : op() { }
      NR_Core(const NR_Core&);
      NR_Core(const DL_Group&, const BigInt&, const BigInt& = 0);
      ~NR_Core() { }
   private:
     std::tr1::shared_ptr<NR_Operation> op;
   };

/*************************************************
* ElGamal Core                                   *
*************************************************/
class ELG_Core
   {
   public:
      SecureVector<byte> encrypt(const byte[], u32bit, const BigInt&) const;
      SecureVector<byte> decrypt(const byte[], u32bit) const;

      ELG_Core& operator=(const ELG_Core&);

      ELG_Core() : op() { }
      ELG_Core(const ELG_Core&);
      ELG_Core(const DL_Group&, const BigInt&, const BigInt& = 0);
      ~ELG_Core() {  }
   private:
     std::tr1::shared_ptr<ELG_Operation> op;
      Blinder blinder;
      u32bit p_bytes;
   };

/*************************************************
* DH Core                                        *
*************************************************/
class DH_Core
   {
   public:
      BigInt agree(const BigInt&) const;

      DH_Core& operator=(const DH_Core&);

      DH_Core() : op() { }
      DH_Core(const DH_Core&);
      DH_Core(const DL_Group&, const BigInt&);
      ~DH_Core() { } 
   private:
     std::tr1::shared_ptr<DH_Operation> op;
     Blinder blinder;
   };

class ECDSA_Core
{
    public:
        
        bool const verify(const byte signature[], u32bit sig_len, const byte message[], u32bit mess_len) const;
           
        SecureVector<byte> const sign(const byte message[], u32bit mess_len) const;

        ECDSA_Core& operator=(const ECDSA_Core&);

        ECDSA_Core() : op() { }
        ECDSA_Core(const ECDSA_Core&);
		ECDSA_Core(EC_Domain_Params const& dom_pars, BigInt const& priv_key, Botan::math::ec::PointGFp const& pub_key);
        ~ECDSA_Core() { } 
    private:
        std::tr1::shared_ptr<ECDSA_Operation> op;
        
        
};

class ECKAEG_Core
{
    public:
        SecureVector<byte> agree(const Botan::math::ec::PointGFp&) const;

        ECKAEG_Core& operator=(const ECKAEG_Core&);

        ECKAEG_Core() : op() { }
        ECKAEG_Core(const ECKAEG_Core&);
        ECKAEG_Core(EC_Domain_Params const& dom_pars, BigInt const& priv_key, Botan::math::ec::PointGFp const& pub_key);
        ~ECKAEG_Core() { } 
    private:
        std::tr1::shared_ptr<ECKAEG_Operation> op;
        Blinder blinder;
};

}

#endif
