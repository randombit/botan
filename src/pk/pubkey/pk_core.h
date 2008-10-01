/*************************************************
* PK Algorithm Core Header File                  *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_PK_CORE_H__
#define BOTAN_PK_CORE_H__

#include <botan/bigint.h>
#include <botan/blinding.h>
#include <botan/pk_ops.h>
#include <botan/dl_group.h>

#if defined(BOTAN_HAS_ECDSA)
  #include <botan/ec_dompar.h>
#endif

namespace Botan {

/*************************************************
* IF Core                                        *
*************************************************/
class BOTAN_DLL IF_Core
   {
   public:
      BigInt public_op(const BigInt&) const;
      BigInt private_op(const BigInt&) const;

      IF_Core& operator=(const IF_Core&);

      IF_Core() { op = 0; }
      IF_Core(const IF_Core&);

      IF_Core(const BigInt&, const BigInt&);

      IF_Core(RandomNumberGenerator& rng,
              const BigInt&, const BigInt&,
              const BigInt&, const BigInt&, const BigInt&,
              const BigInt&, const BigInt&, const BigInt&);

      ~IF_Core() { delete op; }
   private:
      IF_Operation* op;
      Blinder blinder;
   };

/*************************************************
* DSA Core                                       *
*************************************************/
class BOTAN_DLL DSA_Core
   {
   public:
      SecureVector<byte> sign(const byte[], u32bit, const BigInt&) const;
      bool verify(const byte[], u32bit, const byte[], u32bit) const;

      DSA_Core& operator=(const DSA_Core&);

      DSA_Core() { op = 0; }
      DSA_Core(const DSA_Core&);
      DSA_Core(const DL_Group&, const BigInt&, const BigInt& = 0);
      ~DSA_Core() { delete op; }
   private:
      DSA_Operation* op;
   };

/*************************************************
* NR Core                                        *
*************************************************/
class BOTAN_DLL NR_Core
   {
   public:
      SecureVector<byte> sign(const byte[], u32bit, const BigInt&) const;
      SecureVector<byte> verify(const byte[], u32bit) const;

      NR_Core& operator=(const NR_Core&);

      NR_Core() { op = 0; }
      NR_Core(const NR_Core&);
      NR_Core(const DL_Group&, const BigInt&, const BigInt& = 0);
      ~NR_Core() { delete op; }
   private:
      NR_Operation* op;
   };

/*************************************************
* ElGamal Core                                   *
*************************************************/
class BOTAN_DLL ELG_Core
   {
   public:
      SecureVector<byte> encrypt(const byte[], u32bit, const BigInt&) const;
      SecureVector<byte> decrypt(const byte[], u32bit) const;

      ELG_Core& operator=(const ELG_Core&);

      ELG_Core() { op = 0; }
      ELG_Core(const ELG_Core&);

      ELG_Core(const DL_Group&, const BigInt&);
      ELG_Core(RandomNumberGenerator&, const DL_Group&,
               const BigInt&, const BigInt&);

      ~ELG_Core() { delete op; }
   private:
      ELG_Operation* op;
      Blinder blinder;
      u32bit p_bytes;
   };

/*************************************************
* DH Core                                        *
*************************************************/
class BOTAN_DLL DH_Core
   {
   public:
      BigInt agree(const BigInt&) const;

      DH_Core& operator=(const DH_Core&);

      DH_Core() { op = 0; }
      DH_Core(const DH_Core&);
      DH_Core(RandomNumberGenerator& rng,
              const DL_Group&, const BigInt&);
      ~DH_Core() { delete op; }
   private:
      DH_Operation* op;
      Blinder blinder;
   };

#if defined(BOTAN_HAS_ECDSA)
/*************************************************
* ECDSA Core                                     *
*************************************************/
class ECDSA_Core
   {
   public:
      bool verify(const byte signature[], u32bit sig_len,
                  const byte message[], u32bit mess_len) const;

      SecureVector<byte> sign(const byte message[], u32bit mess_len) const;

      ECDSA_Core& operator=(const ECDSA_Core&);

      ECDSA_Core() { op = 0; }

      ECDSA_Core(const ECDSA_Core&);

      ECDSA_Core(const EC_Domain_Params& dom_pars,
                 const BigInt& priv_key,
                 const PointGFp& pub_key);

      ~ECDSA_Core() { delete op; }
   private:
      ECDSA_Operation* op;
   };

/*************************************************
* ECKAEG Core                                    *
*************************************************/
class ECKAEG_Core
   {
   public:
      SecureVector<byte> agree(const PointGFp&) const;

      ECKAEG_Core& operator=(const ECKAEG_Core&);

      ECKAEG_Core() { op = 0; }

      ECKAEG_Core(const ECKAEG_Core&);

      ECKAEG_Core(const EC_Domain_Params& dom_pars,
                  const BigInt& priv_key,
                  PointGFp const& pub_key);

      ~ECKAEG_Core() { delete op; }
   private:
      ECKAEG_Operation* op;
      Blinder blinder;
   };
#endif

}

#endif
