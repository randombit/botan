/*************************************************
* PK Key Types Header File                       *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_PK_KEYS_H__
#define BOTAN_PK_KEYS_H__

#include <botan/base.h>
#include <botan/asn1_oid.h>

namespace Botan {

/*************************************************
* Public Key Base Class                          *
*************************************************/
class Public_Key
   {
   public:
      virtual std::string algo_name() const = 0;
      virtual OID get_oid() const;

      virtual bool check_key(bool) const { return true; }
      virtual u32bit message_parts() const { return 1; }
      virtual u32bit message_part_size() const { return 0; }
      virtual u32bit max_input_bits() const = 0;

      virtual class X509_Encoder* x509_encoder() const { return 0; }
      virtual class X509_Decoder* x509_decoder() { return 0; }

      virtual ~Public_Key() {}
   protected:
      virtual void load_check() const;
   };

/*************************************************
* Private Key Base Class                         *
*************************************************/
class Private_Key : public virtual Public_Key
   {
   public:
      virtual class PKCS8_Encoder* pkcs8_encoder() const { return 0; }
      virtual class PKCS8_Decoder* pkcs8_decoder() { return 0; }
   protected:
      void load_check() const;
      void gen_check() const;
   };

/*************************************************
* PK Encrypting Key                              *
*************************************************/
class PK_Encrypting_Key : public virtual Public_Key
   {
   public:
      virtual SecureVector<byte> encrypt(const byte[], u32bit) const = 0;
      virtual ~PK_Encrypting_Key() {}
   };

/*************************************************
* PK Decrypting Key                              *
*************************************************/
class PK_Decrypting_Key : public virtual Private_Key
   {
   public:
      virtual SecureVector<byte> decrypt(const byte[], u32bit) const = 0;
      virtual ~PK_Decrypting_Key() {}
   };

/*************************************************
* PK Signing Key                                 *
*************************************************/
class PK_Signing_Key : public virtual Private_Key
   {
   public:
      virtual SecureVector<byte> sign(const byte[], u32bit) const = 0;
      virtual ~PK_Signing_Key() {}
   };

/*************************************************
* PK Verifying Key, Message Recovery Version     *
*************************************************/
class PK_Verifying_with_MR_Key : public virtual Public_Key
   {
   public:
      virtual SecureVector<byte> verify(const byte[], u32bit) const = 0;
      virtual ~PK_Verifying_with_MR_Key() {}
   };

/*************************************************
* PK Verifying Key, No Message Recovery Version  *
*************************************************/
class PK_Verifying_wo_MR_Key : public virtual Public_Key
   {
   public:
      virtual bool verify(const byte[], u32bit,
                          const byte[], u32bit) const = 0;
      virtual ~PK_Verifying_wo_MR_Key() {}
   };

/*************************************************
* PK Secret Value Derivation Key                 *
*************************************************/
class PK_Key_Agreement_Key : public virtual Private_Key
   {
   public:
      virtual SecureVector<byte> derive_key(const byte[], u32bit) const = 0;
      virtual MemoryVector<byte> public_value() const = 0;
      virtual ~PK_Key_Agreement_Key() {}
   };

/*************************************************
* Typedefs                                       *
*************************************************/
typedef PK_Key_Agreement_Key PK_KA_Key;
typedef Public_Key X509_PublicKey;
typedef Private_Key PKCS8_PrivateKey;

}

#endif
