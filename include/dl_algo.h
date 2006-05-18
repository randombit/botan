/*************************************************
* DL Scheme Header File                          *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_DL_ALGO_H__
#define BOTAN_DL_ALGO_H__

#include <botan/dl_group.h>
#include <botan/x509_key.h>
#include <botan/pkcs8.h>

namespace Botan {

/*************************************************
* DL Public Key                                  *
*************************************************/
class DL_Scheme_PublicKey : public virtual X509_PublicKey
   {
   public:
      bool check_key(bool) const;

      const DL_Group& get_domain() const { return group; }
      const BigInt& get_y() const { return y; }

      virtual ~DL_Scheme_PublicKey() {}
   protected:
      const BigInt& group_p() const { return group.get_p(); }
      const BigInt& group_q() const { return group.get_q(); }
      const BigInt& group_g() const { return group.get_g(); }

      BigInt y;
      DL_Group group;
   private:
      MemoryVector<byte> DER_encode_pub() const;
      MemoryVector<byte> DER_encode_params() const;
      void BER_decode_pub(DataSource&);
      void BER_decode_params(DataSource&);

      virtual DL_Group::Format group_format() const = 0;
      virtual void X509_load_hook() {}
   };

/*************************************************
* DL Private Key                                 *
*************************************************/
class DL_Scheme_PrivateKey : public virtual DL_Scheme_PublicKey,
                             public virtual PKCS8_PrivateKey
   {
   public:
      bool check_key(bool) const;

      const BigInt& get_x() const { return x; }

      virtual ~DL_Scheme_PrivateKey() {}
   protected:
      BigInt x;
   private:
      SecureVector<byte> DER_encode_priv() const;
      void BER_decode_priv(DataSource&);

      virtual void PKCS8_load_hook() {}
   };

}

#endif
