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
class DL_Scheme_PublicKey : public virtual Public_Key
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
      virtual DL_Group::Format group_format() const = 0;

      BigInt y;
      DL_Group group;
   private:
      X509_Encoder* x509_encoder() const;
      X509_Decoder* x509_decoder();

      virtual void X509_load_hook() {}
   };

/*************************************************
* DL Private Key                                 *
*************************************************/
class DL_Scheme_PrivateKey : public virtual DL_Scheme_PublicKey,
                             public virtual Private_Key
   {
   public:
      bool check_key(bool) const;

      const BigInt& get_x() const { return x; }

      virtual ~DL_Scheme_PrivateKey() {}
   protected:
      BigInt x;
   private:
      PKCS8_Encoder* pkcs8_encoder() const;
      PKCS8_Decoder* pkcs8_decoder();
      virtual void PKCS8_load_hook(bool = false) {}
   };

}

#endif
