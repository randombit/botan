/*************************************************
* IF Scheme Header File                          *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_IF_ALGO_H__
#define BOTAN_IF_ALGO_H__

#include <botan/x509_key.h>
#include <botan/pkcs8.h>
#include <botan/pk_core.h>

namespace Botan {

/*************************************************
* IF Public Key                                  *
*************************************************/
class IF_Scheme_PublicKey : public virtual X509_PublicKey
   {
   public:
      bool check_key(bool) const;

      const BigInt& get_n() const { return n; }
      const BigInt& get_e() const { return e; }

      u32bit max_input_bits() const { return (n.bits() - 1); }

      virtual ~IF_Scheme_PublicKey() {}
   protected:
      virtual void X509_load_hook();
      BigInt n, e;
      IF_Core core;
   private:
      MemoryVector<byte> DER_encode_pub() const;
      MemoryVector<byte> DER_encode_params() const;
      void BER_decode_params(DataSource&);
      void BER_decode_pub(DataSource&);
   };

/*************************************************
* IF Private Key                                 *
*************************************************/
class IF_Scheme_PrivateKey : public virtual IF_Scheme_PublicKey,
                             public virtual PKCS8_PrivateKey
   {
   public:
      bool check_key(bool) const;

      const BigInt& get_p() const { return p; }
      const BigInt& get_q() const { return q; }
      const BigInt& get_d() const { return d; }

      virtual ~IF_Scheme_PrivateKey() {}
   protected:
      virtual void PKCS8_load_hook();
      BigInt d, p, q, d1, d2, c;
   private:
      SecureVector<byte> DER_encode_priv() const;
      void BER_decode_priv(DataSource&);
   };

}

#endif
