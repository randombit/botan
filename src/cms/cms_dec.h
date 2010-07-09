/*
* CMS Decoding
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_CMS_DECODER_H__
#define BOTAN_CMS_DECODER_H__

#include <botan/x509cert.h>
#include <botan/x509stor.h>
#include <botan/pkcs8.h>
#include <botan/ber_dec.h>

namespace Botan {

/**
* CMS Decoding Operation
*/
class BOTAN_DLL CMS_Decoder
   {
   public:
      enum Status { GOOD, BAD, NO_KEY, FAILURE };

      enum Content_Type { DATA, UNKNOWN, COMPRESSED, ENVELOPED, SIGNED,
                          AUTHENTICATED, DIGESTED };

      Status layer_status() const;
      Content_Type layer_type() const;
      std::string layer_info() const;
      std::string layer_algo() const;
      std::string get_data() const;
      std::vector<X509_Certificate> get_certs() const;
      std::vector<X509_CRL> get_crls() const;

      void next_layer() { decode_layer(); }

      void add_key(Private_Key*);

      CMS_Decoder(DataSource&, const X509_Store&,
                  Private_Key* = 0);
   private:
      std::string get_passphrase(const std::string&);
      void read_econtent(BER_Decoder&);
      void initial_read(DataSource&);
      void decode_layer();
      void decompress(BER_Decoder&);

      X509_Store store;
      std::vector<std::string> passphrases;
      std::vector<Private_Key*> keys;

      OID type, next_type;
      SecureVector<byte> data;
      Status status;
      std::string info;
   };

}

#endif
