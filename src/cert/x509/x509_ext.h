/*
* X.509 Certificate Extensions
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_X509_EXTENSIONS_H__
#define BOTAN_X509_EXTENSIONS_H__

#include <botan/asn1_int.h>
#include <botan/asn1_oid.h>
#include <botan/asn1_obj.h>
#include <botan/datastor.h>
#include <botan/pubkey_enums.h>

namespace Botan {

/*
* X.509 Certificate Extension
*/
class BOTAN_DLL Certificate_Extension
   {
   public:
      OID oid_of() const;

      virtual Certificate_Extension* copy() const = 0;

      virtual void contents_to(Data_Store&, Data_Store&) const = 0;
      virtual std::string config_id() const = 0;
      virtual std::string oid_name() const = 0;

      virtual ~Certificate_Extension() {}
   protected:
      friend class Extensions;
      virtual bool should_encode() const { return true; }
      virtual MemoryVector<byte> encode_inner() const = 0;
      virtual void decode_inner(const MemoryRegion<byte>&) = 0;
   };

/*
* X.509 Certificate Extension List
*/
class BOTAN_DLL Extensions : public ASN1_Object
   {
   public:
      void encode_into(class DER_Encoder&) const;
      void decode_from(class BER_Decoder&);

      void contents_to(Data_Store&, Data_Store&) const;

      void add(Certificate_Extension* extn)
         { extensions.push_back(extn); }

      Extensions& operator=(const Extensions&);

      Extensions(const Extensions&);
      Extensions(bool st = true) : should_throw(st) {}
      ~Extensions();
   private:
      static Certificate_Extension* get_extension(const OID&);

      std::vector<Certificate_Extension*> extensions;
      bool should_throw;
   };

namespace Cert_Extension {

/*
* Basic Constraints Extension
*/
class BOTAN_DLL Basic_Constraints : public Certificate_Extension
   {
   public:
      Basic_Constraints* copy() const
         { return new Basic_Constraints(is_ca, path_limit); }

      Basic_Constraints(bool ca = false, u32bit limit = 0) :
         is_ca(ca), path_limit(limit) {}

      bool get_is_ca() const { return is_ca; }
      u32bit get_path_limit() const;
   private:
      std::string config_id() const { return "basic_constraints"; }
      std::string oid_name() const { return "X509v3.BasicConstraints"; }

      MemoryVector<byte> encode_inner() const;
      void decode_inner(const MemoryRegion<byte>&);
      void contents_to(Data_Store&, Data_Store&) const;

      bool is_ca;
      u32bit path_limit;
   };

/*
* Key Usage Constraints Extension
*/
class BOTAN_DLL Key_Usage : public Certificate_Extension
   {
   public:
      Key_Usage* copy() const { return new Key_Usage(constraints); }

      Key_Usage(Key_Constraints c = NO_CONSTRAINTS) : constraints(c) {}

      Key_Constraints get_constraints() const { return constraints; }
   private:
      std::string config_id() const { return "key_usage"; }
      std::string oid_name() const { return "X509v3.KeyUsage"; }

      bool should_encode() const { return (constraints != NO_CONSTRAINTS); }
      MemoryVector<byte> encode_inner() const;
      void decode_inner(const MemoryRegion<byte>&);
      void contents_to(Data_Store&, Data_Store&) const;

      Key_Constraints constraints;
   };

/*
* Subject Key Identifier Extension
*/
class BOTAN_DLL Subject_Key_ID : public Certificate_Extension
   {
   public:
      Subject_Key_ID* copy() const { return new Subject_Key_ID(key_id); }

      Subject_Key_ID() {}
      Subject_Key_ID(const MemoryRegion<byte>&);

      MemoryVector<byte> get_key_id() const { return key_id; }
   private:
      std::string config_id() const { return "subject_key_id"; }
      std::string oid_name() const { return "X509v3.SubjectKeyIdentifier"; }

      bool should_encode() const { return (key_id.size() > 0); }
      MemoryVector<byte> encode_inner() const;
      void decode_inner(const MemoryRegion<byte>&);
      void contents_to(Data_Store&, Data_Store&) const;

      MemoryVector<byte> key_id;
   };

/*
* Authority Key Identifier Extension
*/
class BOTAN_DLL Authority_Key_ID : public Certificate_Extension
   {
   public:
      Authority_Key_ID* copy() const { return new Authority_Key_ID(key_id); }

      Authority_Key_ID() {}
      Authority_Key_ID(const MemoryRegion<byte>& k) : key_id(k) {}

      MemoryVector<byte> get_key_id() const { return key_id; }
   private:
      std::string config_id() const { return "authority_key_id"; }
      std::string oid_name() const { return "X509v3.AuthorityKeyIdentifier"; }

      bool should_encode() const { return (key_id.size() > 0); }
      MemoryVector<byte> encode_inner() const;
      void decode_inner(const MemoryRegion<byte>&);
      void contents_to(Data_Store&, Data_Store&) const;

      MemoryVector<byte> key_id;
   };

/*
* Alternative Name Extension Base Class
*/
class BOTAN_DLL Alternative_Name : public Certificate_Extension
   {
   public:
      AlternativeName get_alt_name() const { return alt_name; }

   protected:
      Alternative_Name(const AlternativeName&,
                       const std::string&, const std::string&);

      Alternative_Name(const std::string&, const std::string&);
   private:
      std::string config_id() const { return config_name_str; }
      std::string oid_name() const { return oid_name_str; }

      bool should_encode() const { return alt_name.has_items(); }
      MemoryVector<byte> encode_inner() const;
      void decode_inner(const MemoryRegion<byte>&);
      void contents_to(Data_Store&, Data_Store&) const;

      std::string config_name_str, oid_name_str;
      AlternativeName alt_name;
   };

/*
* Subject Alternative Name Extension
*/
class BOTAN_DLL Subject_Alternative_Name : public Alternative_Name
   {
   public:
      Subject_Alternative_Name* copy() const
         { return new Subject_Alternative_Name(get_alt_name()); }

      Subject_Alternative_Name(const AlternativeName& = AlternativeName());
   };

/*
* Issuer Alternative Name Extension
*/
class BOTAN_DLL Issuer_Alternative_Name : public Alternative_Name
   {
   public:
      Issuer_Alternative_Name* copy() const
         { return new Issuer_Alternative_Name(get_alt_name()); }

      Issuer_Alternative_Name(const AlternativeName& = AlternativeName());
   };

/*
* Extended Key Usage Extension
*/
class BOTAN_DLL Extended_Key_Usage : public Certificate_Extension
   {
   public:
      Extended_Key_Usage* copy() const { return new Extended_Key_Usage(oids); }

      Extended_Key_Usage() {}
      Extended_Key_Usage(const std::vector<OID>& o) : oids(o) {}

      std::vector<OID> get_oids() const { return oids; }
   private:
      std::string config_id() const { return "extended_key_usage"; }
      std::string oid_name() const { return "X509v3.ExtendedKeyUsage"; }

      bool should_encode() const { return (oids.size() > 0); }
      MemoryVector<byte> encode_inner() const;
      void decode_inner(const MemoryRegion<byte>&);
      void contents_to(Data_Store&, Data_Store&) const;

      std::vector<OID> oids;
   };

/*
* Certificate Policies Extension
*/
class BOTAN_DLL Certificate_Policies : public Certificate_Extension
   {
   public:
      Certificate_Policies* copy() const
         { return new Certificate_Policies(oids); }

      Certificate_Policies() {}
      Certificate_Policies(const std::vector<OID>& o) : oids(o) {}

      std::vector<OID> get_oids() const { return oids; }
   private:
      std::string config_id() const { return "policy_info"; }
      std::string oid_name() const { return "X509v3.CertificatePolicies"; }

      bool should_encode() const { return (oids.size() > 0); }
      MemoryVector<byte> encode_inner() const;
      void decode_inner(const MemoryRegion<byte>&);
      void contents_to(Data_Store&, Data_Store&) const;

      std::vector<OID> oids;
   };

/*
* CRL Number Extension
*/
class BOTAN_DLL CRL_Number : public Certificate_Extension
   {
   public:
      CRL_Number* copy() const;

      CRL_Number() : has_value(false), crl_number(0) {}
      CRL_Number(u32bit n) : has_value(true), crl_number(n) {}

      u32bit get_crl_number() const;
   private:
      std::string config_id() const { return "crl_number"; }
      std::string oid_name() const { return "X509v3.CRLNumber"; }

      bool should_encode() const { return has_value; }
      MemoryVector<byte> encode_inner() const;
      void decode_inner(const MemoryRegion<byte>&);
      void contents_to(Data_Store&, Data_Store&) const;

      bool has_value;
      u32bit crl_number;
   };

/*
* CRL Entry Reason Code Extension
*/
class BOTAN_DLL CRL_ReasonCode : public Certificate_Extension
   {
   public:
      CRL_ReasonCode* copy() const { return new CRL_ReasonCode(reason); }

      CRL_ReasonCode(CRL_Code r = UNSPECIFIED) : reason(r) {}

      CRL_Code get_reason() const { return reason; }
   private:
      std::string config_id() const { return "crl_reason"; }
      std::string oid_name() const { return "X509v3.ReasonCode"; }

      bool should_encode() const { return (reason != UNSPECIFIED); }
      MemoryVector<byte> encode_inner() const;
      void decode_inner(const MemoryRegion<byte>&);
      void contents_to(Data_Store&, Data_Store&) const;

      CRL_Code reason;
   };

}

}

#endif
