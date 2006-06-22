/*************************************************
* X.509 Certificate Extensions Header File       *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_X509_EXTENSIONS__
#define BOTAN_X509_EXTENSIONS__

#include <botan/asn1_int.h>
#include <botan/asn1_oid.h>
#include <botan/asn1_obj.h>
#include <botan/datastor.h>
#include <botan/enums.h>

namespace Botan {

/*************************************************
* X.509 Certificate Extension                    *
*************************************************/
class Certificate_Extension
   {
   public:
      void maybe_add(class DER_Encoder&) const;

      OID oid_of() const;
      void make_critical() { critical = true; }
      bool is_critical() const { return critical; }

      virtual Certificate_Extension* copy() const = 0;

      virtual void contents_to(Data_Store&, Data_Store&) const = 0;
      virtual std::string config_id() const = 0;
      virtual std::string oid_name() const = 0;

      Certificate_Extension() { critical = false; }
      virtual ~Certificate_Extension() {}
   protected:
      friend class Extensions;
      virtual bool should_encode() const { return true; }
      virtual MemoryVector<byte> encode_inner() const = 0;
      virtual void decode_inner(const MemoryRegion<byte>&) = 0;
   private:
      bool critical;
   };

/*************************************************
* X.509 Certificate Extension List               *
*************************************************/
class Extensions : public ASN1_Object
   {
   public:
      void encode_into(class DER_Encoder&) const;
      void decode_from(class BER_Decoder&);

      std::vector<Certificate_Extension*> get() const
         { return extensions; }
      void add(Certificate_Extension* extn)
         { extensions.push_back(extn); }

      ~Extensions();
   private:
      std::vector<Certificate_Extension*> extensions;
   };

namespace Cert_Extension {

/*************************************************
* Basic Constraints Extension                    *
*************************************************/
class Basic_Constraints : public Certificate_Extension
   {
   public:
      Basic_Constraints(bool ca = false, u32bit limit = 0) :
         is_ca(ca), path_limit(limit) {}

      bool get_is_ca() const { return is_ca; }
      bool get_path_limit() const;

      Basic_Constraints* copy() const
         { return new Basic_Constraints(is_ca, path_limit); }
   private:
      std::string config_id() const { return "basic_constraints"; }
      std::string oid_name() const { return "X509v3.BasicConstraints"; }

      MemoryVector<byte> encode_inner() const;
      void decode_inner(const MemoryRegion<byte>&);
      void contents_to(Data_Store&, Data_Store&) const;

      bool is_ca;
      u32bit path_limit;
   };

/*************************************************
* Key Usage Constraints Extension                *
*************************************************/
class Key_Usage : public Certificate_Extension
   {
   public:
      Key_Usage(Key_Constraints c = NO_CONSTRAINTS) : constraints(c) {}

      Key_Constraints get_constraints() const { return constraints; }

      Key_Usage* copy() const { return new Key_Usage(constraints); }
   private:
      std::string config_id() const { return "key_usage"; }
      std::string oid_name() const { return "X509v3.KeyUsage"; }

      bool should_encode() const { return (constraints != NO_CONSTRAINTS); }
      MemoryVector<byte> encode_inner() const;
      void decode_inner(const MemoryRegion<byte>&);
      void contents_to(Data_Store&, Data_Store&) const;

      Key_Constraints constraints;
   };

/*************************************************
* Subject Key Identifier Extension               *
*************************************************/
class Subject_Key_ID : public Certificate_Extension
   {
   public:
      Subject_Key_ID() {}
      Subject_Key_ID(const MemoryRegion<byte>&);

      MemoryVector<byte> get_key_id() const { return key_id; }

      Subject_Key_ID* copy() const { return new Subject_Key_ID(key_id); }
   private:
      std::string config_id() const { return "subject_key_id"; }
      std::string oid_name() const { return "X509v3.SubjectKeyIdentifier"; }

      bool should_encode() const { return (key_id.size() > 0); }
      MemoryVector<byte> encode_inner() const;
      void decode_inner(const MemoryRegion<byte>&);
      void contents_to(Data_Store&, Data_Store&) const;

      MemoryVector<byte> key_id;
   };

/*************************************************
* Authority Key Identifier Extension             *
*************************************************/
class Authority_Key_ID : public Certificate_Extension
   {
   public:
      Authority_Key_ID() {}
      Authority_Key_ID(const MemoryRegion<byte>& k) : key_id(k) {}

      MemoryVector<byte> get_key_id() const { return key_id; }

      Authority_Key_ID* copy() const { return new Authority_Key_ID(key_id); }
   private:
      std::string config_id() const { return "authority_key_id"; }
      std::string oid_name() const { return "X509v3.AuthorityKeyIdentifier"; }

      bool should_encode() const { return (key_id.size() > 0); }
      MemoryVector<byte> encode_inner() const;
      void decode_inner(const MemoryRegion<byte>&);
      void contents_to(Data_Store&, Data_Store&) const;

      MemoryVector<byte> key_id;
   };

/*************************************************
* Alternative Name Extension                     *
*************************************************/
class Alternative_Name : public Certificate_Extension
   {
   public:
      Alternative_Name(const AlternativeName&,
                       const std::string&, const std::string&);

      AlternativeName get_alt_name() const { return alt_name; }

      Alternative_Name* copy() const;
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

/*************************************************
* Extended Key Usage Extension                   *
*************************************************/
class Extended_Key_Usage : public Certificate_Extension
   {
   public:
      Extended_Key_Usage() {}
      Extended_Key_Usage(const std::vector<OID>& o) : oids(o) {}

      std::vector<OID> get_oids() const { return oids; }

      Extended_Key_Usage* copy() const { return new Extended_Key_Usage(oids); }
   private:
      std::string config_id() const { return "extended_key_usage"; }
      std::string oid_name() const { return "X509v3.ExtendedKeyUsage"; }

      bool should_encode() const { return (oids.size() > 0); }
      MemoryVector<byte> encode_inner() const;
      void decode_inner(const MemoryRegion<byte>&);
      void contents_to(Data_Store&, Data_Store&) const;

      std::vector<OID> oids;
   };

/*************************************************
* Certificate Policies Extension                 *
*************************************************/
class Certificate_Policies : public Certificate_Extension
   {
   public:
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

/*************************************************
* CRL Number Extension                           *
*************************************************/
class CRL_Number : public Certificate_Extension
   {
   public:
      CRL_Number() : has_value(false), crl_number(0) {}
      CRL_Number(u32bit n) : has_value(true), crl_number(n) {}

      u32bit get_crl_number() const;

      CRL_Number* copy() const;
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

/*************************************************
* CRL Entry Reason Code Extension                *
*************************************************/
class CRL_ReasonCode : public Certificate_Extension
   {
   public:
      CRL_ReasonCode(CRL_Code r = UNSPECIFIED) : reason(r) {}

      CRL_Code get_reason() const { return reason; }

      CRL_ReasonCode* copy() const { return new CRL_ReasonCode(reason); }
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
