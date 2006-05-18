/*************************************************
* X.509 Certificate Extensions Header File       *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_X509_EXTENSIONS__
#define BOTAN_X509_EXTENSIONS__

#include <botan/asn1_int.h>
#include <botan/asn1_oid.h>
#include <botan/asn1_obj.h>

namespace Botan {

/*************************************************
* X.509 Certificate Extension                    *
*************************************************/
class Certificate_Extension : public ASN1_Object
   {
   public:
      void encode_into(class DER_Encoder&) const;
      void decode_from(class BER_Decoder&);
      void maybe_add(class DER_Encoder&) const;

      OID oid_of() const;
      void make_critical() { critical = true; }
      bool is_critical() const { return critical; }

      //virtual std::multimap<std::string, std::string> contents() const = 0;
      virtual std::string config_id() const = 0;
      virtual std::string oid_name() const = 0;

      Certificate_Extension() { critical = false; }
      virtual ~Certificate_Extension() {}
   protected:
      virtual bool should_encode() const { return true; }
      virtual MemoryVector<byte> encode_inner() const = 0;
      virtual void decode_inner(const MemoryRegion<byte>&) = 0;
   private:
      void encode_into(class DER_Encoder&, bool) const;
      bool critical;
   };

/*************************************************
* X.509 Certificate Extensions                   *
*************************************************/
class Extensions : public ASN1_Object
   {
   public:
      void encode_into(class DER_Encoder&) const;

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
      Basic_Constraints(bool = false, u32bit = 0);
   private:
      std::string config_id() const { return "basic_constraints"; }
      std::string oid_name() const { return "X509v3.BasicConstraints"; }

      MemoryVector<byte> encode_inner() const;
      void decode_inner(const MemoryRegion<byte>&);

      bool is_ca;
      u32bit path_limit;
   };

/*************************************************
* Key Usage Constraints Extension                *
*************************************************/
class Key_Usage : public Certificate_Extension
   {
   public:
      Key_Usage(Key_Constraints);
   private:
      std::string config_id() const { return "key_usage"; }
      std::string oid_name() const { return "X509v3.KeyUsage"; }

      bool should_encode() const { return (constraints != NO_CONSTRAINTS); }
      MemoryVector<byte> encode_inner() const;
      void decode_inner(const MemoryRegion<byte>&);

      Key_Constraints constraints;
   };

/*************************************************
* Subject Key Identifier Extension               *
*************************************************/
class Subject_Key_ID : public Certificate_Extension
   {
   public:
      Subject_Key_ID(const MemoryRegion<byte>&);
   private:
      std::string config_id() const { return "subject_key_id"; }
      std::string oid_name() const { return "X509v3.SubjectKeyIdentifier"; }

      MemoryVector<byte> encode_inner() const;
      void decode_inner(const MemoryRegion<byte>&);

      MemoryVector<byte> key_id;
   };

/*************************************************
* Authority Key Identifier Extension             *
*************************************************/
class Authority_Key_ID : public Certificate_Extension
   {
   public:
      Authority_Key_ID(const MemoryRegion<byte>&);
   private:
      std::string config_id() const { return "authority_key_id"; }
      std::string oid_name() const { return "X509v3.AuthorityKeyIdentifier"; }

      bool should_encode() const { return (key_id.size() > 0); }
      MemoryVector<byte> encode_inner() const;
      void decode_inner(const MemoryRegion<byte>&);

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
   private:
      std::string config_id() const { return config_name_str; }
      std::string oid_name() const { return oid_name_str; }

      bool should_encode() const { return alt_name.has_items(); }
      MemoryVector<byte> encode_inner() const;
      void decode_inner(const MemoryRegion<byte>&);

      std::string config_name_str, oid_name_str;
      AlternativeName alt_name;
   };

/*************************************************
* Extended Key Usage Extension                   *
*************************************************/
class Extended_Key_Usage : public Certificate_Extension
   {
   public:
      Extended_Key_Usage(const std::vector<OID>&);
   private:
      std::string config_id() const { return "extended_key_usage"; }
      std::string oid_name() const { return "X509v3.ExtendedKeyUsage"; }

      bool should_encode() const { return (oids.size() > 0); }
      MemoryVector<byte> encode_inner() const;
      void decode_inner(const MemoryRegion<byte>&);

      std::vector<OID> oids;
   };

/*************************************************
* CRL Number Extension                           *
*************************************************/
class CRL_Number : public Certificate_Extension
   {
   public:
      CRL_Number(u32bit = 0);
   private:
      std::string config_id() const { return "crl_number"; }
      std::string oid_name() const { return "X509v3.CRLNumber"; }

      bool should_encode() const { return (crl_number != 0); }

      MemoryVector<byte> encode_inner() const;
      void decode_inner(const MemoryRegion<byte>&);

      u32bit crl_number;
   };

}

}

#endif
