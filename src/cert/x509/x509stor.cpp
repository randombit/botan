/*
* X.509 Certificate Store
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/x509stor.h>
#include <botan/parsing.h>
#include <botan/pubkey.h>
#include <botan/look_pk.h>
#include <botan/oids.h>
#include <botan/util.h>
#include <algorithm>
#include <memory>

namespace Botan {

namespace {

/*
* Do a validity check
*/
s32bit validity_check(const X509_Time& start, const X509_Time& end,
                      u64bit current_time, u32bit slack)
   {
   const s32bit NOT_YET_VALID = -1, VALID_TIME = 0, EXPIRED = 1;

   if(start.cmp(current_time + slack) > 0)
      return NOT_YET_VALID;
   if(end.cmp(current_time - slack) < 0)
      return EXPIRED;
   return VALID_TIME;
   }

/*
* Compare the value of unique ID fields
*/
bool compare_ids(const MemoryVector<byte>& id1,
                 const MemoryVector<byte>& id2)
   {
   if(!id1.size() || !id2.size())
      return true;
   return (id1 == id2);
   }

/*
* Check a particular usage restriction
*/
bool check_usage(const X509_Certificate& cert, X509_Store::Cert_Usage usage,
                 X509_Store::Cert_Usage check_for, Key_Constraints constraints)
   {
   if((usage & check_for) == 0)
      return true;
   if(cert.constraints() == NO_CONSTRAINTS)
      return true;
   if(cert.constraints() & constraints)
      return true;
   return false;
   }

/*
* Check a particular usage restriction
*/
bool check_usage(const X509_Certificate& cert, X509_Store::Cert_Usage usage,
                 X509_Store::Cert_Usage check_for,
                 const std::string& usage_oid)
   {
   if((usage & check_for) == 0)
      return true;

   const std::vector<std::string> constraints = cert.ex_constraints();

   if(constraints.empty())
      return true;

   return std::binary_search(constraints.begin(), constraints.end(),
                             usage_oid);
   }

/*
* Check the usage restrictions
*/
X509_Code usage_check(const X509_Certificate& cert,
                      X509_Store::Cert_Usage usage)
   {
   if(usage == X509_Store::ANY)
      return VERIFIED;

   if(!check_usage(cert, usage, X509_Store::CRL_SIGNING, CRL_SIGN))
      return CA_CERT_NOT_FOR_CRL_ISSUER;

   if(!check_usage(cert, usage, X509_Store::TLS_SERVER, "PKIX.ServerAuth"))
      return INVALID_USAGE;
   if(!check_usage(cert, usage, X509_Store::TLS_CLIENT, "PKIX.ClientAuth"))
      return INVALID_USAGE;
   if(!check_usage(cert, usage, X509_Store::CODE_SIGNING, "PKIX.CodeSigning"))
      return INVALID_USAGE;
   if(!check_usage(cert, usage, X509_Store::EMAIL_PROTECTION,
                   "PKIX.EmailProtection"))
      return INVALID_USAGE;
   if(!check_usage(cert, usage, X509_Store::TIME_STAMPING,
                   "PKIX.TimeStamping"))
      return INVALID_USAGE;

   return VERIFIED;
   }

}

/*
* Define equality for revocation data
*/
bool X509_Store::CRL_Data::operator==(const CRL_Data& other) const
   {
   if(issuer != other.issuer)
      return false;
   if(serial != other.serial)
      return false;
   return compare_ids(auth_key_id, other.auth_key_id);
   }

/*
* Define inequality for revocation data
*/
bool X509_Store::CRL_Data::operator!=(const CRL_Data& other) const
   {
   return !((*this) == other);
   }

/*
* Define an ordering for revocation data
*/
bool X509_Store::CRL_Data::operator<(const X509_Store::CRL_Data& other) const
   {
   if(*this == other)
      return false;

   const MemoryVector<byte>& serial1 = serial;
   const MemoryVector<byte>& key_id1 = auth_key_id;
   const MemoryVector<byte>& serial2 = other.serial;
   const MemoryVector<byte>& key_id2 = other.auth_key_id;

   if(compare_ids(key_id1, key_id2) == false)
      {
      if(std::lexicographical_compare(key_id1.begin(), key_id1.end(),
                                      key_id2.begin(), key_id2.end()))
         return true;

      if(std::lexicographical_compare(key_id2.begin(), key_id2.end(),
                                      key_id1.begin(), key_id1.end()))
         return false;
      }

   if(compare_ids(serial1, serial2) == false)
      {
      if(std::lexicographical_compare(serial1.begin(), serial1.end(),
                                      serial2.begin(), serial2.end()))
         return true;

      if(std::lexicographical_compare(serial2.begin(), serial2.end(),
                                      serial1.begin(), serial1.end()))
         return false;
      }

   return (issuer < other.issuer);
   }

/*
* X509_Store Constructor
*/
X509_Store::X509_Store(u32bit slack, u32bit cache_timeout)
   {
   revoked_info_valid = true;

   validation_cache_timeout = cache_timeout;
   time_slack = slack;
   }

/*
* X509_Store Copy Constructor
*/
X509_Store::X509_Store(const X509_Store& other)
   {
   certs = other.certs;
   revoked = other.revoked;
   revoked_info_valid = other.revoked_info_valid;
   for(u32bit j = 0; j != other.stores.size(); ++j)
      stores[j] = other.stores[j]->clone();
   time_slack = other.time_slack;
   }

/*
* X509_Store Destructor
*/
X509_Store::~X509_Store()
   {
   for(u32bit j = 0; j != stores.size(); ++j)
      delete stores[j];
   }

/*
* Verify a certificate's authenticity
*/
X509_Code X509_Store::validate_cert(const X509_Certificate& cert,
                                    Cert_Usage cert_usage)
   {
   recompute_revoked_info();

   std::vector<u32bit> indexes;
   X509_Code chaining_result = construct_cert_chain(cert, indexes);
   if(chaining_result != VERIFIED)
      return chaining_result;

   const u64bit current_time = system_time();

   s32bit time_check = validity_check(cert.start_time(), cert.end_time(),
                                      current_time, time_slack);
   if(time_check < 0)      return CERT_NOT_YET_VALID;
   else if(time_check > 0) return CERT_HAS_EXPIRED;

   X509_Code sig_check_result = check_sig(cert, certs[indexes[0]]);
   if(sig_check_result != VERIFIED)
      return sig_check_result;

   if(is_revoked(cert))
      return CERT_IS_REVOKED;

   for(u32bit j = 0; j != indexes.size() - 1; ++j)
      {
      const X509_Certificate& current_cert = certs[indexes[j]].cert;

      time_check = validity_check(current_cert.start_time(),
                                  current_cert.end_time(),
                                  current_time,
                                  time_slack);

      if(time_check < 0)      return CERT_NOT_YET_VALID;
      else if(time_check > 0) return CERT_HAS_EXPIRED;

      sig_check_result = check_sig(certs[indexes[j]], certs[indexes[j+1]]);
      if(sig_check_result != VERIFIED)
         return sig_check_result;
      }

   return usage_check(cert, cert_usage);
   }

/*
* Find this certificate
*/
u32bit X509_Store::find_cert(const X509_DN& subject_dn,
                             const MemoryRegion<byte>& subject_key_id) const
   {
   for(u32bit j = 0; j != certs.size(); ++j)
      {
      const X509_Certificate& this_cert = certs[j].cert;
      if(compare_ids(this_cert.subject_key_id(), subject_key_id) &&
         this_cert.subject_dn() == subject_dn)
         return j;
      }
   return NO_CERT_FOUND;
   }

/*
* Find the parent of this certificate
*/
u32bit X509_Store::find_parent_of(const X509_Certificate& cert)
   {
   const X509_DN issuer_dn = cert.issuer_dn();
   const MemoryVector<byte> auth_key_id = cert.authority_key_id();

   u32bit index = find_cert(issuer_dn, auth_key_id);

   if(index != NO_CERT_FOUND)
      return index;

   if(auth_key_id.size())
      {
      for(u32bit j = 0; j != stores.size(); ++j)
         {
         std::vector<X509_Certificate> got = stores[j]->by_SKID(auth_key_id);

         if(got.empty())
            continue;

         for(u32bit k = 0; k != got.size(); ++k)
            add_cert(got[k]);
         return find_cert(issuer_dn, auth_key_id);
         }
      }

   return NO_CERT_FOUND;
   }

/*
* Construct a chain of certificate relationships
*/
X509_Code X509_Store::construct_cert_chain(const X509_Certificate& end_cert,
                                           std::vector<u32bit>& indexes,
                                           bool need_full_chain)
   {
   u32bit parent = find_parent_of(end_cert);

   while(true)
      {
      if(parent == NO_CERT_FOUND)
         return CERT_ISSUER_NOT_FOUND;
      indexes.push_back(parent);

      if(certs[parent].is_verified(validation_cache_timeout))
         if(certs[parent].verify_result() != VERIFIED)
            return certs[parent].verify_result();

      const X509_Certificate& parent_cert = certs[parent].cert;
      if(!parent_cert.is_CA_cert())
         return CA_CERT_NOT_FOR_CERT_ISSUER;

      if(certs[parent].is_trusted())
         break;
      if(parent_cert.is_self_signed())
         return CANNOT_ESTABLISH_TRUST;

      if(parent_cert.path_limit() < indexes.size() - 1)
         return CERT_CHAIN_TOO_LONG;

      parent = find_parent_of(parent_cert);
      }

   if(need_full_chain)
      return VERIFIED;

   while(true)
      {
      if(indexes.size() < 2)
         break;

      const u32bit cert = indexes.back();

      if(certs[cert].is_verified(validation_cache_timeout))
         {
         if(certs[cert].verify_result() != VERIFIED)
            throw Internal_Error("X509_Store::construct_cert_chain");
         indexes.pop_back();
         }
      else
         break;
      }

   const u32bit last_cert = indexes.back();
   const u32bit parent_of_last_cert = find_parent_of(certs[last_cert].cert);
   if(parent_of_last_cert == NO_CERT_FOUND)
      return CERT_ISSUER_NOT_FOUND;
   indexes.push_back(parent_of_last_cert);

   return VERIFIED;
   }

/*
* Check the CAs signature on a certificate
*/
X509_Code X509_Store::check_sig(const Cert_Info& cert_info,
                                const Cert_Info& ca_cert_info) const
   {
   if(cert_info.is_verified(validation_cache_timeout))
      return cert_info.verify_result();

   const X509_Certificate& cert    = cert_info.cert;
   const X509_Certificate& ca_cert = ca_cert_info.cert;

   X509_Code verify_code = check_sig(cert, ca_cert.subject_public_key());

   cert_info.set_result(verify_code);

   return verify_code;
   }

/*
* Check a CA's signature
*/
X509_Code X509_Store::check_sig(const X509_Object& object, Public_Key* key)
   {
   std::auto_ptr<Public_Key> pub_key(key);
   std::auto_ptr<PK_Verifier> verifier;

   try {
      std::vector<std::string> sig_info =
         split_on(OIDS::lookup(object.signature_algorithm().oid), '/');

      if(sig_info.size() != 2 || sig_info[0] != pub_key->algo_name())
         return SIGNATURE_ERROR;

      std::string padding = sig_info[1];
      Signature_Format format;
      if(key->message_parts() >= 2) format = DER_SEQUENCE;
      else                          format = IEEE_1363;

      if(dynamic_cast<PK_Verifying_with_MR_Key*>(pub_key.get()))
         {
         PK_Verifying_with_MR_Key* sig_key =
            dynamic_cast<PK_Verifying_with_MR_Key*>(pub_key.get());
         verifier.reset(get_pk_verifier(*sig_key, padding, format));
         }
      else if(dynamic_cast<PK_Verifying_wo_MR_Key*>(pub_key.get()))
         {
         PK_Verifying_wo_MR_Key* sig_key =
            dynamic_cast<PK_Verifying_wo_MR_Key*>(pub_key.get());
         verifier.reset(get_pk_verifier(*sig_key, padding, format));
         }
      else
         return CA_CERT_CANNOT_SIGN;

      bool valid = verifier->verify_message(object.tbs_data(),
                                            object.signature());

      if(valid)
         return VERIFIED;
      else
         return SIGNATURE_ERROR;
      }
   catch(Decoding_Error) { return CERT_FORMAT_ERROR; }
   catch(Exception)      {}

   return UNKNOWN_X509_ERROR;
   }

/*
* Recompute the revocation status of the certs
*/
void X509_Store::recompute_revoked_info() const
   {
   if(revoked_info_valid)
      return;

   for(u32bit j = 0; j != certs.size(); ++j)
      {
      if((certs[j].is_verified(validation_cache_timeout)) &&
         (certs[j].verify_result() != VERIFIED))
         continue;

      if(is_revoked(certs[j].cert))
         certs[j].set_result(CERT_IS_REVOKED);
      }

   revoked_info_valid = true;
   }

/*
* Check if a certificate is revoked
*/
bool X509_Store::is_revoked(const X509_Certificate& cert) const
   {
   CRL_Data revoked_info;
   revoked_info.issuer = cert.issuer_dn();
   revoked_info.serial = cert.serial_number();
   revoked_info.auth_key_id = cert.authority_key_id();

   if(std::binary_search(revoked.begin(), revoked.end(), revoked_info))
      return true;
   return false;
   }

/*
* Retrieve all the certificates in the store
*/
std::vector<X509_Certificate>
X509_Store::get_certs(const Search_Func& search) const
   {
   std::vector<X509_Certificate> found_certs;
   for(u32bit j = 0; j != certs.size(); ++j)
      {
      if(search.match(certs[j].cert))
         found_certs.push_back(certs[j].cert);
      }
   return found_certs;
   }

/*
* Construct a path back to a root for this cert
*/
std::vector<X509_Certificate>
X509_Store::get_cert_chain(const X509_Certificate& cert)
   {
   std::vector<X509_Certificate> result;
   std::vector<u32bit> indexes;
   X509_Code chaining_result = construct_cert_chain(cert, indexes, true);

   if(chaining_result != VERIFIED)
      throw Invalid_State("X509_Store::get_cert_chain: Can't construct chain");

   for(u32bit j = 0; j != indexes.size(); ++j)
      result.push_back(certs[indexes[j]].cert);
   return result;
   }

/*
* Add a certificate store to the list of stores
*/
void X509_Store::add_new_certstore(Certificate_Store* certstore)
   {
   stores.push_back(certstore);
   }

/*
* Add a certificate to the store
*/
void X509_Store::add_cert(const X509_Certificate& cert, bool trusted)
   {
   if(trusted && !cert.is_self_signed())
      throw Invalid_Argument("X509_Store: Trusted certs must be self-signed");

   if(find_cert(cert.subject_dn(), cert.subject_key_id()) == NO_CERT_FOUND)
      {
      revoked_info_valid = false;
      Cert_Info info(cert, trusted);
      certs.push_back(info);
      }
   else if(trusted)
      {
      for(u32bit j = 0; j != certs.size(); ++j)
         {
         const X509_Certificate& this_cert = certs[j].cert;
         if(this_cert == cert)
            certs[j].trusted = trusted;
         }
      }
   }

/*
* Add one or more certificates to the store
*/
void X509_Store::do_add_certs(DataSource& source, bool trusted)
   {
   while(!source.end_of_data())
      {
      try {
         X509_Certificate cert(source);
         add_cert(cert, trusted);
         }
      catch(Decoding_Error) {}
      catch(Invalid_Argument) {}
      }
   }

/*
* Add one or more certificates to the store
*/
void X509_Store::add_certs(DataSource& source)
   {
   do_add_certs(source, false);
   }

/*
* Add one or more certificates to the store
*/
void X509_Store::add_trusted_certs(DataSource& source)
   {
   do_add_certs(source, true);
   }

/*
* Add one or more certificates to the store
*/
X509_Code X509_Store::add_crl(const X509_CRL& crl)
   {
   s32bit time_check = validity_check(crl.this_update(), crl.next_update(),
                                      system_time(), time_slack);

   if(time_check < 0)      return CRL_NOT_YET_VALID;
   else if(time_check > 0) return CRL_HAS_EXPIRED;

   u32bit cert_index = NO_CERT_FOUND;

   for(u32bit j = 0; j != certs.size(); ++j)
      {
      const X509_Certificate& this_cert = certs[j].cert;
      if(compare_ids(this_cert.subject_key_id(), crl.authority_key_id()))
         {
         if(this_cert.subject_dn() == crl.issuer_dn())
            cert_index = j;
         }
      }

   if(cert_index == NO_CERT_FOUND)
      return CRL_ISSUER_NOT_FOUND;

   const X509_Certificate& ca_cert = certs[cert_index].cert;

   X509_Code verify_result = validate_cert(ca_cert, CRL_SIGNING);
   if(verify_result != VERIFIED)
      return verify_result;

   verify_result = check_sig(crl, ca_cert.subject_public_key());
   if(verify_result != VERIFIED)
      return verify_result;

   std::vector<CRL_Entry> revoked_certs = crl.get_revoked();

   for(u32bit j = 0; j != revoked_certs.size(); ++j)
      {
      CRL_Data revoked_info;
      revoked_info.issuer = crl.issuer_dn();
      revoked_info.serial = revoked_certs[j].serial_number();
      revoked_info.auth_key_id = crl.authority_key_id();

      std::vector<CRL_Data>::iterator p =
         std::find(revoked.begin(), revoked.end(), revoked_info);

      if(revoked_certs[j].reason_code() == REMOVE_FROM_CRL)
         {
         if(p == revoked.end()) continue;
         revoked.erase(p);
         }
      else
         {
         if(p != revoked.end()) continue;
         revoked.push_back(revoked_info);
         }
      }

   std::sort(revoked.begin(), revoked.end());
   revoked_info_valid = false;

   return VERIFIED;
   }

/*
* PEM encode the set of certificates
*/
std::string X509_Store::PEM_encode() const
   {
   std::string cert_store;
   for(u32bit j = 0; j != certs.size(); ++j)
      cert_store += certs[j].cert.PEM_encode();
   return cert_store;
   }

/*
* Create a Cert_Info structure
*/
X509_Store::Cert_Info::Cert_Info(const X509_Certificate& c,
                                 bool t) : cert(c), trusted(t)
   {
   checked = false;
   result = UNKNOWN_X509_ERROR;
   last_checked = 0;
   }

/*
* Return the verification results
*/
X509_Code X509_Store::Cert_Info::verify_result() const
   {
   if(!checked)
      throw Invalid_State("Cert_Info::verify_result() called; not checked");
   return result;
   }

/*
* Set the verification results
*/
void X509_Store::Cert_Info::set_result(X509_Code code) const
   {
   result = code;
   last_checked = system_time();
   checked = true;
   }

/*
* Check if this certificate can be trusted
*/
bool X509_Store::Cert_Info::is_trusted() const
   {
   return trusted;
   }

/*
* Check if this certificate has been verified
*/
bool X509_Store::Cert_Info::is_verified(u32bit timeout) const
   {
   if(!checked)
      return false;
   if(result != VERIFIED && result != CERT_NOT_YET_VALID)
      return true;

   const u64bit current_time = system_time();

   if(current_time > last_checked + timeout)
      checked = false;

   return checked;
   }

}
