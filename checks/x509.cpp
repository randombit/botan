
#include <botan/filters.h>
#include <botan/x509self.h>
#include <botan/x509stor.h>
#include <botan/x509_ca.h>
#include <botan/pkcs10.h>
#include <botan/rsa.h>
#include <botan/dsa.h>
using namespace Botan;

#include <iostream>
#include <memory>

X509_Cert_Options ca_opts();
X509_Cert_Options req_opts1();
X509_Cert_Options req_opts2();

u64bit key_id(const Public_Key* key)
   {
   std::auto_ptr<X509_Encoder> encoder(key->x509_encoder());
   if(!encoder.get())
      throw Internal_Error("Public_Key:key_id: No encoder found");

   Pipe pipe(new Hash_Filter("SHA-1", 8));
   pipe.start_msg();
   pipe.write(key->algo_name());
   pipe.write(encoder->alg_id().parameters);
   pipe.write(encoder->key_bits());
   pipe.end_msg();

   SecureVector<byte> output = pipe.read_all();

   if(output.size() != 8)
      throw Internal_Error("Public_Key::key_id: Incorrect output size");

   u64bit id = 0;
   for(u32bit j = 0; j != 8; ++j)
      id = (id << 8) | output[j];
   return id;
   }

u32bit check_against_copy(const Private_Key& orig)
   {
   Private_Key* copy_priv = PKCS8::copy_key(orig);
   Public_Key* copy_pub = X509::copy_key(orig);

   const std::string passphrase= "I need work! -Mr. T"; // Me too...
   DataSource_Memory enc_source(PKCS8::PEM_encode(orig, passphrase));
   Private_Key* copy_priv_enc = PKCS8::load_key(enc_source, passphrase);

   u64bit orig_id = key_id(&orig);
   u64bit pub_id = key_id(copy_pub);
   u64bit priv_id = key_id(copy_priv);
   u64bit priv_enc_id = key_id(copy_priv_enc);

   delete copy_pub;
   delete copy_priv;
   delete copy_priv_enc;

   if(orig_id != pub_id || orig_id != priv_id || orig_id != priv_enc_id)
      {
      std::cout << "Failed copy check\n";
      return 1;
      }
   return 0;
   }

void do_x509_tests()
   {
   std::cout << "Testing X.509 CA/CRL/cert/cert request: " << std::flush;

   /* Create the CA's key and self-signed cert */
   std::cout << '.' << std::flush;
   RSA_PrivateKey ca_key(1024);

   std::cout << '.' << std::flush;
   X509_Certificate ca_cert = X509::create_self_signed_cert(ca_opts(), ca_key);
   std::cout << '.' << std::flush;

   /* Create user #1's key and cert request */
   std::cout << '.' << std::flush;
   DSA_PrivateKey user1_key(DL_Group("dsa/jce/1024"));
   std::cout << '.' << std::flush;
   PKCS10_Request user1_req = X509::create_cert_req(req_opts1(), user1_key);

   /* Create user #2's key and cert request */
   std::cout << '.' << std::flush;
   RSA_PrivateKey user2_key(768);
   std::cout << '.' << std::flush;
   PKCS10_Request user2_req = X509::create_cert_req(req_opts2(), user2_key);

   /* Create the CA object */
   std::cout << '.' << std::flush;
   X509_CA ca(ca_cert, ca_key);
   std::cout << '.' << std::flush;

   /* Sign the requests to create the certs */
   std::cout << '.' << std::flush;
   X509_Certificate user1_cert = ca.sign_request(user1_req);
   std::cout << '.' << std::flush;
   X509_Certificate user2_cert = ca.sign_request(user2_req);
   std::cout << '.' << std::flush;

   X509_CRL crl1 = ca.new_crl();

   /* Verify the certs */
   X509_Store store;

   store.add_cert(ca_cert, true); // second arg == true: trusted CA cert

   std::cout << '.' << std::flush;
   if(store.validate_cert(user1_cert) != VERIFIED)
      std::cout << "\nFAILED: User cert #1 did not validate" << std::endl;

   if(store.validate_cert(user2_cert) != VERIFIED)
      std::cout << "\nFAILED: User cert #2 did not validate" << std::endl;

   if(store.add_crl(crl1) != VERIFIED)
      std::cout << "\nFAILED: CRL #1 did not validate" << std::endl;

   std::vector<CRL_Entry> revoked;
   revoked.push_back(user2_cert);

   X509_CRL crl2 = ca.update_crl(crl1, revoked);

   if(store.add_crl(crl2) != VERIFIED)
      std::cout << "\nFAILED: CRL #2 did not validate" << std::endl;

   if(store.validate_cert(user2_cert) != CERT_IS_REVOKED)
      std::cout << "\nFAILED: User cert #2 was not revoked" << std::endl;

   check_against_copy(ca_key);
   check_against_copy(user1_key);
   check_against_copy(user2_key);

   std::cout << std::endl;
   }

/* Return some option sets */
X509_Cert_Options ca_opts()
   {
   X509_Cert_Options opts("Test CA/US/Botan Project/Testing");

   opts.uri = "http://botan.randombit.net";
   opts.dns = "botan.randombit.net";
   opts.email = "testing@randombit.net";

   opts.CA_key(1);

   return opts;
   }

X509_Cert_Options req_opts1()
   {
   X509_Cert_Options opts("Test User 1/US/Botan Project/Testing");

   opts.uri = "http://botan.randombit.net";
   opts.dns = "botan.randombit.net";
   opts.email = "testing@randombit.net";

   return opts;
   }

X509_Cert_Options req_opts2()
   {
   X509_Cert_Options opts("Test User 2/US/Botan Project/Testing");

   opts.uri = "http://botan.randombit.net";
   opts.dns = "botan.randombit.net";
   opts.email = "testing@randombit.net";

   opts.add_ex_constraint("PKIX.EmailProtection");

   return opts;
   }
