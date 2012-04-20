/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstdlib>
#include <memory>

#include <botan/botan.h>
#include <botan/oids.h>

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO)
  #include <botan/x509_key.h>
  #include <botan/pkcs8.h>
  #include <botan/pubkey.h>
#endif

#if defined(BOTAN_HAS_RSA)
  #include <botan/rsa.h>
#endif

#if defined(BOTAN_HAS_DSA)
  #include <botan/dsa.h>
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
  #include <botan/dh.h>
#endif

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
  #include <botan/nr.h>
#endif

#if defined(BOTAN_HAS_RW)
  #include <botan/rw.h>
#endif

#if defined(BOTAN_HAS_ELGAMAL)
  #include <botan/elgamal.h>
#endif

#if defined(BOTAN_HAS_ECDSA)
  #include <botan/ecdsa.h>
#endif

#if defined(BOTAN_HAS_ECDH)
  #include <botan/ecdh.h>
#endif

#if defined(BOTAN_HAS_GOST_34_10_2001)
  #include <botan/gost_3410.h>
#endif

#if defined(BOTAN_HAS_DLIES)
  #include <botan/dlies.h>
  #include <botan/kdf.h>
#endif

#include <botan/filters.h>
#include <botan/numthry.h>
using namespace Botan;

#include "common.h"
#include "validate.h"

namespace {

BigInt to_bigint(std::string input)
   {
   while(input.find(' ') != std::string::npos)
      input = input.erase(input.find(' '), 1);

   while(input.find('\t') != std::string::npos)
      input = input.erase(input.find('\t'), 1);

   while(input.find('\n') != std::string::npos)
      input = input.erase(input.find('\n'), 1);

   return BigInt::decode(reinterpret_cast<const byte*>(input.data()),
                         input.length(), BigInt::Hexadecimal);
   }

void dump_data(const SecureVector<byte>& out,
               const SecureVector<byte>& expected)
   {
   Pipe pipe(new Hex_Encoder);

   pipe.process_msg(out);
   pipe.process_msg(expected);
   std::cout << "Got: " << pipe.read_all_as_string(0) << std::endl;
   std::cout << "Exp: " << pipe.read_all_as_string(1) << std::endl;
   }

void validate_save_and_load(const Private_Key* priv_key,
                            RandomNumberGenerator& rng)
   {
   std::string name = priv_key->algo_name();

   std::string pub_pem = X509::PEM_encode(*priv_key);

   try
      {
      DataSource_Memory input_pub(pub_pem);
      std::auto_ptr<Public_Key> restored_pub(X509::load_key(input_pub));

      if(restored_pub.get() == 0)
         std::cout << "Could not recover " << name << " public key\n";
      else if(restored_pub->check_key(rng, true) == false)
         std::cout << "Restored pubkey failed self tests " << name << "\n";
      }
   catch(std::exception& e)
      {
      std::cout << "Exception during load of " << name
                << " key: " << e.what() << "\n";
      std::cout << "PEM for pubkey was:\n" << pub_pem << "\n";
      }

   std::string priv_pem = PKCS8::PEM_encode(*priv_key);

   try
      {
      DataSource_Memory input_priv(priv_pem);
      std::auto_ptr<Private_Key> restored_priv(
         PKCS8::load_key(input_priv, rng));

      if(restored_priv.get() == 0)
         std::cout << "Could not recover " << name << " privlic key\n";
      else if(restored_priv->check_key(rng, true) == false)
         std::cout << "Restored privkey failed self tests " << name << "\n";
      }
   catch(std::exception& e)
      {
      std::cout << "Exception during load of " << name
                << " key: " << e.what() << "\n";
      std::cout << "PEM for privkey was:\n" << priv_pem << "\n";
      }
   }

void validate_decryption(PK_Decryptor& d, const std::string& algo,
                         const SecureVector<byte> ctext,
                         const SecureVector<byte> ptext,
                         bool& failure)
   {
   SecureVector<byte> decrypted = d.decrypt(ctext);
   if(decrypted != ptext)
      {
      std::cout << "FAILED (decrypt): " << algo << std::endl;
      dump_data(decrypted, ptext);
      failure = true;
      }
   }

void validate_encryption(PK_Encryptor& e, PK_Decryptor& d,
                         const std::string& algo, const std::string& input,
                         const std::string& random, const std::string& exp,
                         bool& failure)
   {
   SecureVector<byte> message = hex_decode(input);
   SecureVector<byte> expected = hex_decode(exp);
   Fixed_Output_RNG rng(hex_decode(random));

   SecureVector<byte> out = e.encrypt(message, rng);
   if(out != expected)
      {
      std::cout << "FAILED (encrypt): " << algo << std::endl;
      dump_data(out, expected);
      failure = true;
      }

   validate_decryption(d, algo, out, message, failure);
   }

void validate_signature(PK_Verifier& v, PK_Signer& s, const std::string& algo,
                        const std::string& input,
                        RandomNumberGenerator& rng,
                        const std::string& exp, bool& failure)
   {
   SecureVector<byte> message = hex_decode(input);

   SecureVector<byte> expected = hex_decode(exp);

   SecureVector<byte> sig = s.sign_message(message, rng);

   if(sig != expected)
      {
      std::cout << "FAILED (sign): " << algo << std::endl;
      dump_data(sig, expected);
      failure = true;
      }

   if(!v.verify_message(message, sig))
      {
      std::cout << "FAILED (verify): " << algo << std::endl;
      failure = true;
      }

   /* This isn't a very thorough testing method, but it will hopefully
      catch any really horrible errors */
   sig[0]++;
   if(v.verify_message(message, sig))
      {
      std::cout << "FAILED (accepted bad sig): " << algo << std::endl;
      failure = true;
      }
   }

void validate_signature(PK_Verifier& v, PK_Signer& s, const std::string& algo,
                        const std::string& input,
                        const std::string& random,
                        const std::string& exp, bool& failure)
   {
   Fixed_Output_RNG rng(hex_decode(random));

   validate_signature(v, s, algo, input, rng, exp, failure);
   }

void validate_kas(PK_Key_Agreement& kas, const std::string& algo,
                  const SecureVector<byte>& pubkey, const std::string& output,
                  u32bit keylen, bool& failure)
   {
   SecureVector<byte> expected = hex_decode(output);

   SecureVector<byte> got = kas.derive_key(keylen,
                                           pubkey).bits_of();

   if(got != expected)
      {
      std::cout << "FAILED: " << algo << std::endl;
      dump_data(got, expected);
      failure = true;
      }
   }

u32bit validate_rsa_enc_pkcs8(const std::string& algo,
                              const std::vector<std::string>& str,
                              RandomNumberGenerator& rng)
   {
   if(str.size() != 4 && str.size() != 5)
      throw std::runtime_error("Invalid input from pk_valid.dat");


#if defined(BOTAN_HAS_RSA)
   std::string pass;
   if(str.size() == 5) pass = str[4];
   strip_newlines(pass); /* it will have a newline thanks to the messy
                                decoding method we use */

   DataSource_Memory keysource(reinterpret_cast<const byte*>(str[0].c_str()),
                               str[0].length());

   std::auto_ptr<Private_Key> privkey(PKCS8::load_key(keysource, rng, pass));

   RSA_PrivateKey* rsapriv = dynamic_cast<RSA_PrivateKey*>(privkey.get());
   if(!rsapriv)
      throw Invalid_Argument("Bad key load for RSA key");

   RSA_PublicKey* rsapub = dynamic_cast<RSA_PublicKey*>(rsapriv);

   std::string eme = algo.substr(12, std::string::npos);

   PK_Encryptor_EME e(*rsapub, eme);
   PK_Decryptor_EME d(*rsapriv, eme);

   bool failure = false;
   validate_encryption(e, d, algo, str[1], str[2], str[3], failure);
   return (failure ? 1 : 0);
#endif

   return 2;
   }

u32bit validate_rsa_enc(const std::string& algo,
                        const std::vector<std::string>& str,
                        RandomNumberGenerator& rng)
   {
   if(str.size() != 6)
      throw std::runtime_error("Invalid input from pk_valid.dat");

#if defined(BOTAN_HAS_RSA)
   RSA_PrivateKey privkey(rng,
                          to_bigint(str[1]), to_bigint(str[2]),
                          to_bigint(str[0]));

   RSA_PublicKey pubkey = privkey;

   std::string eme = algo.substr(6, std::string::npos);

   PK_Encryptor_EME e(pubkey, eme);
   PK_Decryptor_EME d(privkey, eme);

   bool failure = false;
   validate_encryption(e, d, algo, str[3], str[4], str[5], failure);
   return (failure ? 1 : 0);
#endif

   return 2;
   }

u32bit validate_elg_enc(const std::string& algo,
                        const std::vector<std::string>& str,
                        RandomNumberGenerator& rng)
   {
   if(str.size() != 6 && str.size() != 7)
      throw std::runtime_error("Invalid input from pk_valid.dat");


#if defined(BOTAN_HAS_ELGAMAL)
   DL_Group domain(to_bigint(str[0]), to_bigint(str[1]));
   ElGamal_PrivateKey privkey(rng, domain, to_bigint(str[2]));
   ElGamal_PublicKey pubkey = privkey;

   std::string eme = algo.substr(8, std::string::npos);

   PK_Decryptor_EME d(privkey, eme);

   bool failure = false;
   if(str.size() == 7)
      {
      PK_Encryptor_EME e(pubkey, eme);
      validate_encryption(e, d, algo, str[4], str[5], str[6], failure);
      }
   else
      validate_decryption(d, algo, hex_decode(str[5]),
                          hex_decode(str[4]), failure);
   return (failure ? 1 : 0);
#endif

   return 2;
   }

u32bit validate_rsa_sig(const std::string& algo,
                        const std::vector<std::string>& str,
                        RandomNumberGenerator& rng)
   {
   if(str.size() != 6)
      throw std::runtime_error("Invalid input from pk_valid.dat");


#if defined(BOTAN_HAS_RSA)
   RSA_PrivateKey privkey(rng,
                          to_bigint(str[1]), to_bigint(str[2]),
                          to_bigint(str[0]));

   RSA_PublicKey pubkey = privkey;

   std::string emsa = algo.substr(7, std::string::npos);

   PK_Verifier v(pubkey, emsa);
   PK_Signer s(privkey, emsa);
   bool failure = false;
   validate_signature(v, s, algo, str[3], str[4], str[5], failure);
   return (failure ? 1 : 0);
#endif

   return 2;
   }

u32bit validate_rsa_ver(const std::string& algo,
                        const std::vector<std::string>& str)
   {
   if(str.size() != 5) /* is actually 4, parse() adds an extra empty one */
      throw std::runtime_error("Invalid input from pk_valid.dat");

#if defined(BOTAN_HAS_RSA)
   RSA_PublicKey key(to_bigint(str[1]), to_bigint(str[0]));

   std::string emsa = algo.substr(6, std::string::npos);

   PK_Verifier v(key, emsa);

   SecureVector<byte> msg = hex_decode(str[2]);
   SecureVector<byte> sig = hex_decode(str[3]);

   bool passed = true;
   passed = v.verify_message(msg, sig);
   return (passed ? 0 : 1);
#endif

   return 2;
   }

u32bit validate_rsa_ver_x509(const std::string& algo,
                             const std::vector<std::string>& str)
   {
   if(str.size() != 5) /* is actually 3, parse() adds extra empty ones */
      throw std::runtime_error("Invalid input from pk_valid.dat");

#if defined(BOTAN_HAS_RSA)
   DataSource_Memory keysource(reinterpret_cast<const byte*>(str[0].c_str()),
                               str[0].length());

   std::auto_ptr<Public_Key> key(X509::load_key(keysource));

   RSA_PublicKey* rsakey = dynamic_cast<RSA_PublicKey*>(key.get());

   if(!rsakey)
      throw Invalid_Argument("Bad key load for RSA public key");

   std::string emsa = algo.substr(11, std::string::npos);

   PK_Verifier v(*rsakey, emsa);

   SecureVector<byte> msg = hex_decode(str[1]);
   SecureVector<byte> sig = hex_decode(str[2]);

   bool passed = v.verify_message(msg, sig);
   return (passed ? 0 : 1);

#endif

   return 2;
   }

u32bit validate_rw_ver(const std::string& algo,
                       const std::vector<std::string>& str)
   {
   if(str.size() != 5)
      throw std::runtime_error("Invalid input from pk_valid.dat");

#if defined(BOTAN_HAS_RW)
   RW_PublicKey key(to_bigint(str[1]), to_bigint(str[0]));

   std::string emsa = algo.substr(5, std::string::npos);

   PK_Verifier v(key, emsa);

   SecureVector<byte> msg = hex_decode(str[2]);
   SecureVector<byte> sig = hex_decode(str[3]);

   bool passed = true;
   passed = v.verify_message(msg, sig);
   return (passed ? 0 : 1);
#endif

   return 2;
   }

u32bit validate_rw_sig(const std::string& algo,
                       const std::vector<std::string>& str,
                       RandomNumberGenerator& rng)
   {
   if(str.size() != 5)
      throw std::runtime_error("Invalid input from pk_valid.dat");

#if defined(BOTAN_HAS_RW)
   RW_PrivateKey privkey(rng, to_bigint(str[1]), to_bigint(str[2]),
                         to_bigint(str[0]));
   RW_PublicKey pubkey = privkey;

   std::string emsa = algo.substr(3, std::string::npos);

   PK_Verifier v(pubkey, emsa);
   PK_Signer s(privkey, emsa);

   bool failure = false;
   validate_signature(v, s, algo, str[3], rng, str[4], failure);
   return (failure ? 1 : 0);
#endif

   return 2;
   }

u32bit validate_dsa_sig(const std::string& algo,
                        const std::vector<std::string>& str,
                        RandomNumberGenerator& rng)
   {
   if(str.size() != 4 && str.size() != 5)
      throw std::runtime_error("Invalid input from pk_valid.dat");

   std::string pass;
   if(str.size() == 5) pass = str[4];
   strip_newlines(pass); /* it will have a newline thanks to the messy
                                decoding method we use */

#if defined(BOTAN_HAS_DSA)

   DataSource_Memory keysource(reinterpret_cast<const byte*>(str[0].c_str()),
                               str[0].length());

   std::auto_ptr<Private_Key> privkey(PKCS8::load_key(keysource, rng, pass));

   DSA_PrivateKey* dsapriv = dynamic_cast<DSA_PrivateKey*>(privkey.get());
   if(!dsapriv)
      throw Invalid_Argument("Bad key load for DSA private key");

   DSA_PublicKey* dsapub = dynamic_cast<DSA_PublicKey*>(dsapriv);

   std::string emsa = algo.substr(4, std::string::npos);

   PK_Verifier v(*dsapub, emsa);
   PK_Signer s(*dsapriv, emsa);

   bool failure = false;
   validate_signature(v, s, algo, str[1], str[2], str[3], failure);
   return (failure ? 1 : 0);
#endif

   return 2;
   }

u32bit validate_ecdsa_sig(const std::string& algo,
                          const std::vector<std::string>& str,
                          RandomNumberGenerator& rng)
   {
   if(str.size() != 5)
      throw std::runtime_error("Invalid input from pk_valid.dat");

#if defined(BOTAN_HAS_ECDSA)

   EC_Group group(OIDS::lookup(str[0]));
   ECDSA_PrivateKey ecdsa(rng, group, to_bigint(str[1]));

   std::string emsa = algo.substr(6, std::string::npos);

   PK_Verifier v(ecdsa, emsa);
   PK_Signer s(ecdsa, emsa);

   bool failure = false;
   validate_signature(v, s, algo, str[2], str[3], str[4], failure);
   return (failure ? 1 : 0);
#endif

   return 2;
   }

u32bit validate_gost_ver(const std::string& algo,
                         const std::vector<std::string>& str)
   {
   if(str.size() != 5)
      throw std::runtime_error("Invalid input from pk_valid.dat");

#if defined(BOTAN_HAS_GOST_34_10_2001)

   EC_Group group(OIDS::lookup(str[0]));

   PointGFp public_point = OS2ECP(hex_decode(str[1]), group.get_curve());

   GOST_3410_PublicKey gost(group, public_point);

   std::string emsa = algo.substr(13, std::string::npos);

   PK_Verifier v(gost, emsa);

   SecureVector<byte> msg = hex_decode(str[2]);
   SecureVector<byte> sig = hex_decode(str[3]);

   bool passed = v.verify_message(msg, sig);
   return (passed ? 0 : 1);
#endif

   return 2;
   }

u32bit validate_dsa_ver(const std::string& algo,
                        const std::vector<std::string>& str)
   {
   if(str.size() != 5) /* is actually 3, parse() adds extra empty ones */
      throw std::runtime_error("Invalid input from pk_valid.dat");

   DataSource_Memory keysource(reinterpret_cast<const byte*>(str[0].c_str()),
                               str[0].length());


#if defined(BOTAN_HAS_DSA)
   std::auto_ptr<Public_Key> key(X509::load_key(keysource));

   DSA_PublicKey* dsakey = dynamic_cast<DSA_PublicKey*>(key.get());

   if(!dsakey)
      throw Invalid_Argument("Bad key load for DSA public key");

   std::string emsa = algo.substr(7, std::string::npos);

   PK_Verifier v(*dsakey, emsa);

   SecureVector<byte> msg = hex_decode(str[1]);
   SecureVector<byte> sig = hex_decode(str[2]);

   v.set_input_format(DER_SEQUENCE);
   bool passed = v.verify_message(msg, sig);
   return (passed ? 0 : 1);
#endif

   return 2;
   }

u32bit validate_nr_sig(const std::string& algo,
                       const std::vector<std::string>& str,
                       RandomNumberGenerator& rng)
   {
   if(str.size() != 8)
      throw std::runtime_error("Invalid input from pk_valid.dat");


#if defined(BOTAN_HAS_NYBERG_RUEPPEL)

   DL_Group domain(to_bigint(str[0]), to_bigint(str[1]), to_bigint(str[2]));
   NR_PrivateKey privkey(rng, domain, to_bigint(str[4]));
   NR_PublicKey pubkey = privkey;

   std::string emsa = algo.substr(3, std::string::npos);

   PK_Verifier v(pubkey, emsa);
   PK_Signer s(privkey, emsa);

   bool failure = false;
   validate_signature(v, s, algo, str[5], str[6], str[7], failure);
   return (failure ? 1 : 0);
#endif

   return 2;
   }

u32bit validate_dh(const std::string& algo,
                   const std::vector<std::string>& str,
                   RandomNumberGenerator& rng)
   {
   if(str.size() != 5 && str.size() != 6)
      throw std::runtime_error("Invalid input from pk_valid.dat");


#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
   DL_Group domain(to_bigint(str[0]), to_bigint(str[1]));

   DH_PrivateKey mykey(rng, domain, to_bigint(str[2]));
   DH_PublicKey otherkey(domain, to_bigint(str[3]));

   std::string kdf = algo.substr(3, std::string::npos);

   u32bit keylen = 0;
   if(str.size() == 6)
      keylen = to_u32bit(str[5]);

   PK_Key_Agreement kas(mykey, kdf);

   bool failure = false;
   validate_kas(kas, algo, otherkey.public_value(),
                str[4], keylen, failure);
   return (failure ? 1 : 0);
#endif

   return 2;
   }

u32bit validate_dlies(const std::string& algo,
                      const std::vector<std::string>& str,
                      RandomNumberGenerator& rng)
   {
   if(str.size() != 6)
      throw std::runtime_error("Invalid input from pk_valid.dat");

#if defined(BOTAN_HAS_DLIES)
   DL_Group domain(to_bigint(str[0]), to_bigint(str[1]));

   DH_PrivateKey from(rng, domain, to_bigint(str[2]));
   DH_PrivateKey to(rng, domain, to_bigint(str[3]));

   const std::string opt_str = algo.substr(6, std::string::npos);

   std::vector<std::string> options = split_on(opt_str, '/');

   if(options.size() != 3)
      throw std::runtime_error("DLIES needs three options: " + opt_str);

   MessageAuthenticationCode* mac = get_mac(options[1]);
   u32bit mac_key_len = to_u32bit(options[2]);

   DLIES_Encryptor e(from,
                     get_kdf(options[0]),
                     mac, mac_key_len);

   DLIES_Decryptor d(to,
                     get_kdf(options[0]),
                     mac->clone(), mac_key_len);

   e.set_other_key(to.public_value());

   std::string empty = "";
   bool failure = false;
   validate_encryption(e, d, algo, str[4], empty, str[5], failure);
   return (failure ? 1 : 0);
#else
   return 2;
#endif
   }

void do_pk_keygen_tests(RandomNumberGenerator& rng)
   {
   std::cout << "Testing PK key generation: " << std::flush;

#define DL_KEY(TYPE, GROUP)                 \
   {                                        \
   TYPE key(rng, DL_Group(GROUP));          \
   key.check_key(rng, true);                \
   validate_save_and_load(&key, rng);       \
   std::cout << '.' << std::flush;          \
   }

#define EC_KEY(TYPE, GROUP)                 \
   {                                        \
   TYPE key(rng, EC_Group(OIDS::lookup(GROUP)));        \
   key.check_key(rng, true);                \
   validate_save_and_load(&key, rng);       \
   std::cout << '.' << std::flush;          \
   }

#if defined(BOTAN_HAS_RSA)
      {
      RSA_PrivateKey rsa1024(rng, 1024);
      rsa1024.check_key(rng, true);
      validate_save_and_load(&rsa1024, rng);
      std::cout << '.' << std::flush;
      }
#endif

#if defined(BOTAN_HAS_RW)
      {
      RW_PrivateKey rw1024(rng, 1024);
      rw1024.check_key(rng, true);
      validate_save_and_load(&rw1024, rng);
      std::cout << '.' << std::flush;
      }
#endif

#if defined(BOTAN_HAS_DSA)
   DL_KEY(DSA_PrivateKey, "dsa/jce/512");
   DL_KEY(DSA_PrivateKey, "dsa/jce/768");
   DL_KEY(DSA_PrivateKey, "dsa/jce/1024");
   DL_KEY(DSA_PrivateKey, "dsa/botan/2048");
   DL_KEY(DSA_PrivateKey, "dsa/botan/3072");
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
   DL_KEY(DH_PrivateKey, "modp/ietf/768");
   DL_KEY(DH_PrivateKey, "modp/ietf/1024");
   DL_KEY(DH_PrivateKey, "modp/ietf/2048");
   DL_KEY(DH_PrivateKey, "modp/ietf/4096");
   DL_KEY(DH_PrivateKey, "dsa/jce/1024");
#endif

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
   DL_KEY(NR_PrivateKey, "dsa/jce/512");
   DL_KEY(NR_PrivateKey, "dsa/jce/768");
   DL_KEY(NR_PrivateKey, "dsa/jce/1024");
   DL_KEY(NR_PrivateKey, "dsa/botan/2048");
   DL_KEY(NR_PrivateKey, "dsa/botan/3072");
#endif

#if defined(BOTAN_HAS_ELGAMAL)
   DL_KEY(ElGamal_PrivateKey, "modp/ietf/768");
   DL_KEY(ElGamal_PrivateKey, "modp/ietf/1024");
   DL_KEY(ElGamal_PrivateKey, "dsa/jce/1024");
   DL_KEY(ElGamal_PrivateKey, "dsa/botan/2048");
   DL_KEY(ElGamal_PrivateKey, "dsa/botan/3072");
#endif

#if defined(BOTAN_HAS_ECDSA)
   EC_KEY(ECDSA_PrivateKey, "secp112r1");
   EC_KEY(ECDSA_PrivateKey, "secp128r1");
   EC_KEY(ECDSA_PrivateKey, "secp160r1");
   EC_KEY(ECDSA_PrivateKey, "secp192r1");
   EC_KEY(ECDSA_PrivateKey, "secp224r1");
   EC_KEY(ECDSA_PrivateKey, "secp256r1");
   EC_KEY(ECDSA_PrivateKey, "secp384r1");
   EC_KEY(ECDSA_PrivateKey, "secp521r1");
#endif

#if defined(BOTAN_HAS_GOST_34_10_2001)
   EC_KEY(GOST_3410_PrivateKey, "gost_256A");
   EC_KEY(GOST_3410_PrivateKey, "secp112r1");
   EC_KEY(GOST_3410_PrivateKey, "secp128r1");
   EC_KEY(GOST_3410_PrivateKey, "secp160r1");
   EC_KEY(GOST_3410_PrivateKey, "secp192r1");
   EC_KEY(GOST_3410_PrivateKey, "secp224r1");
   EC_KEY(GOST_3410_PrivateKey, "secp256r1");
   EC_KEY(GOST_3410_PrivateKey, "secp384r1");
   EC_KEY(GOST_3410_PrivateKey, "secp521r1");
#endif

   std::cout << std::endl;
   }

}

u32bit do_pk_validation_tests(const std::string& filename,
                              RandomNumberGenerator& rng)
   {
   std::ifstream test_data(filename.c_str());

   if(!test_data)
      throw Botan::Stream_IO_Error("Couldn't open test file " + filename);

   u32bit errors = 0, alg_count = 0;
   std::string algorithm, print_algorithm;

   while(!test_data.eof())
      {
      if(test_data.bad() || test_data.fail())
         throw Botan::Stream_IO_Error("File I/O error reading from " +
                                      filename);

      std::string line;
      std::getline(test_data, line);

      strip_comments(line);
      if(line.size() == 0) continue;

      // Do line continuation
      while(line[line.size()-1] == '\\' && !test_data.eof())
         {
         line.replace(line.size()-1, 1, "");
         std::string nextline;
         std::getline(test_data, nextline);
         strip_comments(nextline);
         if(nextline.size() == 0) continue;
         line.push_back('\n');
         line += nextline;
         }

      if(line[0] == '[' && line[line.size() - 1] == ']')
         {
         std::string old_algo = print_algorithm;
         algorithm = line.substr(1, line.size() - 2);
         print_algorithm = algorithm;
         if(print_algorithm.find("_PKCS8") != std::string::npos)
            print_algorithm.replace(print_algorithm.find("_PKCS8"), 6, "");
         if(print_algorithm.find("_X509") != std::string::npos)
            print_algorithm.replace(print_algorithm.find("_X509"), 5, "");
         if(print_algorithm.find("_VA") != std::string::npos)
            print_algorithm.replace(print_algorithm.find("_VA"), 3, "");

         if(old_algo != print_algorithm && old_algo != "")
            {
            std::cout << std::endl;
            alg_count = 0;
            }

         if(old_algo != print_algorithm)
            std::cout << "Testing " << print_algorithm << ": ";
         continue;
         }

      std::vector<std::string> substr = parse(line);

#if 0
      std::cout << "Testing: " << print_algorithm << std::endl;
#endif

      u32bit new_errors = 0;

      try
         {

         if(algorithm.find("DSA/") == 0)
            new_errors = validate_dsa_sig(algorithm, substr, rng);
         else if(algorithm.find("DSA_VA/") == 0)
            new_errors = validate_dsa_ver(algorithm, substr);

         else if(algorithm.find("ECDSA/") == 0)
            new_errors = validate_ecdsa_sig(algorithm, substr, rng);

         else if(algorithm.find("GOST_3410_VA/") == 0)
            new_errors = validate_gost_ver(algorithm, substr);

         else if(algorithm.find("RSAES_PKCS8/") == 0)
            new_errors = validate_rsa_enc_pkcs8(algorithm, substr, rng);
         else if(algorithm.find("RSAVA_X509/") == 0)
            new_errors = validate_rsa_ver_x509(algorithm, substr);

         else if(algorithm.find("RSAES/") == 0)
            new_errors = validate_rsa_enc(algorithm, substr, rng);
         else if(algorithm.find("RSASSA/") == 0)
            new_errors = validate_rsa_sig(algorithm, substr, rng);
         else if(algorithm.find("RSAVA/") == 0)
            new_errors = validate_rsa_ver(algorithm, substr);
         else if(algorithm.find("RWVA/") == 0)
            new_errors = validate_rw_ver(algorithm, substr);
         else if(algorithm.find("RW/") == 0)
            new_errors = validate_rw_sig(algorithm, substr, rng);
         else if(algorithm.find("NR/") == 0)
            new_errors = validate_nr_sig(algorithm, substr, rng);
         else if(algorithm.find("ElGamal/") == 0)
            new_errors = validate_elg_enc(algorithm, substr, rng);
         else if(algorithm.find("DH/") == 0)
            new_errors = validate_dh(algorithm, substr, rng);
         else if(algorithm.find("DLIES/") == 0)
            new_errors = validate_dlies(algorithm, substr, rng);
         else
            std::cout << "WARNING: Unknown PK algorithm "
                      << algorithm << std::endl;

         if(new_errors == 0) // OK
            std::cout << '.';
         else if(new_errors == 1) // test failed
            std::cout << 'X';
         else if(new_errors == 2) // unknown algo
            std::cout << '?';

         std::cout.flush();

         alg_count++;
         if(new_errors == 1)
            errors += new_errors;
         }
      catch(std::exception& e)
         {
         std::cout << "Exception: " << e.what() << "\n";
         }

      if(new_errors == 1)
         std::cout << "ERROR: \"" << algorithm << "\" failed test #"
                   << std::dec << alg_count << std::endl;
      }

   std::cout << std::endl;

   do_ec_tests(rng);
   errors += do_ecdsa_tests(rng);
   errors += do_ecdh_tests(rng);
   do_pk_keygen_tests(rng);

   return errors;
   }

