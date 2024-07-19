/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PSK_DB_H_
#define BOTAN_PSK_DB_H_

#include <botan/secmem.h>
#include <memory>
#include <set>
#include <span>
#include <string>

namespace Botan {

class BlockCipher;
class MessageAuthenticationCode;

/**
* This is an interface to a generic PSK (pre-shared key) database.
* It might be implemented as a plaintext storage or via some mechanism
* that encrypts the keys and/or values.
*/
class BOTAN_PUBLIC_API(2, 4) PSK_Database {
   public:
      /**
      * @returns the set of names for which get() will return a value.
      */
      virtual std::set<std::string> list_names() const = 0;

      /**
      * @returns the value associated with the specified @p name or otherwise
      * throw an exception.
      */
      virtual secure_vector<uint8_t> get(std::string_view name) const = 0;

      /**
      * Set a value that can later be accessed with get().
      * If name already exists in the database, the old value will be overwritten.
      */
      virtual void set(std::string_view name, const uint8_t psk[], size_t psk_len) = 0;

      /**
      * Remove the PSK with the given @p name from the database
      */
      virtual void remove(std::string_view name) = 0;

      /**
      * @returns true if the values in the PSK database are encrypted. If false,
      *          saved values are being stored in plaintext.
      */
      virtual bool is_encrypted() const = 0;

      /**
      * Get a PSK in the form of a string (eg if the PSK is a password)
      */
      std::string get_str(std::string_view name) const;

      /**
      * Like set() but accepts the PSK as a string (eg for a password).
      */
      void set_str(std::string_view name, std::string_view psk);

      /**
      * Like set() but accepting an arbitrary contiguous byte array.
      */
      void set_vec(std::string_view name, std::span<const uint8_t> psk) { set(name, psk.data(), psk.size()); }

      virtual ~PSK_Database() = default;
};

/**
* A mixin for an encrypted PSK database.
*
* Both names and values are encrypted using NIST key wrapping (see NIST
* SP800-38F) with AES-256. First the master key is used with HMAC(SHA-256) to
* derive two 256-bit keys, one for encrypting all names and the other to key an
* instance of HMAC(SHA-256). Values are each encrypted under an individual key
* created by hashing the encrypted name with HMAC. This associates the encrypted
* key with the name, and prevents an attacker with write access to the data
* store from taking an encrypted key associated with one entity and copying it
* to another entity.
*
* Names and PSKs are both padded to the next multiple of 8 bytes, providing some
* obfuscation of the length.
*
* Subclasses must implement the virtual calls to handle storing and getting raw
* (base64 encoded) values.
*/
class BOTAN_PUBLIC_API(2, 4) Encrypted_PSK_Database : public PSK_Database {
   public:
      /**
      * Initializes or opens a PSK database. The @p master_key is used to secure
      * the contents. It may be of any length. If encrypting PSKs under a
      * passphrase, use a suitable key derivation scheme (such as Argon2id) to
      * derive the secret key. If the master key is lost, all PSKs stored are
      * unrecoverable.
      *
      * One artifact of the names being encrypted is that is is possible to use
      * multiple different master keys with the same underlying storage. Each
      * master key will be responsible for a subset of the keys. An attacker who
      * knows one of the keys will be able to tell there are other values
      * encrypted under another key, but will not be able to tell how many other
      * master keys are in use.
      *
      * @param master_key specifies the master key used to encrypt all
      * keys and value. It can be of any length, but should be at least 256 bits.
      *
      * Subkeys for the cryptographic algorithms used are derived from this
      * master key. No key stretching is performed; if encrypting a PSK database
      * using a password, it is recommended to use Argon2id to derive the database
      * master key.
      */
      Encrypted_PSK_Database(const secure_vector<uint8_t>& master_key);

      ~Encrypted_PSK_Database() override;

      std::set<std::string> list_names() const override;

      secure_vector<uint8_t> get(std::string_view name) const override;

      void set(std::string_view name, const uint8_t psk[], size_t psk_len) override;

      void remove(std::string_view name) override;

      bool is_encrypted() const override { return true; }

   protected:
      /**
      * Save a encrypted (name/value) pair to the database. Both will be base64
      * encoded strings.
      */
      virtual void kv_set(std::string_view index, std::string_view value) = 0;

      /**
      * Get a value previously saved with kv_set(). Should return an empty
      * string if @p index is not found.
      */
      virtual std::string kv_get(std::string_view index) const = 0;

      /**
      * Remove an @p index
      */
      virtual void kv_del(std::string_view index) = 0;

      /**
      * Return all indexes in the table (ie values for which ``kv_get`` will
      * return a non-empty string)
      */
      virtual std::set<std::string> kv_get_all() const = 0;

   private:
      std::unique_ptr<BlockCipher> m_cipher;
      std::unique_ptr<MessageAuthenticationCode> m_hmac;
      secure_vector<uint8_t> m_wrap_key;
};

class SQL_Database;

class BOTAN_PUBLIC_API(2, 4) Encrypted_PSK_Database_SQL : public Encrypted_PSK_Database {
   public:
      /**
      * Creates or uses the named table in @p db. The SQL schema of the table is
      * `(psk_name TEXT PRIMARY KEY, psk_value TEXT)`.
      */
      Encrypted_PSK_Database_SQL(const secure_vector<uint8_t>& master_key,
                                 std::shared_ptr<SQL_Database> db,
                                 std::string_view table_name);

      ~Encrypted_PSK_Database_SQL() override;

   private:
      void kv_set(std::string_view index, std::string_view value) override;
      std::string kv_get(std::string_view index) const override;
      void kv_del(std::string_view index) override;
      std::set<std::string> kv_get_all() const override;

      std::shared_ptr<SQL_Database> m_db;
      const std::string m_table_name;
};

}  // namespace Botan

#endif
