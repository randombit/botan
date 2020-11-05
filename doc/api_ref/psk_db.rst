PSK Database
======================

.. versionadded:: 2.4.0

Many applications need to store pre-shared keys (hereafter PSKs) for
authentication purposes.

An abstract interface to PSK stores, along with some implementations
of same, are provided in ``psk_db.h``

.. cpp:class:: PSK_Database

   .. cpp:function:: bool is_encrypted() const

      Returns true if (at least) the PSKs themselves are encrypted. Returns
      false if PSKs are stored in plaintext.

   .. cpp:function:: std::set<std::string> list_names() const

      Return the set of valid names stored in the database, ie values for which
      ``get`` will return a value.

   .. cpp:function:: void set(const std::string& name, const uint8_t psk[], size_t psk_len)

      Save a PSK. If ``name`` already exists, the current value will be
      overwritten.

   .. cpp:function:: secure_vector<uint8_t> get(const std::string& name) const

      Return a value saved with ``set``. Throws an exception if ``name`` doesn't
      exist.

   .. cpp:function:: void remove(const std::string& name)

      Remove ``name`` from the database. If ``name`` doesn't exist, ignores the request.

   .. cpp::function:: std::string get_str(const std::string& name) const

      Like ``get`` but casts the return value to a string.

   .. cpp:function:: void set_str(const std::string& name, const std::string& psk)

      Like ``set`` but accepts the psk as a string (eg for a password).

   .. cpp:function:: template<typename Alloc> void set_vec(const std::string& name, \
                                              const std::vector<uint8_t, Alloc>& psk)

      Like ``set`` but accepting a vector.

The same header also provides a specific instantiation of ``PSK_Database`` which
encrypts both names and PSKs. It must be subclassed to provide the storage.

.. cpp:class:: Encrypted_PSK_Database : public PSK_Database

   .. cpp:function:: Encrypted_PSK_Database(const secure_vector<uint8_t>& master_key)

      Initializes or opens a PSK database. The master key is used the secure the
      contents. It may be of any length. If encrypting PSKs under a passphrase,
      use a suitable key derivation scheme (such as PBKDF2) to derive the secret
      key. If the master key is lost, all PSKs stored are unrecoverable.

      Both names and values are encrypted using NIST key wrapping (see NIST
      SP800-38F) with AES-256. First the master key is used with HMAC(SHA-256)
      to derive two 256-bit keys, one for encrypting all names and the other to
      key an instance of HMAC(SHA-256). Values are each encrypted under an
      individual key created by hashing the encrypted name with HMAC. This
      associates the encrypted key with the name, and prevents an attacker with
      write access to the data store from taking an encrypted key associated
      with one entity and copying it to another entity.

      Names and PSKs are both padded to the next multiple of 8 bytes, providing
      some obfuscation of the length.

      One artifact of the names being encrypted is that is is possible to use
      multiple different master keys with the same underlying storage. Each
      master key will be responsible for a subset of the keys. An attacker who
      knows one of the keys will be able to tell there are other values
      encrypted under another key, but will not be able to tell how many other
      master keys are in use.

   .. cpp:function:: virtual void kv_set(const std::string& index, const std::string& value) = 0

      Save an encrypted value. Both ``index`` and ``value`` will be non-empty
      base64 encoded strings.

   .. cpp:function:: virtual std::string kv_get(const std::string& index) const = 0

      Return a value saved with ``kv_set``, or return the empty string.

   .. cpp:function:: virtual void kv_del(const std::string& index) = 0

      Remove a value saved with ``kv_set``.

   .. cpp:function:: virtual std::set<std::string> kv_get_all() const = 0

      Return all active names (ie values for which ``kv_get`` will return a
      non-empty string).

A subclass of ``Encrypted_PSK_Database`` which stores data in a SQL database
is also available.

.. cpp:class:: Encrypted_PSK_Database_SQL : public Encrypted_PSK_Database

  .. cpp:function:: Encrypted_PSK_Database_SQL(const secure_vector<uint8_t>& master_key, \
                                 std::shared_ptr<SQL_Database> db, \
                                 const std::string& table_name)

     Creates or uses the named table in ``db``. The SQL schema of the table is
     ``(psk_name TEXT PRIMARY KEY, psk_value TEXT)``.
