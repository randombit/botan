Secure Remote Password
========================================

The library contains an implementation of the :wikipedia:`SRP-6a
password based key exchange protocol
<Secure_remote_password_protocol>` in ``srp6.h``.

A SRP client provides what is called a SRP *verifier* to the server.
This verifier is based on a password, but the password cannot be
easily derived from the verifier. Later, the client and server can
perform an SRP exchange, in which

.. warning::

     While knowledge of the verifier does not easily allow an attacker
     to get the raw password, they could still use the verifier to
     impersonate the server to the client, so verifiers should be
     carefully protected.


.. cpp:function:: BigInt generate_srp6_verifier( \
          const std::string& identifier, \
          const std::string& password, \
          const std::vector<byte>& salt, \
          const std::string& group_id, \
          const std::string& hash_id)


.. cpp:function:: std::pair<BigInt,SymmetricKey> srp6_client_agree( \
               const std::string& username, \
               const std::string& password, \
               const std::string& group_id, \
               const std::string& hash_id, \
               const std::vector<byte>& salt, \
               const BigInt& B, \
               RandomNumberGenerator& rng)

.. cpp:function:: std::string srp6_group_identifier( \
            const BigInt& N, const BigInt& g)
