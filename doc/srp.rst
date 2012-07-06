Secure Remote Password
========================================

The library contains an implementation of the SRP-6a password based
key exchange protocol in ``srp6.h``.

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
