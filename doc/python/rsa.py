#!/usr/bin/python

import botan

rng = botan.RandomNumberGenerator()

rsa_priv = botan.RSA_PrivateKey(768, rng)

print rsa_priv.to_string()
print int(rsa_priv.get_N())
print int(rsa_priv.get_E())


rsa_pub = botan.RSA_PublicKey(rsa_priv)

key = rng.gen_random(20)

ciphertext = rsa_pub.encrypt(key, 'EME1(SHA-1)', rng)

print ciphertext.encode('hex')

plaintext = rsa_priv.decrypt(ciphertext, 'EME1(SHA-1)')

print plaintext == key


signature = rsa_priv.sign(key, 'EMSA4(SHA-256)', rng)

print rsa_pub.verify(key, signature,  'EMSA4(SHA-256)')

# Corrupt the signature, make sure it doesn't verify
signature = signature.replace(signature[0], '0')

print rsa_pub.verify(key, signature,  'EMSA4(SHA-256)')
