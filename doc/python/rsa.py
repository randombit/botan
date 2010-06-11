#!/usr/bin/python

import botan

def make_into_c_array(ber):
    output = 'static unsigned char key_data[%d] = {\n\t' % (len(ber))

    for (idx,c) in zip(range(len(ber)), ber):
        if idx != 0 and idx % 8 == 0:
            output += "\n\t"
        output += "0x%s, " % (c.encode('hex'))

    output += "\n};\n"

    return output

rng = botan.RandomNumberGenerator()

rsa_priv = botan.RSA_PrivateKey(768, rng)

print rsa_priv.to_string()
print int(rsa_priv.get_N())
print int(rsa_priv.get_E())

rsa_pub = botan.RSA_PublicKey(rsa_priv)

print make_into_c_array(rsa_pub.to_ber())
#print make_into_c_array(rsa_priv.to_ber())

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
