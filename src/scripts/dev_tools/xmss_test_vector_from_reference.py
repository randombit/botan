#!/usr/bin/env python3

"""
This is a wrapper around the XMSS reference implementation CLI tools
to generate test data readable py test_xmss.cpp

Uses the XMSS reference implementation from here:
   https://github.com/XMSS/xmss-reference

(C) 2023 René Meusel (Rohde & Schwarz Cybersecurity)

Botan is released under the Simplified BSD License (see license.txt)
"""

import asyncio
import tempfile
import sys
import binascii


async def run(cmd, args):
    vc = await asyncio.create_subprocess_exec(cmd, *args,
                                              stdout=asyncio.subprocess.PIPE,
                                              stderr=asyncio.subprocess.PIPE)
    (stdout, stderr) = await vc.communicate()
    if stderr:
        raise RuntimeError(
            "Process execution failed with: " + stderr.decode("utf-8"))
    return stdout


def tohex(b):
    return binascii.hexlify(b).decode("utf-8")


def fromhex(s):
    return binascii.unhexlify(s)


KEYGEN_UTIL = "ui/xmss_keypair"
SIGN_UTIL = "ui/xmss_sign"

TEST_MESSAGES = [b'', fromhex("01020304"), fromhex("f1cceaeaae1838a11e8f9244ba16387663a38f661e160d7ded41a5d535066732b28f101412489dc73d6206ca43976dfee50faa23862b6defff6a873cad75ac069670e6203e970cada047cd10a3d3a5a2d4fb05c4d68ac3b88b7760cef22075504ab2808e175b54dff1659da07581ae7da0f287e18bcfc31bccf9ebb7ccb61a1321b3f0da52050d7220a291f94c71db4e9d315510372bb0be8362e156363ccf10903dc7b3fd6a6816e0a3c1ee2a79cbc683805aa7ff9346c977cdb7eddd1eb6c4b2686007f75a339a27ea25e5092ff01eee99a5241d43b548efdd667aa5171d5fc4089b5273840384b2ef390e56736263df23533f5f8330b53aabb68c24ddfed9aaafdd5679adcb877e5f0e7270cbcd7d3938136fa6cf038e27bdf03825a63917693d8b3e653950fc5059bda02e8c7c5f457d86ef684138028d18044c277c23fdab00491866ff354f2ec6722f56d4ce9f2ecef50b2f4f2a85c55b6eb6dc5d66b13e67b87b0071a5b2e4bc7ab92757a683867326ce18dba8ff2beb7bbbaa314e65953e861c8b10bce481f607fad0f690a9c0eb4c0155917707a02db1d22d88f2a14584f10ab13746fed752a4b7f62ebc85b34360d8ab964e280bd96e51b32ee6a589c62b63f42d7babfe6c7da6324ffb6f1dff4f6df586b1d2d34e23e3be915631bf143537268fb50ed13fff1a91856a451e91debc9fc337f666089b8e86efc410e97f1591ee0162d26fda6e6212b97886b96422b92b1220a6b6134287755ac3d12d2b96854a3e9e9cbc2477db2c3462695675ef8ab08a4968b79f6851a98b5f5056ecdb710864422cddb3d974451f66904377ab2056d6ebf7e398dcd075852537507c85a84ba14ee4c0aeb50c3bcb40f22e904eb7dbbda856b6556ab1e005e41eaf372f050c29f76f92c21647dfcbb40aad9f92201108d1ff3153163924c99cb6296f7e179779c8764627bed676e22c98b61793275da8f6f25b0122fc309c4a3f174816d90af39d0d15b457df37b8c00227655f9b3a3d2614bb9f2d1b273f67b2f92c182cd9bd64aef8038d0ccf6826083fe84135b4de6111e02909acdf175b1defcd11b24d01e50530aaa835dfdc5a6f237dbdc6ee3c3796d95306ae63b4401740b17ae5006a0bd4bf76bbe97df40a565a9483d99c0e8b17bd96dd72721da6b9d75323c262006d70ecca750caf81072151dbe43189cff3ea254d78b5fdf83530c1d937b3374fff41c3fd26c0f3124e38d9747e7213cf3daeaddf31b0ac7c72c6b04eb8ef17da3e9e93d09435ba8d707ea4c12576aa8ef23c760162645a30ec557b7688e8ede33d116ef39c9ee89865e2cbb854d35570fd92a7fc41ed95809e1a9c2d79ed79855505ac99d26c56d70b824bd098622cb5c704e70e7f281f215c3eb059edb8ce13731e")]


class Keypair:
    @staticmethod
    async def generate(xmss_param):
        for _ in range(5):
            keypair = await run(KEYGEN_UTIL, [xmss_param])
            if len(keypair) < 8:
                continue

            oid = keypair[0:4]

            # Slicing fails if the oid appears in the public key by chance.
            # This is just a simple test generation script, so we don't really
            # care about the bias this introduces.
            if keypair.count(oid) == 2:
                return Keypair(xmss_param, keypair)

        raise RuntimeError("Keypair generation failed")

    def __init__(self, xmss_params, keypair):
        self.keypair = keypair
        self.oid = self.keypair[0:4]
        self.params_name = xmss_params[5:]

        # transform the public/private keys into the format Botan expects
        sk_slice = self.keypair.find(self.oid, 4)
        self.public_key = self.keypair[:sk_slice]
        secret_portion = self.keypair[sk_slice+4:-len(self.public_key)+4]
        n = int((len(secret_portion) - 4) / 2)
        self.idx = secret_portion[0:4]
        self.secret_seed = secret_portion[4:n+4]
        self.secret_prf = secret_portion[n+4:]
        self.public_seed = self.public_key[n+4:n*2+4]
        wots_derivation_method = "\x02" # WOTS+ derivation as described in NIST SP.800-208
        self.secret_key = self.public_key + self.idx + self.secret_prf + self.secret_seed + wots_derivation_method

    async def sign(self, message):
        with tempfile.NamedTemporaryFile() as msg_file, tempfile.NamedTemporaryFile() as key_file:
            key_file.write(self.keypair)
            key_file.flush()
            msg_file.write(message)
            msg_file.flush()
            signature_and_msg = await run(SIGN_UTIL, [key_file.name, msg_file.name])
            return signature_and_msg[:-len(message)] if len(message) != 0 else signature_and_msg


async def join(strings):
    return "\n".join(await asyncio.gather(*strings))


async def make_xmss_sig_vec_entry(xmss_param):
    async def entry(msg):
        kp = await Keypair.generate(xmss_param)
        out = "Params = {}\n".format(kp.params_name)
        out += "Msg = {}\n".format(tohex(msg))
        out += "PrivateKey = {}\n".format(tohex(kp.secret_key))
        sig = await kp.sign(msg)
        out += "Signature = {}\n".format(tohex(sig))
        return out

    return await join([entry(msg) for msg in TEST_MESSAGES])


async def make_xmss_verify_vec_entry(xmss_param):
    async def entry(msg):
        kp = await Keypair.generate(xmss_param)
        out = "Params = {}\n".format(kp.params_name)
        out += "Msg = {}\n".format(tohex(msg))
        out += "PublicKey = {}\n".format(tohex(kp.public_key))
        sig = await kp.sign(msg)
        out += "Signature = {}\n".format(tohex(sig))
        return out

    return await join([entry(msg) for msg in TEST_MESSAGES])


async def make_xmss_keygen_vec_entry(xmss_param):
    kp = await Keypair.generate(xmss_param)
    out = "Params = {}\n".format(xmss_param)
    out += "SecretSeed = {}\n".format(tohex(kp.secret_seed))
    out += "PublicSeed = {}\n".format(tohex(kp.public_seed))
    out += "SecretPrf = {}\n".format(tohex(kp.secret_prf))
    out += "PublicKey = {}\n".format(tohex(kp.public_key))
    out += "PrivateKey = {}\n".format(tohex(kp.secret_key))
    return out


if len(sys.argv) < 3:
    print("Usage: {} <test vector: 'sig', 'verify', 'keygen'> <XMSS Parameter Set Name(s)>".format(
        sys.argv[0]))
    sys.exit(1)

funs = {
    "sig": make_xmss_sig_vec_entry,
    "verify": make_xmss_verify_vec_entry,
    "keygen": make_xmss_keygen_vec_entry
}

tv = sys.argv[1]
if tv not in funs:
    print("Unknown test vector: %s" % tv)
    sys.exit(1)


async def main():
    print(await join([funs[tv](p) for p in sys.argv[2:]]))

asyncio.run(main())
