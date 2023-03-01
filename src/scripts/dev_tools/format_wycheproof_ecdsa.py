#!/usr/bin/env python3

"""
(C) 2023 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)
"""

import sys
import json
import re

def map_group_name(group):
    if group.startswith('brainpoolP'):
        return group.replace('P', '')

    return group

def main(args = None):
    if args is None:
        args = sys.argv

    brainpool_t = re.compile('brainpoolP[0-9]+t1')

    last_group = None
    last_msg = None

    for file in args[1:]:
        if file.find('p1363') > 0:
            continue

        if file.find('webcrypto') > 0:
            continue

        data = json.loads(open(file).read())
        assert(data['algorithm'] == 'ECDSA')

        for group in data['testGroups']:
            if brainpool_t.match(group['key']['curve']):
                continue

            if last_group != group['key']['curve']:
                print("Group =", map_group_name(group['key']['curve']))
                last_group = group['key']['curve']
            print("Hash =", group['sha'])
            print()

            print("Px = 0x%s" % (group['key']['wx']))
            print("Py = 0x%s" % (group['key']['wy']))

            for test in group['tests']:
                print("\n# Test %d (%s)" % (test['tcId'], test['comment']))

                if last_msg != test['msg']:
                    print("Msg =", test['msg'])
                    last_msg = test['msg']
                print("Signature =", test['sig'])

                accept = test['result'][0].upper() == 'V'

                # We force this to V since all other "Acceptable" signatures
                # in the test set are ones we do want to reject, eg due to
                # invalid DER encodings
                if(test['comment'] == 'Hash weaker than DL-group'):
                    accept = True
                print("Valid =", 1 if accept else 0)

            print()

if __name__ == '__main__':
    sys.exit(main())
