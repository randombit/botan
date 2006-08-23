#!/usr/bin/python

import sys, re, os, botan
from os.path import join;

class TestResult(Exception):
    def __init__(self, r):
        self.result = r
    def __str__(self):
        return repr(self.result).replace('botan._botan.verify_result.', '')

def throw_unless_ok(r):
    if r != botan.verify_result.verified:
        raise TestResult(r)

def validate(ca_certs, certs, crls, ee_certs):
    store = botan.X509_Store()

    for cert in certs:
        if cert not in ee_certs:
            store.add_cert(botan.X509_Certificate(cert), cert in ca_certs)

    for crl in crls:
        throw_unless_ok(store.add_crl(botan.X509_CRL(crl)))

    for ee in ee_certs:
        throw_unless_ok(store.validate(botan.X509_Certificate(ee)))

    raise TestResult(botan.verify_result.verified)

def main():
    for root, dirs, files in os.walk('../nist_tests/tests'):
        if files:
            crls = [join(root,x) for x in files if x.endswith(".crl")]
            certs = [join(root,x) for x in files if x.endswith(".crt")]
            end_entity = [x for x in certs if x.find("End Cert") != -1]
            ca_certs = [x for x in certs if x.find("Trust Anchor") != -1]

            try:
                validate(ca_certs, certs, crls, end_entity)
            except TestResult, result:
                print result
        
if __name__ == "__main__":
    sys.exit(main())
