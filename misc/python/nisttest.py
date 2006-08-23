#!/usr/bin/python

import sys, os, botan
from os.path import join;

def validate(ca_certs, certs, crls, ee_certs):
    store = botan.X509_Store()
    for cert in certs:
        if cert not in ee_certs:
            store.add_cert(botan.X509_Certificate(cert), cert in ca_certs)

    for crl in crls:
        r = store.add_crl(botan.X509_CRL(crl))
        if r != botan.verify_result.verified:
            return r

    for ee in ee_certs:
        r = store.validate(botan.X509_Certificate(ee))
        if r != botan.verify_result.verified:
            return r

    return botan.verify_result.verified

def run_test(files, rootdir, testname, expected):
    crls = [join(rootdir,x) for x in files if x.endswith(".crl")]
    certs = [join(rootdir,x) for x in files if x.endswith(".crt")]
    end_entity = [x for x in certs if x.find("End Cert") != -1]
    ca_certs = [x for x in certs if x.find("Trust Anchor") != -1]

    print "Running", testname, "...",

    result = validate(ca_certs, certs, crls, end_entity)
    result = repr(result).replace('botan._botan.verify_result.', '')
    
    if result != expected:
        print "FAILED: got", result, "expected", expected
    else:
        print "passed"

def main():
    def load_results(file):
        results = {}
        for line in open(file, 'r'):
            line = line[0:line.find('#')].strip()
            if line:
                test,result = line.split(' ')
                results[test] = result
        return results

    results = load_results('results.txt')

    for root, dirs, files in os.walk('../nist_tests/tests'):
        if files:
            thistest = root[root.rfind('/')+1:]
            if thistest in results:
                run_test(files, root, thistest, results[thistest])
            else:
                print "Skipping", thistest, "- no expected result set"
        
if __name__ == "__main__":
    sys.exit(main())
