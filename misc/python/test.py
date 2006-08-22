#!/usr/bin/python

import sys, botan

def do_hash(input):
    pipe = botan.Pipe(botan.Filter("MD5"), botan.Filter("Hex_Encoder"))

    print pipe
    pipe.start_msg()
    pipe.write(input)
    pipe.end_msg()

    return pipe.read_all()

def main():
    cert = botan.X509_Certificate("cert.pem")
    print cert.self_signed
    print cert.is_CA
    print cert.version
    print cert.pathlimit
    print cert.start_time()
    print cert.end_time()
    print cert.subject_info("Name")
    print cert.subject_info("X520.OrganizationalUnit")
    print cert.issuer_info("Name")
    print cert.issuer_info("X520.OrganizationalUnit")
    print cert.policies()
    print cert.ex_constraints()
    print cert.subject_key_id()

    cert2 = botan.X509_Certificate("cert.crt")
    cert3 = botan.X509_Certificate("cert.pem")
    cert4 = botan.X509_Certificate("cert2.crt")
    print cert2 == cert4

if __name__ == "__main__":
    sys.exit(main())
