#!/usr/bin/python

import sys, botan

class FindDOD(botan.X509_Store.Search_Func):
    def match(self, cert):
        return ("PythonCA" in cert.subject_info("Name"))

def main():
    cert = botan.X509_Certificate("cert.pem")

    stor = botan.X509_Store()
    stor.add_cert(botan.X509_Certificate("cert.pem"), True)
    stor.add_cert(botan.X509_Certificate("cert2.pem"))
    stor.add_cert(botan.X509_Certificate("cert.crt"))
    matcher = FindDOD()
    certs = stor.get_certs(matcher)

    for cert in certs:
        print cert.subject_info("Email")
        print cert.subject_key_id()

if __name__ == "__main__":
    sys.exit(main())
