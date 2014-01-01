# vim: set ft=perl:
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN { $| = 1; print "1..24\n"; }
END { print "not ok 1\n" unless $loaded; }

require 't/testutl.pl';
use Botan;

$loaded = 1;
print "ok 1\n";

######################### End of black magic.

# Insert your test code below (better if it prints "ok 13"
# (correspondingly "not ok 13") depending on the success of chunk 13
# of the test code):

use strict;

# Data prep

my $botan_lic_b64_garbage = <<'EOF';
Q29weXJpZ2h0IChDKSAxOTk5LTIwMDQgVGhlIEJvdGFuIFByb2plY3QuIEFsbCBy__ì¹
aWdodHMgcmVzZXJ2ZWQuCgpSZWRpc3RyaWJ1dGlvbiBhbmQgdXNlIGluIHNvdXJj$$*:
ZSBhbmQgYmluYXJ5IGZvcm1zLCBmb3IgYW55IHVzZSwgd2l0aCBvciB3aXRob3V0!@#$%^&*(
Cm1vZGlmaWNhdGlvbiwgaXMgcGVybWl0dGVkIHByb3ZpZGVkIHRoYXQgdGhlIGZv[\]
bGxvd2luZyBjb25kaXRpb25zIGFyZSBtZXQ6CgoxLiBSZWRpc3RyaWJ1dGlvbnMg'~`
b2Ygc291cmNlIGNvZGUgbXVzdCByZXRhaW4gdGhlIGFib3ZlIGNvcHlyaWdodCBu()
b3RpY2UsIHRoaXMKbGlzdCBvZiBjb25kaXRpb25zLCBhbmQgdGhlIGZvbGxvd2lu
ZyBkaXNjbGFpbWVyLgoKMi4gUmVkaXN0cmlidXRpb25zIGluIGJpbmFyeSBmb3Jt
IG11c3QgcmVwcm9kdWNlIHRoZSBhYm92ZSBjb3B5cmlnaHQgbm90aWNlLAp0aGlz
IGxpc3Qgb2YgY29uZGl0aW9ucywgYW5kIHRoZSBmb2xsb3dpbmcgZGlzY2xhaW1l
ciBpbiB0aGUgZG9jdW1lbnRhdGlvbgphbmQvb3Igb3RoZXIgbWF0ZXJpYWxzIHBy_,^
b3ZpZGVkIHdpdGggdGhlIGRpc3RyaWJ1dGlvbi4KClRISVMgU09GVFdBUkUgSVMg{|}~~~~~
UFJPVklERUQgQlkgVEhFIEFVVEhPUihTKSAiQVMgSVMiIEFORCBBTlkgRVhQUkVT~~~~~~~~
UyBPUiBJTVBMSUVECldBUlJBTlRJRVMsIElOQ0xVRElORywgQlVUIE5PVCBMSU1J__:;
VEVEIFRPLCBUSEUgSU1QTElFRCBXQVJSQU5USUVTIE9GCk1FUkNIQU5UQUJJTElU
WSBBTkQgRklUTkVTUyBGT1IgQSBQQVJUSUNVTEFSIFBVUlBPU0UsIEFSRSBESVND
TEFJTUVELgoKSU4gTk8gRVZFTlQgU0hBTEwgVEhFIEFVVEhPUihTKSBPUiBDT05U
UklCVVRPUihTKSBCRSBMSUFCTEUgRk9SIEFOWSBESVJFQ1QsCklORElSRUNULCBJ
TkNJREVOVEFMLCBTUEVDSUFMLCBFWEVNUExBUlksIE9SIENPTlNFUVVFTlRJQUwg
REFNQUdFUyAoSU5DTFVESU5HLApCVVQgTk9UIExJTUlURUQgVE8sIFBST0NVUkVN
RU5UIE9GIFNVQlNUSVRVVEUgR09PRFMgT1IgU0VSVklDRVM7IExPU1MgT0YgVVNF
LApEQVRBLCBPUiBQUk9GSVRTOyBPUiBCVVNJTkVTUyBJTlRFUlJVUFRJT04pIEhP
V0VWRVIgQ0FVU0VEIEFORCBPTiBBTlkgVEhFT1JZIE9GCkxJQUJJTElUWSwgV0hF
VEhFUiBJTiBDT05UUkFDVCwgU1RSSUNUIExJQUJJTElUWSwgT1IgVE9SVCAoSU5D
TFVESU5HIE5FR0xJR0VOQ0UKT1IgT1RIRVJXSVNFKSBBUklTSU5HIElOIEFOWSBX
QVkgT1VUIE9GIFRIRSBVU0UgT0YgVEhJUyBTT0ZUV0FSRSwgRVZFTiBJRgpBRFZJ
U0VEIE9GIFRIRSBQT1NTSUJJTElUWSBPRiBTVUNIIERBTUFHRS4K
EOF

my $botan_lic_b64_ws = $botan_lic_b64_garbage;
$botan_lic_b64_ws =~ s/[^A-Za-z0-9+\/= \n]//g;

my $botan_lic_b64 = $botan_lic_b64_ws;
$botan_lic_b64 =~ s/[ \n]//g;


my $botan_lic = <<'EOF';
Copyright (C) 1999-2004 The Botan Project. All rights reserved.

Redistribution and use in source and binary forms, for any use, with or without
modification, is permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions, and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions, and the following disclaimer in the documentation
and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) "AS IS" AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ARE DISCLAIMED.

IN NO EVENT SHALL THE AUTHOR(S) OR CONTRIBUTOR(S) BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
EOF


# Decoder...

my $f;

eval { $f = Botan::Base64_Decoder->new(&Botan::NONE); };
print "not " if $@ || !defined $f;
print "ok 2\n";

my $dec;
eval { $dec = Botan::Pipe->new($f); };
print "not " if $@ || !defined $dec;
print "ok 3\n";

eval { $f = Botan::Base64_Decoder->new(&Botan::IGNORE_WS); };
print "not " if $@ || !defined $f;
print "ok 4\n";

my $dec_is;
eval { $dec_is = Botan::Pipe->new($f); };
print "not " if $@ || !defined $dec_is;
print "ok 5\n";

eval { $f = Botan::Base64_Decoder->new(&Botan::FULL_CHECK); };
print "not " if $@ || !defined $f;
print "ok 6\n";

my $dec_fc;
eval { $dec_fc = Botan::Pipe->new($f); };
print "not " if $@ || !defined $dec_fc;
print "ok 7\n";


# Testing clean base64 input

my $data;

undef $data;
eval {
    $dec->process_msg($botan_lic_b64);
    $data = $dec->read();
};

print "not " if $@ || $data ne $botan_lic;
print "ok 8\n";

undef $data;
eval {
    $dec_is->process_msg($botan_lic_b64);
    $data = $dec_is->read();
};

print "not " if $@ || $data ne $botan_lic;
print "ok 9\n";

undef $data;
eval {
    $dec_fc->process_msg($botan_lic_b64);
    $data = $dec_fc->read();
};

print "not " if $@ || $data ne $botan_lic;
print "ok 10\n";


# Testing base64 input with whitespaces

undef $data;
eval {
    $dec->process_msg($botan_lic_b64_ws);
    $dec->set_default_msg(1);
    $data = $dec->read();
};

print "not " if $@ || $data ne $botan_lic;
print "ok 11\n";

undef $data;
eval {
    $dec_is->process_msg($botan_lic_b64_ws);
    $dec_is->set_default_msg(1);
    $data = $dec_is->read();
};

print "not " if $@ || $data ne $botan_lic;
print "ok 12\n";

undef $data;
eval {
    $dec_fc->process_msg($botan_lic_b64_ws);
    $dec_fc->set_default_msg(1);
    $data = $dec_fc->read();
};

print "not " unless $@ && !defined $data;
print "ok 13\n";


# Testing base64 input with garbage

undef $data;
eval {
    $dec->process_msg($botan_lic_b64_garbage);
    $dec->set_default_msg(2);
    $data = $dec->read();
};

print "not " if $@ || $data ne $botan_lic;
print "ok 14\n";

undef $data;
eval {
    $dec_is->process_msg($botan_lic_b64_garbage);
    $dec_is->set_default_msg(2);
    $data = $dec_is->read();
};

print "not " unless $@ && !defined $data;
print "ok 15\n";

undef $data;
eval {
    $dec_fc->process_msg($botan_lic_b64_garbage);
    $dec_fc->set_default_msg(2);
    $data = $dec_fc->read();
};

print "not " unless $@ && !defined $data;
print "ok 16\n";


# Encoder...

eval { $f = Botan::Base64_Encoder->new(); };
print "not " if $@ || !defined $f;
print "ok 17\n";

my $enc;
eval { $enc = Botan::Pipe->new($f); };
print "not " if $@ || !defined $enc;
print "ok 18\n";

eval { $f = Botan::Base64_Encoder->new(1, 5); };
print "not " if $@ || !defined $f;
print "ok 19\n";

my $enc2;
eval { $enc2 = Botan::Pipe->new($f); };
print "not " if $@ || !defined $enc2;
print "ok 20\n";

undef $data;
eval {
    $enc->process_msg("Hello\n");
    $data = $enc->read();
};
print "not " if $@ || $data ne "SGVsbG8K";
print "ok 21\n";

undef $data;
eval {
    $enc2->process_msg("Hello\n");
    $data = $enc2->read();
};
print "not " if $@ || $data ne "SGVsb\nG8K\n";
print "ok 22\n";


# Encoder with decoder...

my $p;
eval {
    $p = Botan::Pipe->new(
	    Botan::Base64_Encoder->new(),
	    Botan::Base64_Decoder->new(),
	);
};
print "not " if $@ || !defined $p;
print "ok 23\n";

print "not " unless random_message_ok($p);
print "ok 24\n";
