# vim: set ft=perl:
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN { $| = 1; print "1..4\n"; }
END { print "not ok 1\n" unless $loaded; }

use Botan;

$loaded = 1;
print "ok 1\n";

######################### End of black magic.

# Insert your test code below (better if it prints "ok 13"
# (correspondingly "not ok 13") depending on the success of chunk 13
# of the test code):

use strict;

my $cert = Botan::X509_Certificate->new('data/ca.cert.der');

print "not " if $cert->x509_version() != 3;
print "ok 2\n";

print "not " if $cert->start_time() ne '2000/8/20 21:48:00 UTC';
print "ok 3\n";

print "not " if $cert->end_time() ne '2002/8/10 21:48:00 UTC';
print "ok 4\n";

#my $subject = $cert->subject_dn()->get_attributes();
#print STDERR "subject=", join(',', @{$subject}), "\n";
#
#my $issuer = $cert->issuer_dn()->get_attributes();
#print STDERR "issuer=", join(',', @{$issuer}), "\n";
#
