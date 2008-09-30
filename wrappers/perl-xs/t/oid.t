# vim: set ft=perl:
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN { $| = 1; print "1..6\n"; }
END { print "not ok 1\n" unless $loaded; }

use Botan;

$loaded = 1;
print "ok 1\n";

######################### End of black magic.

# Insert your test code below (better if it prints "ok 13"
# (correspondingly "not ok 13") depending on the success of chunk 13
# of the test code):

use strict;

print "not " unless Botan::OIDS::have_oid('X520.CommonName');
print "ok 2\n";

my $oid_c = Botan::OID->new('2.5.4.3');
print "not " if Botan::OIDS::lookup_by_oid($oid_c) ne 'X520.CommonName';
print "ok 3\n";

my $oid_x = Botan::OIDS::lookup_by_name('X520.CommonName');
print "not " if $oid_x->as_string() ne '2.5.4.3';
print "ok 4\n";

my $oid_foo_num = '1.2.3.4.5.6.7.8.9.10.11.12.13.14.15';
my $oid_foo = Botan::OID->new($oid_foo_num);
print "not " if Botan::OIDS::lookup_by_oid($oid_foo) ne $oid_foo_num;
print "ok 5\n";

Botan::OIDS::add_oid($oid_foo, 'Zito.Foo');

print "not " if Botan::OIDS::lookup_by_oid($oid_foo) ne 'Zito.Foo';
print "ok 6\n";
