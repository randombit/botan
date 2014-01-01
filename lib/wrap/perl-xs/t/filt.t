# vim: set ft=perl:
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN { $| = 1; print "1..5\n"; }
END { print "not ok 1\n" unless $loaded; }

use Botan;

$loaded = 1;
print "ok 1\n";

######################### End of black magic.

# Insert your test code below (better if it prints "ok 13"
# (correspondingly "not ok 13") depending on the success of chunk 13
# of the test code):

use strict;

my $pipe = Botan::Pipe->new(Botan::Hex_Encoder->new());

print "not " unless $pipe;
print "ok 2\n";

$pipe->process_msg('FOO');

print "not " if $pipe->read() ne '464F4F';
print "ok 3\n";

$pipe = Botan::Pipe->new(Botan::Hex_Encoder->new(0, 0, 1));

print "not " unless $pipe;
print "ok 4\n";

$pipe->process_msg('FOO');

print "not " if $pipe->read() ne '464f4f';
print "ok 5\n";






#my $pipe = Botan::Pipe->new(Botan::Base64_Encoder->new());
#$pipe->process_msg('FOO');
#
#print "not " if $pipe->read() ne 'Rk9P';
#print "ok 4\n";

