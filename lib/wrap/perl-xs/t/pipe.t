# vim: set ft=perl:
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN { $| = 1; print "1..20\n"; }
END { print "not ok 1\n" unless $loaded; }

use Botan;

$loaded = 1;
print "ok 1\n";

######################### End of black magic.

# Insert your test code below (better if it prints "ok 13"
# (correspondingly "not ok 13") depending on the success of chunk 13
# of the test code):

use strict;

my $pipe = Botan::Pipe->new();

print "not " unless $pipe;
print "ok 2\n";

$pipe->start_msg();
$pipe->write('Hello world');
$pipe->end_msg();

print "not " if $pipe->message_count() != 1;
print "ok 3\n";

print "not " if $pipe->remaining() != 11;
print "ok 4\n";

print "not " if $pipe->end_of_data();
print "ok 5\n";

print "not " if $pipe->read() ne 'Hello world';
print "ok 6\n";

print "not " if $pipe->remaining() != 0;
print "ok 7\n";

print "not " unless $pipe->end_of_data();
print "ok 8\n";

$pipe->process_msg('Hello world');

print "not " if $pipe->message_count() != 2;
print "ok 9\n";

my $msg_num = $pipe->message_count() -1;

print "not " if $pipe->read(5, $msg_num) ne 'Hello';
print "ok 10\n";

print "not " if $pipe->read(6, $msg_num) ne ' world';
print "ok 11\n";

print "not " if $pipe->remaining() != 0;
print "ok 12\n";

print "not " unless $pipe->end_of_data();
print "ok 13\n";

$pipe->process_msg("The\0string\0with\0null\0chars\0");
$msg_num = $pipe->message_count() -1;

print "not " if $pipe->read(80, $msg_num) ne "The\0string\0with\0null\0chars\0";
print "ok 14\n";

$pipe->process_msg('FOO BAR');
$pipe->set_default_msg($pipe->message_count() -1);

print "not " if $pipe->peek(3) ne 'FOO';
print "ok 15\n";

print "not " if $pipe->peek(3, 4) ne 'BAR';
print "ok 16\n";

print "not " if $pipe->peek() ne 'FOO BAR';
print "ok 17\n";

print "not " if $pipe->read() ne 'FOO BAR';
print "ok 18\n";

print "not " if $pipe->remaining() != 0;
print "ok 19\n";

print "not " unless $pipe->end_of_data();
print "ok 20\n";

