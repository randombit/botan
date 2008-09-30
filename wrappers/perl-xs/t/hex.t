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

my ($hex, $hex_ws, $hex_garbage);
while ( $_ = <DATA> )
{
    $hex_garbage .= $_;
    s/[^[:xdigit:][:space:]]//g;
    $hex_ws .= $_;
    s/[^[:xdigit:]]//g;
    $hex .= $_;
}
my $data_test = pack("H*", $hex);

# Decoder...

my $f;

eval { $f = Botan::Hex_Decoder->new(&Botan::NONE); };
print "not " if $@ || !defined $f;
print "ok 2\n";

my $dec;
eval { $dec = Botan::Pipe->new($f); };
print "not " if $@ || !defined $dec;
print "ok 3\n";

eval { $f = Botan::Hex_Decoder->new(&Botan::IGNORE_WS); };
print "not " if $@ || !defined $f;
print "ok 4\n";

my $dec_is;
eval { $dec_is = Botan::Pipe->new($f); };
print "not " if $@ || !defined $dec_is;
print "ok 5\n";

eval { $f = Botan::Hex_Decoder->new(&Botan::FULL_CHECK); };
print "not " if $@ || !defined $f;
print "ok 6\n";

my $dec_fc;
eval { $dec_fc = Botan::Pipe->new($f); };
print "not " if $@ || !defined $dec_fc;
print "ok 7\n";


# Testing clean hexadecimal input

my $data;

undef $data;
eval {
    $dec->process_msg($hex);
    $data = $dec->read();
};

print "not " if $@ || $data ne $data_test;
print "ok 8\n";

undef $data;
eval {
    $dec_is->process_msg($hex);
    $data = $dec_is->read();
};

print "not " if $@ || $data ne $data_test;
print "ok 9\n";

undef $data;
eval {
    $dec_fc->process_msg($hex);
    $data = $dec_fc->read();
};

print "not " if $@ || $data ne $data_test;
print "ok 10\n";


# Testing hexadecimal input with whitespaces

undef $data;
eval {
    $dec->process_msg($hex_ws);
    $dec->set_default_msg(1);
    $data = $dec->read();
};

print "not " if $@ || $data ne $data_test;
print "ok 11\n";

undef $data;
eval {
    $dec_is->process_msg($hex_ws);
    $dec_is->set_default_msg(1);
    $data = $dec_is->read();
};

print "not " if $@ || $data ne $data_test;
print "ok 12\n";

undef $data;
eval {
    $dec_fc->process_msg($hex_ws);
    $dec_fc->set_default_msg(1);
    $data = $dec_fc->read();
};

print "not " unless $@ && !defined $data;
print "ok 13\n";


# Testing hexadecimal input with garbage

undef $data;
eval {
    $dec->process_msg($hex_garbage);
    $dec->set_default_msg(2);
    $data = $dec->read();
};

print "not " if $@ || $data ne $data_test;
print "ok 14\n";

undef $data;
eval {
    $dec_is->process_msg($hex_garbage);
    $dec_is->set_default_msg(2);
    $data = $dec_is->read();
};

print "not " unless $@ && !defined $data;
print "ok 15\n";

undef $data;
eval {
    $dec_fc->process_msg($hex_garbage);
    $dec_fc->set_default_msg(2);
    $data = $dec_fc->read();
};

print "not " unless $@ && !defined $data;
print "ok 16\n";


# Encoder...

eval { $f = Botan::Hex_Encoder->new(); };
print "not " if $@ || !defined $f;
print "ok 17\n";

my $enc;
eval { $enc = Botan::Pipe->new($f); };
print "not " if $@ || !defined $enc;
print "ok 18\n";

eval { $f = Botan::Hex_Encoder->new(1, 5, 1); };
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
print "not " if $@ || $data ne "48656C6C6F0A";
print "ok 21\n";

undef $data;
eval {
    $enc2->process_msg("Hello\n");
    $data = $enc2->read();
};
print "not " if $@ || $data ne "48656\nc6c6f\n0a\n";
print "ok 22\n";


# Encoder with decoder...

my $p;
eval {
    $p = Botan::Pipe->new(
	    Botan::Hex_Encoder->new(),
	    Botan::Hex_Decoder->new(),
	);
};
print "not " if $@ || !defined $p;
print "ok 23\n";

print "not " unless random_message_ok($p);
print "ok 24\n";



__DATA__
cb13 4a4d 7522 1fd3 c6f6 7786 d04b 3043  ..JMu"....w..K..
4552 4bcf 4d2b 9d71 0cfe 4d6a 1caf bcfd  .RK.M+.q..Mj....
8f91 6151 ff85 e900 7e6a bafc 15e9 ae51  ...Q....~j.....Q
b14b 7210 bb40 5958 2b82 d49e b808 68a5  .Kr..@YX+.....h.
7945 9dec f686 9b98 989e 826d 8088 6ee7  y..........m..n.
d066 1eac 8c34 c461 bb54 7726 87ab d681  .........Tw&....
a0be 52e5 1128 0cf2 759e cb2d e690 4ed9  ..R..(..u..-..N.
7e88 bda7 2523 4a0f 185a 02b1 f898 fc41  ~...%#J..Z......
dd48 fa87 945d 7611 b8c9 a50a 2de2 b670  .H...]v.....-..p
0056 c8be 2cbb e7d0 1e70 4a3d 79f0 dce9  .V..,....pJ=y...
b57f 154b 2b3a db73 f086 de11 9f3e 1641  ...K+:.s.....>..
3a28 8b9b bb0f 682b 80db b791 89e0 62c0  :(....h+........
7204 db97 5432 2eb0 a04e f38e 809f 7223  r...T....N....r#
912e e552 1452 6dd2 e09f dd06 c715 7c1a  ...R.Rm.......|.
fe3d d6cc b6d0 a17a 27d7 4327 4e43 8af3  .=.....z'..'N...
6eb5 e9f8 bfe9 34c3 6636 8243 358f 966d  n..............m
7d87 d17b 5c37 6acb 4972 f4ec 6806 bbde  }..{\.j.Ir..h...
2689 a019 a9e2 4101 7fe2 de72 bc03 eb5e  &..........r...^
b699 2d6b f8cd a08e 6e01 edfc a81a 94b6  ..-k....n.......
9073 15fb efb2 c8d9 9f85 6633 85f1 e9d0  .s..............
20ce 578b ab9d 2e51 b947 69bf fba5 82c6   .W....Q.Gi.....
2ed0 dd36 d679 a399 7db3 8a0d cdef 0eda  .....y..}.......
e761 e7f1 5b17 3f67 0c83 215a eddf 9d2a  ....[.?g..!Z...*
5e70 0a77 c92e 94e1 a82b fd7c f10a 894f  ^p.w.....+.|...O
2955 f0e8 7398 f409 2040 b797 da03 a5a6  )U..s... @......
7ba4 c3c9 2659 b9f7 6a56 e17a b481 983f  {...&Y..jV.z...?
00ed 3cc8 5a22 ad5c b6e0 3566 d717 35a6  ..<.Z".\........
1523 4104 de63 477e fd24 68e5 e816 98df  .#....G~.$h.....
1747 417e db72 a76a be5b b9dc 3dfb 2d05  .G.~.r.j.[..=.-.
d27f e597 eafc 9a29 15c5 792d 9c88 9aea  .......)..y-....
485e e431 96c3 7723 da6d 28b2 477a fd12  H^....w#.m(.Gz..
e645 5dcd 7d5a d8b4 7acc 10b2 b41a e11d  ..].}Z..z.......
