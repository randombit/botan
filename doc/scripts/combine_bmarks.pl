#!/usr/bin/perl -w

use strict;

my %results;
my %pk;

my %pk_algos;
my %algos;

my %filename_to_desc;

for my $filename (@ARGV) {

    open IN, "<$filename" or die "Couldn't read $filename ($!)\n";

    my $desc = <IN>;
    chomp $desc;

    $results{$desc} = {};

    while(<IN>) {
        if(/(.*): +(.*) Mbytes\/sec/) {
            $results{$desc}{$1} = $2;
            $algos{$1} = undef;
        }
        if(/(.*): (.*) ops \/ second \((.*)\)/) {
            my $alg = "$1";
            $alg = "$alg $3" if defined($3);
            $pk{$desc}{$alg} = $2;
            $pk_algos{$alg} = undef;
        }
    }
}


sub print_table {
    my @columns = sort keys %results;

    print "\n<P>All results are in MiB / second:\n";
    print "<TABLE BORDER CELLSPACING=1>\n<THEAD>\n";

    my %col_index = ();

    my $line = "<TR><TH>Algorithm              ";

    foreach my $col (@columns) {
        $col_index{$col} = length($line);
        $line .= "<TH>" . $col . "   ";
    }

    $line .= "\n<TBODY>\n";

    print $line;

    $line = '';

    foreach my $algo (sort keys %algos) {
        $line = "   <TR><TH>$algo   ";

        for my $col (@columns) {
            my $result = $results{$col}{$algo};
            $result = "-" if not defined($result);

            $result = "<TH>$result";

            $line .= ' ' while(length($line) < ($col_index{$col}));
            $line .= $result;

        }

        print $line, "\n";
        $line = '';
    }

    print "</TABLE>\n";
}


sub print_pk_table {
    my @columns = sort keys %pk;

    print "\n<P>All results are in operations per second:\n";
    print "<TABLE BORDER CELLSPACING=1>\n<THEAD>\n";

    my %col_index = ();

    my $line = "<TR><TH>Algorithm                        ";

    foreach my $col (@columns) {
        $col_index{$col} = length($line);
        $line .= "<TH>" . $col . "   ";
    }

    $line .= "\n<TBODY>\n";

    print $line;

    foreach my $algo (sort keys %pk_algos) {
        my $line = "   <TR><TH>$algo   ";

        for my $col (@columns) {
            my $result = $pk{$col}{$algo};
            $result = '-' if not defined($result);

            $result = "<TH>$result";

            $line .= ' ' while(length($line) < ($col_index{$col}));
            $line .= $result;

        }

        print $line, "\n";
    }

    print "</TABLE>\n";
}

print_table();
print_pk_table();
