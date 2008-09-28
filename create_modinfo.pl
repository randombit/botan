#!/usr/bin/perl -w

use File::Spec;

for $dir (<*>) {
    next if $dir eq "create_modinfo.pl";

    my @files = glob("$dir/*");

    my $modfile = "$dir/modinfo.txt";

    open MOD, ">$modfile" or die "Couldn't write $modfile\n ($!)";

    my $name = uc $dir;
    my $macro = uc $dir;

    print MOD "realname \"$name\"\n\n";

    print MOD "define $macro\n\n";

    print MOD "load_on auto\n\n";

    print MOD "<add>\n";

    for my $fsname (@files) {
        my (undef, undef, $file) = File::Spec->splitpath($fsname);
        print MOD "$file\n";
    }

    print MOD "</add>\n";

    close MOD;

    #print $dir, " - ", join(' ', glob("$dir/*")), "\n";
}
