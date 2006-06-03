
sub os_info_for {
    my ($os,$hashref) = @_;

    my %hash = %{ $hashref };

    die "Internal error: os_info_for called with undef hash\n"
        unless %hash;

    die "Internal error: os_info_for called with an os of defaults\n"
        if($os eq 'defaults');

    return $hash{$os} if(defined($hash{$os}) && $hash{$os} ne '');
    return $hash{'defaults'};
}

sub os_static_suffix {
    my $os = $_[0];
    return os_info_for($os, \%OS_STATIC_SUFFIX);
}

sub os_shared_suffix {
    my $os = $_[0];
    return os_info_for($os, \%OS_SHARED_SUFFIX);
}

sub os_obj_suffix {
    my $os = $_[0];
    return os_info_for($os, \%OS_OBJ_SUFFIX);
}

sub os_ar_command {
    my $os = $_[0];
    return os_info_for($os, \%OS_AR_COMMAND);
}

sub os_ar_needs_ranlib {
    my $os = $_[0];
    return os_info_for($os, \%OS_AR_NEEDS_RANLIB);
}

sub os_install_info {
    my ($os,$what) = @_;

    return $doc_dir if($what eq 'docs' && $doc_dir);
    return $lib_dir if($what eq 'libs' && $lib_dir);

    return $INSTALL_INFO{$os}{$what}
       if(defined($INSTALL_INFO{$os}) &&
          defined($INSTALL_INFO{$os}{$what}));

    return $INSTALL_INFO{'defaults'}{$what};
}
