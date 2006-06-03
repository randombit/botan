
sub print_pkg_config
{
    my ($os, $major,$minor,$patch,@libs) = @_;

    return if($os eq 'generic' or $os eq 'windows');

    my $install_root = os_install_info($os, 'root');
    my $header_dir   = os_install_info($os, 'headers');
    my $lib_dir      = os_install_info($os, 'libs');

   if($user_set_root ne '') { $install_root = $user_set_root; }

    my $link_to = "-lm";
    foreach my $lib (@libs)
    {
        $link_to .= " -l" . $lib;
    }

    my $VERSION = $major . "." . $minor . "." . $patch;

    open PKGCONFIG, ">botan-config" or
        die "Couldn't write to botan-config ($!)";

    print PKGCONFIG <<END_OF_FILE;
#!/bin/sh

guess_prefix=\`dirname \\\`dirname \$0\\\`\`
install_prefix=$install_root
prefix=
includedir=$header_dir
libdir=$lib_dir

usage()
{
    echo "botan-config [--prefix[=DIR]] [--version] [--libs] [--cflags]"
    exit 1
}

if test \$# -eq 0; then
    usage
fi

if test \`echo \$guess_prefix | cut -c 1\` = "/"; then
   prefix=\$guess_prefix
else
   prefix=\$install_prefix
fi

while test \$# -gt 0; do
    case "\$1" in
    -*=*) optarg=`echo "\$1" | sed 's/[-_a-zA-Z0-9]*=//'` ;;
    *) optarg= ;;
    esac
    case "\$1" in
    --prefix=*)
        prefix=\$optarg
        ;;
    --prefix)
        echo \$prefix
        ;;
    --version)
        echo $VERSION
        exit 0
        ;;
    --cflags)
        if [ \$prefix != "/usr" -a \$prefix != "/usr/local" ]
        then
           echo -I\$prefix/\$includedir
        fi
        ;;
    --libs)
        echo -L\$prefix/\$libdir $link_to -lbotan
        ;;
    *)
        usage
        ;;
    esac
    shift
done

exit 0
END_OF_FILE

    close PKGCONFIG;
    chmod 0755, 'botan-config';
}
