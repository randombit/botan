##################################################
# Generate compiler options and print makefile   #
##################################################
sub generate_makefile {
   my($make_style, $cc, $os, $submodel, $arch,
      $debug, $no_shared, $dumb_gcc,
      $lib_src, $check_src, $all_includes,
      $added_src, @libs_used) = @_;

   my %all_lib_srcs = (%{ $lib_src }, %{ $added_src });

   ##################################################
   # Set language options                           #
   ##################################################
   my $lang_flags = $CC_LANG_FLAGS{$cc};
   $lang_flags = "$lang_flags -fpermissive" if($dumb_gcc);

   ##################################################
   # Set basic optimization options                 #
   ##################################################
   my $lib_opt_flags = $CC_LIB_OPT_FLAGS{$cc};
   if(!$debug and ($CC_NO_DEBUG_FLAGS{$cc}))
      { $lib_opt_flags .= ' '.$CC_NO_DEBUG_FLAGS{$cc}; }
   if($debug and ($CC_DEBUG_FLAGS{$cc}))
      { $lib_opt_flags .= ' '.$CC_DEBUG_FLAGS{$cc}; }

   ##################################################
   # Set machine dependent optimization options     #
   ##################################################
   my $mach_opt_flags = '';
   if(defined($CC_MACHINE_OPT_FLAGS{$cc}{$submodel}))
      { $mach_opt_flags = $CC_MACHINE_OPT_FLAGS{$cc}{$submodel}; }
   elsif(defined($CC_MACHINE_OPT_FLAGS{$cc}{$arch})) {
      $mach_opt_flags = $CC_MACHINE_OPT_FLAGS{$cc}{$arch};
      my $processed_modelname = $submodel;
      if(defined($CC_MACHINE_OPT_FLAGS_RE{$cc}{$arch}))
         { $processed_modelname =~
              s/$CC_MACHINE_OPT_FLAGS_RE{$cc}{$arch}//; }
      $mach_opt_flags =~ s/SUBMODEL/$processed_modelname/g;
   }

   ##################################################
   # Figure out static library creation method      #
   ##################################################
   # This is a default that works on most Unix and Unix-like systems
   my $ar_command = "ar crs";
   my $ar_needs_ranlib = 0; # almost no systems need it anymore

   # See if there are any over-riding methods. We presume if CC is creating
   # the static libs, it knows how to create the index itself.
   if($CC_AR_COMMAND{$cc}) { $ar_command = $CC_AR_COMMAND{$cc}; }
   elsif(os_ar_command($os))
   {
       $ar_command = os_ar_command($os);
       $ar_needs_ranlib = 1 if(os_ar_needs_ranlib($os));
   }

   ##################################################
   # Set shared object options                      #
   ##################################################
   my $so_link_flags = '';
   my $so_obj_flags = $CC_SO_OBJ_FLAGS{$cc};

   if($no_shared or (!in_array($OS_SUPPORTS_SHARED{$os}, 'all') and
                     !in_array($OS_SUPPORTS_SHARED{$os}, $arch)))
      { $so_obj_flags = ''; }

  elsif(defined($CC_SO_LINK_FLAGS{$cc}{$os}))
      { $so_link_flags = $CC_SO_LINK_FLAGS{$cc}{$os}; }
   elsif(defined($CC_SO_LINK_FLAGS{$cc}{'default'}))
      { $so_link_flags = $CC_SO_LINK_FLAGS{$cc}{'default'}; }

   my $make_shared = 0;
   $make_shared = 1
       if(($so_obj_flags or $so_link_flags) and $OS_SUPPORTS_SHARED{$os});

   ##################################################
   # Set check code compilation flags               #
   ##################################################
   my $check_opt_flags = $CC_CHECK_OPT_FLAGS{$cc};

   ##################################################
   # Set misc ABI options                           #
   ##################################################
   my $ccopts = '';

   $ccopts .= ' '.$CC_ABI_FLAGS{$cc}{$arch}
      if(defined($CC_ABI_FLAGS{$cc}{$arch}));

   $ccopts .= ' '.$CC_ABI_FLAGS{$cc}{$os} if(defined($CC_ABI_FLAGS{$cc}{$os}));

   $ccopts .= ' '.$CC_ABI_FLAGS{$cc}{'all'}
      if(defined($CC_ABI_FLAGS{$cc}{'all'}));

   ##################################################
   # Where to install?                              #
   ##################################################
   my $install_root = os_install_info($os, 'root');
   my $header_dir   = os_install_info($os, 'headers');
   my $lib_dir      = os_install_info($os, 'libs');
   my $doc_dir      = os_install_info($os, 'docs');

   if($user_set_root ne '') { $install_root = $user_set_root; }

   ##################################################
   # Open the makefile                              #
   ##################################################
   open MAKEFILE, ">$MAKE_FILE"
      or die "Couldn't write $MAKE_FILE ($!)\n";

   ##################################################
   # Ready, set, print!                             #
   ##################################################
   my $cc_bin = $CC_BINARY_NAME{$cc};

   # Hack for 10.1, 10.2+ is fixed. Don't have a 10.0.x machine anymore
   if($os eq "darwin" and $cc eq "gcc") { $cc_bin = "c++"; }

   my $obj_suffix = os_obj_suffix($os);
   my $static_suffix = os_static_suffix($os);

   # Man that's a lot of arguments. :)
   my @arguments = (\*MAKEFILE,
                    $os,
                    $cc_bin . $ccopts,
                    $lib_opt_flags,
                    $check_opt_flags,
                    $mach_opt_flags,
                    $lang_flags,
                    $CC_WARN_FLAGS{$cc},
                    $make_shared,
                    $so_obj_flags,
                    $so_link_flags,
                    $obj_suffix,
                    os_shared_suffix($os),
                    $static_suffix,
                    $ar_command,
                    $ar_needs_ranlib,
                    \%all_lib_srcs,
                    $check_src,
                    \%all_includes,
                    \%DOCS,
                    $install_root,
                    $header_dir,
                    $lib_dir,
                    $doc_dir,
                    \@libs_used);

   if($make_style eq 'unix') { print_unix_makefile(@arguments); }
   elsif($make_style eq 'nmake') { print_nmake_makefile(@arguments); }
   else {
      die "(error): This configure script does not know how to make ",
          "a makefile for makefile style \"$make_style\"\n";
   }

   close MAKEFILE;
}

##################################################
# Print a header for a makefile                  #
##################################################
sub print_header {
    my ($fh, $comment, $string) = @_;
    print $fh $comment x 50, "\n",
             "$comment $string", ' 'x(47-length($string)), "$comment\n",
              $comment x 50, "\n";
}
