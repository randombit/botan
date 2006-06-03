##################################################
# Print a NMAKE-style makefile                   #
##################################################
sub print_nmake_makefile {
   my ($makefile, $os, $cc,
       $lib_opt, $check_opt, $mach_opt,
       $lang_flags, $warn_flags,
       undef, # $make_shared
       undef, # $so_obj
       undef, # $so_link
       $obj_suffix,
       $so_suffix,
       $static_lib_suffix,
       $ar_command,
       undef, # $use_ranlib
       $src_hash, $check_hash, $include_hash, $docs,
       $install_root, $header_dir, $lib_dir, $doc_dir,
       $lib_list) = @_;

   ##################################################
   # Some constants                                 #
   ##################################################
   my $__TAB__ = "\t";
   my $COMMENT_CHAR = '#';

   ##################################################
   # Convert the references to hashes               #
   ##################################################
   my %src = %{ $src_hash };
   my %includes = %{ $include_hash };

   my %check = %{ $check_hash };

   my %docs = %{ $docs };

   ##################################################
   # Make the library linking list                  #
   ##################################################
   my $link_to = '';
   foreach my $lib (@{ $lib_list })
   {
       my $lib_full = $lib . "." . $static_lib_suffix;
       if($link_to eq '') { $link_to .= $lib_full; }
       else               { $link_to .= ' ' . $lib_full; }
   }

   ##################################################
   # Generate a few variables                       #
   ##################################################
   my $lib_flags   = '$(LIB_OPT) $(MACH_OPT) $(LANG_FLAGS) $(WARN_FLAGS)';

   my $libs = '$(STATIC_LIB)';

##################### COMMON CODE (PARTIALLY) ######################

   my $includes = file_list(16, undef, undef, undef, %includes);

   my $lib_obj = file_list(16, $BUILD_LIB_DIR, '.cpp', '.'.$obj_suffix,
                           %src, %added_src);
   my $check_obj = file_list(16, $BUILD_CHECK_DIR, '.cpp', '.'.$obj_suffix,
                             %check);

   my $doc_list = file_list(16, undef, undef, undef, %docs);

##################### / COMMON CODE (PARTIALLY) ######################

   print_header($makefile, $COMMENT_CHAR, 'Compiler Options');
   print $makefile <<END_OF_MAKEFILE_HEADER;
CXX           = $cc
LIB_OPT       = $lib_opt
CHECK_OPT     = $check_opt
MACH_OPT      = $mach_opt
LANG_FLAGS    = $lang_flags
WARN_FLAGS    = $warn_flags
SO_OBJ_FLAGS  =
SO_LINK_FLAGS =
LINK_TO       = $link_to

END_OF_MAKEFILE_HEADER

   print_header($makefile, $COMMENT_CHAR, 'Version Numbers');
   print $makefile <<END_OF_VERSIONS;
MAJOR         = $MAJOR_VERSION
MINOR         = $MINOR_VERSION
PATCH         = $PATCH_VERSION

VERSION       = \$(MAJOR).\$(MINOR).\$(PATCH)

END_OF_VERSIONS

   print_header($makefile, $COMMENT_CHAR, 'Installation Settings');
   print $makefile <<END_OF_INSTALL_SETTINGS;
INSTALLROOT   = $install_root

LIBDIR        = \$(INSTALLROOT)\\$lib_dir
HEADERDIR     = \$(INSTALLROOT)\\$header_dir\\botan
DOCDIR        = \$(INSTALLROOT)\\$doc_dir

END_OF_INSTALL_SETTINGS

   print_header($makefile, $COMMENT_CHAR, 'Aliases for Common Programs');
   print $makefile <<END_OF_COMMAND_ALIASES;
AR            = $ar_command
CD            = \@cd
ECHO          = \@echo
INSTALL       = copy
INSTALL_CMD   = \$(INSTALL)
MKDIR         = \@md
MKDIR_INSTALL = \@md
RM            = \@del /Q
RMDIR         = \@rmdir

END_OF_COMMAND_ALIASES

   print_header($makefile, $COMMENT_CHAR, 'File Lists');
   print $makefile <<END_OF_FILE_LISTS;
LIB_FLAGS     = $lib_flags
CHECK_FLAGS   = \$(CHECK_OPT) \$(LANG_FLAGS) \$(WARN_FLAGS)

CHECK         = check

DOCS          = $doc_list

HEADERS       = $includes

LIBOBJS       = $lib_obj

CHECKOBJS     = $check_obj

LIBRARIES     = $libs

LIBNAME       = libbotan
STATIC_LIB    = \$(LIBNAME).$static_lib_suffix

END_OF_FILE_LISTS

   print $makefile "all: \$(LIBRARIES)\n\n";
   print_header($makefile, $COMMENT_CHAR, 'Build Commands');

   sub print_build_cmds_nmake {
      my ($fh, $dir, $flags, $obj_suffix, %files) = @_;
      foreach (sort keys %files) {
         my $src_file = catfile ($files{$_}, $_);
         my $obj_file = catfile ($dir, $_);
         $obj_file =~ s/.cpp/.$obj_suffix/;
         print $fh "$obj_file: $src_file\n",
            "\t\$(CXX) -I$BUILD_INCLUDE_DIR $flags /c \$? /Fo\$@\n\n";
      }
   }

   print_build_cmds_nmake($makefile, $BUILD_LIB_DIR,
                          '$(LIB_FLAGS)', $obj_suffix, %src, %added_src);

   print_build_cmds_nmake($makefile, $BUILD_CHECK_DIR,
                          '$(CHECK_FLAGS)', $obj_suffix, %check);

   print_header($makefile, $COMMENT_CHAR, 'Link Commands');

   print $makefile <<END_OF_LINK_COMMANDS;
\$(CHECK): \$(LIBRARIES) \$(CHECKOBJS)
${__TAB__}LINK /OUT:\$@.exe \$(CHECKOBJS) \$(STATIC_LIB) \$(LINK_TO)

\$(STATIC_LIB): \$(LIBOBJS)
$__TAB__\$(AR) /OUT:\$@ /NAME:BOTAN-\$(VERSION) \$(LIBOBJS)
END_OF_LINK_COMMANDS

   print $makefile "\n";

   print_header($makefile, $COMMENT_CHAR, 'Misc Targets');
   print $makefile "static: \$(STATIC_LIB)\n\n";

   print_header($makefile, $COMMENT_CHAR, 'Fake Targets');
   print $makefile <<END_OF_FAKE_TARGETS;
clean:
$__TAB__\$(RM) $BUILD_LIB_DIR\\* $BUILD_CHECK_DIR\\*
$__TAB__\$(RM) \$(LIBRARIES) \$(CHECK)

distclean: clean
$__TAB__\$(RM) $CPP_INCLUDE_DIR\\*
$__TAB__\$(RMDIR) $CPP_INCLUDE_DIR
$__TAB__\$(RMDIR) $BUILD_LIB_DIR $BUILD_CHECK_DIR $BUILD_INCLUDE_DIR $BUILD_DIR
$__TAB__\$(RM) $MAKE_FILE
END_OF_FAKE_TARGETS

   print_header($makefile, $COMMENT_CHAR, 'Install Commands');

   print $makefile <<END_OF_INSTALL_SCRIPTS;
install: \$(LIBRARIES)
$__TAB__\$(ECHO) "Install command not done"
END_OF_INSTALL_SCRIPTS

    print $makefile "\n";

}
