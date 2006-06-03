##################################################
# Print a Unix style makefile                    #
##################################################
sub print_unix_makefile {
   my ($makefile, $os, $cc,
       $lib_opt, $check_opt, $mach_opt,
       $lang_flags, $warn_flags,
       $make_shared, $so_obj, $so_link,
       $obj_suffix, $so_suffix, $static_lib_suffix,
       $ar_command, $use_ranlib,
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
   my $link_to = "-lm";
   foreach my $lib (@{ $lib_list })
   {
       $link_to .= " -l" . $lib;
   }

   ##################################################
   # Generate a few variables                       #
   ##################################################
   my $lib_flags   = '$(LIB_OPT) $(MACH_OPT) $(LANG_FLAGS) $(WARN_FLAGS)';

   my $libs = '$(STATIC_LIB)';
   if($make_shared) { $lib_flags .= ' $(SO_OBJ_FLAGS)';
                      $libs .= ' $(SHARED_LIB)'; }

   my $install_user = os_install_info($os, 'user');
   my $install_group = os_install_info($os, 'group');

   my $install_cmd_exec = os_install_info($os, 'command');
   my $install_cmd_data = os_install_info($os, 'command');

   $install_cmd_exec =~ s/OWNER/\$(OWNER)/;
   $install_cmd_data =~ s/OWNER/\$(OWNER)/;

   $install_cmd_exec =~ s/GROUP/\$(GROUP)/;
   $install_cmd_data =~ s/GROUP/\$(GROUP)/;

   $install_cmd_exec =~ s/MODE/\$(EXEC_MODE)/;
   $install_cmd_data =~ s/MODE/\$(DATA_MODE)/;

##################### COMMON CODE (PARTIALLY) ######################
   sub file_list {
      my ($spaces, $put_in, $from, $to, %files) = @_;
      my $len = $spaces;
      my $list;
      foreach (sort keys %files) {
         my $file = $_;
         my $dir = $put_in;
         if(!defined($dir)) { $dir = $files{$_}; }
         if($len > 60)
            { $list .= "\\\n" . ' 'x$spaces; $len = $spaces; }
         if(defined($from) and defined($to)) { $file =~ s/$from/$to/; }
         if(defined($dir))
            { $list .= catfile ($dir, $file) . ' ';
              $len += length($file) + length($dir); }
         else
            { $list .= $file . ' ';
              $len += length($file); }
      }
      return $list;
   }

   my $includes = file_list(16, undef, undef, undef, %includes);

   my $lib_obj = file_list(16, $BUILD_LIB_DIR, '(\.cpp$|\.s$|\.S$)',
                           '.'.$obj_suffix, %src, %added_src);
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
SO_OBJ_FLAGS  = $so_obj
SO_LINK_CMD   = $so_link
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

BINDIR        = \$(INSTALLROOT)/bin
LIBDIR        = \$(INSTALLROOT)/$lib_dir
HEADERDIR     = \$(INSTALLROOT)/$header_dir/botan
DOCDIR        = \$(INSTALLROOT)/$doc_dir/Botan-\$(VERSION)

OWNER         = $install_user
GROUP         = $install_group
DATA_MODE     = 644
EXEC_MODE     = 755

CONFIG_SCRIPT = botan-config

END_OF_INSTALL_SETTINGS

   print_header($makefile, $COMMENT_CHAR, 'Aliases for Common Programs');
   print $makefile <<END_OF_COMMAND_ALIASES;
AR               = $ar_command
CD               = \@cd
ECHO             = \@echo
INSTALL_CMD_EXEC = $install_cmd_exec
INSTALL_CMD_DATA = $install_cmd_data
LN               = ln -fs
MKDIR            = \@mkdir
MKDIR_INSTALL    = \@umask 022; mkdir -p -m \$(EXEC_MODE)
RANLIB           = \@ranlib
RM               = \@rm -f
RM_R             = \@rm -rf

END_OF_COMMAND_ALIASES

   print_header($makefile, $COMMENT_CHAR, 'File Lists');
   print $makefile <<END_OF_FILE_LISTS;
CHECK         = check

DOCS          = $doc_list

HEADERS       = $includes

LIBOBJS       = $lib_obj

CHECKOBJS     = $check_obj

LIB_FLAGS     = $lib_flags
CHECK_FLAGS   = \$(CHECK_OPT) \$(LANG_FLAGS) \$(WARN_FLAGS)

LIBRARIES     = $libs

LIBNAME       = libbotan
STATIC_LIB    = \$(LIBNAME).$static_lib_suffix

END_OF_FILE_LISTS

   if($make_shared) {
       print $makefile <<END_OF_SHARED_LIB_DECL;
SHARED_LIB    = \$(LIBNAME)-\$(MAJOR).\$(MINOR).\$(PATCH).$so_suffix
SONAME        = \$(LIBNAME)-\$(MAJOR).\$(MINOR).\$(PATCH).$so_suffix

SYMLINK       = \$(LIBNAME).$so_suffix

END_OF_SHARED_LIB_DECL
   }

   print $makefile "all: \$(LIBRARIES)\n\n";
   print_header($makefile, $COMMENT_CHAR, 'Build Commands');

   sub print_build_cmds {
      my ($fh, $dir, $flags, $obj_suffix, %files) = @_;
      foreach (sort keys %files) {
         my $src_file = catfile ($files{$_}, $_);
         my $obj_file = catfile ($dir, $_);
         $obj_file =~ s/\.cpp$/.$obj_suffix/;
         $obj_file =~ s/\.s$/.$obj_suffix/;
         $obj_file =~ s/\.S$/.$obj_suffix/;
         print $fh "$obj_file: $src_file\n",
            "\t\$(CXX) -I$BUILD_INCLUDE_DIR $flags -c \$? -o \$@\n\n";
      }
   }

   print_build_cmds($makefile, $BUILD_LIB_DIR,
                    '$(LIB_FLAGS)', $obj_suffix, %src, %added_src);

   print_build_cmds($makefile, $BUILD_CHECK_DIR,
                    '$(CHECK_FLAGS)', $obj_suffix, %check);

   print_header($makefile, $COMMENT_CHAR, 'Link Commands');

   print $makefile <<END_OF_LINK_COMMANDS;
\$(CHECK): \$(LIBRARIES) \$(CHECKOBJS)
$__TAB__\$(CXX) \$(CHECKOBJS) -L. -lbotan \$(LINK_TO) -o \$(CHECK)

\$(STATIC_LIB): \$(LIBOBJS)
$__TAB__\$(RM) \$(STATIC_LIB)
$__TAB__\$(AR) \$(STATIC_LIB) \$(LIBOBJS)
END_OF_LINK_COMMANDS

   if($use_ranlib) { print $makefile "$__TAB__\$(RANLIB) \$(STATIC_LIB)\n\n"; }
   else { print $makefile "\n"; }

   if($make_shared) {
      print $makefile <<END_OF_SO_LINK_COMMAND;
\$(SHARED_LIB): \$(LIBOBJS)
$__TAB__\$(SO_LINK_CMD) \$(LINK_TO) \$(LIBOBJS) -o \$(SHARED_LIB)
$__TAB__\$(LN) \$(SHARED_LIB) \$(SYMLINK)

END_OF_SO_LINK_COMMAND
    }


   print_header($makefile, $COMMENT_CHAR, 'Fake Targets');

   print $makefile ".PHONY = clean distclean install static";
   if($make_shared) { print $makefile " shared"; }
   print $makefile "\n\n";

   print $makefile "static: \$(STATIC_LIB)\n\n";
   if($make_shared) { print $makefile "shared: \$(SHARED_LIB)\n\n"; }

   print $makefile <<END_OF_FAKE_TARGETS;
clean:
$__TAB__\$(RM_R) $BUILD_LIB_DIR/* $BUILD_CHECK_DIR/*
$__TAB__\$(RM) \$(LIBRARIES) \$(SYMLINK) \$(CHECK)

distclean: clean
$__TAB__\$(RM_R) $BUILD_DIR
$__TAB__\$(RM) $MAKE_FILE \$(CONFIG_SCRIPT)

END_OF_FAKE_TARGETS

   print $makefile <<END_OF_INSTALL_SCRIPTS;
install: \$(LIBRARIES)
$__TAB__\$(ECHO) "Installing Botan into \$(INSTALLROOT)... "
$__TAB__\$(MKDIR_INSTALL) \$(DOCDIR)
$__TAB__\$(MKDIR_INSTALL) \$(HEADERDIR)
$__TAB__\$(MKDIR_INSTALL) \$(LIBDIR)
$__TAB__\$(MKDIR_INSTALL) \$(BINDIR)
$__TAB__\@for i in \$(DOCS); do \\
$__TAB__   \$(INSTALL_CMD_DATA) \$\$i \$(DOCDIR); \\
$__TAB__ done
$__TAB__\@for i in \$(HEADERS); do \\
$__TAB__   \$(INSTALL_CMD_DATA) \$\$i \$(HEADERDIR); \\
$__TAB__ done
$__TAB__\@\$(INSTALL_CMD_DATA) \$(STATIC_LIB) \$(LIBDIR)
$__TAB__\@\$(INSTALL_CMD_EXEC) \$(CONFIG_SCRIPT) \$(BINDIR)
END_OF_INSTALL_SCRIPTS

   if($make_shared) {
      print $makefile <<END_OF_SYMLINKS;
$__TAB__\@\$(INSTALL_CMD_EXEC) \$(SHARED_LIB) \$(LIBDIR)
$__TAB__\$(CD) \$(LIBDIR); \$(LN) \$(SHARED_LIB) \$(SYMLINK)

END_OF_SYMLINKS
   }
   else { print $makefile "\n"; }

}
