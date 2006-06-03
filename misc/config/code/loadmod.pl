sub load_module {
   my ($modname,$cc,$os,$arch,$sub,%module) = @_;

   # Check to see if everything is OK WRT system requirements
   if(defined($module{'os'}) and !exists($module{'os'}{$os}) and
         $os ne 'generic')
       { die "(error): Module '$modname' does not run on $REALNAME{$os}\n"; }

   if(defined($module{'arch'}) and $arch ne 'generic' and
      !exists($module{'arch'}{$arch}) and !exists($module{'arch'}{$sub}))
       { die "(error): Module '$modname' does not run on ".
              "$REALNAME{$arch}/$sub\n"; }

   if(defined($module{'cc'}) and !exists($module{'cc'}{$cc}))
       {
       die "(error): Module '$modname' does not work with $REALNAME{$cc}\n";
       }

   handle_files($modname, $module{'replace'}, \&replace_file);
   handle_files($modname, $module{'ignore'},  \&ignore_file);
   handle_files($modname, $module{'add'},     \&add_file);

   if(defined($module{'notes'}))
   {
       my $realname = $module{'name'};
       my $note = $module{'notes'};
       print STDERR "(note): $modname (\"$realname\"): $note\n";
   }
}

sub handle_files {
   my($modname, $hash_scalar, $func) = @_;
   return unless defined($hash_scalar);
   my %hash = %{ $hash_scalar };
   foreach (sort keys %hash) {
      if(defined($hash{$_})) { &$func($modname, $_, $hash{$_}); }
      else                   { &$func($modname, $_); }
    }
}

sub full_path {
   my ($file,$modname) = @_;
   if(defined($modname))
      { return catfile ($MOD_DIR, $modname, $file); }
   else {
      if($file =~ /\.h$/)
         { return catfile ($INCLUDE_DIR, $file); }
      elsif($file =~ /\.cpp$/ or $file =~ /\.s$/ or $file =~ /\.S$/)
         { return catfile ($SRC_DIR, $file); }
      else { die "(internal error): Not sure where to put $file\n"; }
   }
}

sub add_file {
    my ($modname,$file) = @_;
    check_for_file(full_path($file, $modname), $modname);
    if($file =~ /\.cpp$/ or $file =~ /\.s$/ or $file =~ /\.S$/)
    { $added_src{$file} = catdir($MOD_DIR, $modname); }
    elsif($file =~ /\.h$/)
    { $added_include{$file} = catdir($MOD_DIR, $modname); }
    else { die "Not sure where to put $file\n"; }
}

sub ignore_file {
   my ($modname,$file) = @_;
   check_for_file(full_path($file), $modname);
   if($file =~ /\.cpp$/ or $file =~ /\.s$/ or $file =~ /\.S$/)
      { $ignored_src{$file} = 1; }
   elsif($file =~ /\.h$/) { $ignored_include{$file} = 1; }
   else { die "Not sure where to put $file\n"; }
}

# This works because ignore file always runs on files in the main source tree,
# and add always works on the file in the modules directory.
sub replace_file {
   my ($modname,$file) = @_;
   ignore_file($modname, $file);
   add_file($modname, $file);
}
