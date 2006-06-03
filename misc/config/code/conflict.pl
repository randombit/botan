sub check_for_conflicts {
   my @mods = @_;
   my (%ignored, %added, %replaced, %defines);
   foreach my $mod (@mods) {

       sub check_hash {
           my ($mod, $do_what, $hashref) = @_;
           foreach (keys %{ $MODULES{$mod}{$do_what} }) {
               ${$hashref}{conflicts($mod, $_, $do_what, $hashref)} = $mod;
           }
       }

      check_hash($mod, 'define', \%defines);
      check_hash($mod, 'replace', \%replaced);
      check_hash($mod, 'add', \%added);
      check_hash($mod, 'ignore', \%ignored);
   }
}

sub conflicts {
    my ($mod, $item, $do_what, $hashref) = @_;
    return if(!defined($item));

    if(defined($$hashref{$item})) {
       my $other_mod = $$hashref{$item};
       die "(error): Both $mod and $other_mod $do_what $item\n";
       }
    return $item;
}
