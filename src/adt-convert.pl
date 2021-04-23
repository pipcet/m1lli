my @lines = <>;
map { chomp } @lines;
my @lastpath;
my %adt;

sub unquote_string {
    my @values = @_;
    map { s/^"//; } @values;
    map { s/"$//; } @values;
    return join(" ", @values);
}

sub value_join {
    my @values = @_;
    map { s/^<//; } @values;
    map { s/>$//; } @values;
    return "<" . join(" ", @values) . ">";
}

while (@lines) {
    my $line = shift @lines;
    $line =~ /^(.*?)\.([^.\[]*?)\[(.*?)(:.*?)?\] = (.*)$/;
    my ($node, $prop, $off0, $value) = ($1, $2, $3, $5);
    $adt{$node}{$prop}{$off0} = $value;
}
for my $path (sort keys %adt) {
    for my $prop (sort keys %{$adt{$path}}) {
	for $off0 (sort { $a <=> $b } keys %{$adt{$path}{$prop}}) {
	    my $value = $adt{$path}{$prop}{$off0};
	    push @{$adtvals{$path . "." . $prop}}, $value;
	}
    }
}
for my $path (sort keys %adtvals) {
    my @values = @{$adtvals{$path}};
    my @path = split(/\./, $path);
    my $node = $path;
    $node =~ s/\.([^.]*)$//;
    my $prop = $1;
    pop @path;
    while (@lastpath && $lastpath[$#lastpath] ne $path[$#lastpath]) {
	pop @lastpath;
	print(("    " x @lastpath) . "    };\n");
    }
    while ($#lastpath < $#path) {
	print(("    " x @lastpath) . "    " . $path[$#lastpath+1] . ": " . unquote_string($adt{$node}{full_name}{0}) . "    {\n");
	push @lastpath, $path[$#lastpath+1];
    }
    my $outprop;
    if ($prop =~ /^(#(address|size|clock)-cell?s)$/) {
	map { s/^\[(.*)\]$/$1/ } @values;
	my $value = join(", ", @values);
	print(("    " x @lastpath) . "    $prop = <$value>;\n");
    }
    if ($prop =~ /^(compatible|clock-output-names)$/) {
	map { s/^\[(.*)\]$/$1/ } @values;
	my $value = join(" ", @values);
	print(("    " x @lastpath) . "    $prop = $value;\n");
    }
    if ($prop =~ /^(reg)$/) {
	map { s/^\[(.*)\]$/$1/ } @values;
	my $value = join(" ", @values);
	print(("    " x @lastpath) . "    $prop = <$value>;\n");
    }
    if ($prop eq "clk") {
	my $value = value_join(@values);
	print(("    " x @lastpath) . "    clocks = $value;\n");
    }
    @lastpath = @path;
}
while (@lastpath) {
    pop @lastpath;
    print(("    " x @lastpath) . "    };\n");
}
