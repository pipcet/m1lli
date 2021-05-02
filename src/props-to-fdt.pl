my %fdt;

while (<>) {
    chomp;
    if (/^(.*?)([^. ]*) = (.*)$/) {
	push @fdt, $1 unless exists $fdt{$1};
	push @{$fdt{$1}}, [$2, $3];
    } elsif (/^(.*?)([^. ]*)$/) {
	push @fdt, $1 unless exists $fdt{$1};
	push @{$fdt{$1}}, [$2];
    }
}

print "/dts-v1/;\n";
print "/ {\n";
my @lastpath;
my $node = "";
for my $propval (@{$fdt{$node}}) {
    my ($prop, $val) = @$propval;
    if (defined $val) {
	print(("    " x (@lastpath + 1)) . "$prop = $val;\n");
    } else {
	print(("    " x (@lastpath + 1)) . "$prop;\n");
    }
}
while (@fdt) {
    my $node = shift @fdt;
    my @path = split /\./, $node;
    if ($path[0] eq "") { @path = (); }
    while (@lastpath && $lastpath[$#lastpath] ne $path[$#lastpath]) {
	pop @lastpath;
	print(("    " x (@lastpath + 1)) . "};\n");
    }
    while (@path > @lastpath) {
	print(("    " x (@lastpath + 1)) . "$path[@lastpath] {\n");
	push @lastpath, $path[@lastpath];
	if (@path == @lastpath) {
	    for my $propval (@{$fdt{$node}}) {
		my ($prop, $val) = @$propval;
		if (defined $val) {
		    print(("    " x (@lastpath + 1)) . "$prop = $val;\n");
		} else {
		    print(("    " x (@lastpath + 1)) . "$prop;\n");
		}
	    }
	}
    }
    my @cnodes;
    my @ncnodes;
    for my $node2 (@fdt) {
	if (substr($node2, 0, length($node)) eq $node) {
	    push @cnodes, $node2;
	} else {
	    push @ncnodes, $node2;
	}
    }
    @fdt = (@cnodes, @ncnodes);
}
while (@lastpath) {
    pop @lastpath;
    print(("    " x (@lastpath + 1)) . "};\n");
}

print("};\n");
