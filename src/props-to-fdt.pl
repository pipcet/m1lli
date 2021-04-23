my %fdt;

while (<>) {
    chomp;
    /^(.*?)\.([^. ]*) = (.*)$/ or die;
    $fdt{$1}{$2} = $3;
}

print "/dts-v1/;\n";
print "/ {\n";
my @lastpath;
for my $node (sort keys %fdt) {
    my @path = split /\./, $node;
    if ($path[0] eq "") { @path = (); }
    while (@lastpath && $lastpath[$#lastpath] ne $path[$#lastpath]) {
	print "};\n";
	pop @lastpath;
    }
    while (@path > @lastpath) {
	print "$path[@lastpath] {\n";
	push @lastpath, $path[@lastpath];
    }
    for my $prop (sort keys %{$fdt{$node}}) {
	print "$prop = " . $fdt{$node}{$prop} . ";\n";
    }
}
while (@lastpath) {
    print "};\n";
    pop @lastpath;
}
