#!/usr/bin/perl
use strict;
use File::Slurp qw(read_file write_file);
use IPC::Run qw(run);

sub usage {
    my $program = "dt";
    warn "${program} adt-to-dtp <adt file> <dtp file>: convert ADT binary format to DT property format\n";
    warn "${program} dtb-to-dtp <adt file> <dtp file>: convert DTB binary format to DT property format\n";
    warn "${program} dtp-to-dtb <adt file> <dtp file>: convert DT property format to DTB binary format\n";
    warn "${program} tunable <adt file> <dtp file>: extract tunables from ADT binary format\n";
    warn "${program} extract-adt <dtb file> <adt file>: extract ADT from DTB binary format\n";
    warn "${program} dts-to-dtp <adt file> <dtp file>: convert DT source format to DT property format\n";
    warn "${program} dtp-to-dts <adt file> <dtp file>: convert DT property format to DT source format\n";
}

sub dts_to_dtp {
    my $dts = shift;
    my $dtp = "";
    my @lines = split("\n", $dts);
    my @path = ();
    for (@lines) {
	next if /^\//;
	s/^[\t ]*//;
	if (/^};/) {
	    pop @path;
	} elsif (/^(.*) {/) {
	    push @path, "$1.";
	} elsif (/^(.*?) = (.*);$/) {
	    $dtp .= (join("", @path) . "$1 = $2\n");
	} elsif (/^(.*?);$/) {
	    $dtp .= (join("", @path) . "$1\n");
	} elsif (/^[ \t]*$/) {
	} else {
	    die "bad line $_";
	}
    }
    die unless @path == 0;
    return $dtp;
}

sub dtp_to_dts {
    my %fdt;
    my @fdt;

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

    my $dts = "";
    $dts .= "/dts-v1/;\n";
    $dts .= "/ {\n";
    my @lastpath;
    my $node = "";
    for my $propval (@{$fdt{$node}}) {
	my ($prop, $val) = @$propval;
	if (defined $val) {
	    $dts .= (("    " x (@lastpath + 1)) . "$prop = $val;\n");
	} else {
	    $dts .= (("    " x (@lastpath + 1)) . "$prop;\n");
	}
    }
    while (@fdt) {
	my $node = shift @fdt;
	my @path = split /\./, $node;
	if ($path[0] eq "") { @path = (); }
	while (@lastpath && $lastpath[$#lastpath] ne $path[$#lastpath]) {
	    pop @lastpath;
	    $dts .= (("    " x (@lastpath + 1)) . "};\n");
	}
	while (@path > @lastpath) {
	    $dts .= (("    " x (@lastpath + 1)) . "$path[@lastpath] {\n");
	    push @lastpath, $path[@lastpath];
	    if (@path == @lastpath) {
		for my $propval (@{$fdt{$node}}) {
		    my ($prop, $val) = @$propval;
		    if (defined $val) {
			$dts .= (("    " x (@lastpath + 1)) . "$prop = $val;\n");
		    } else {
			$dts .= (("    " x (@lastpath + 1)) . "$prop;\n");
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
	$dts .= (("    " x (@lastpath + 1)) . "};\n");
    }

    $dts .= ("};\n");

    return $dts;
}

sub dts_to_dtb {
    my $dts = shift;
    my $dtb = "";
    run(["dtc", "-Idts", "-Odtb"], \$dts, \$dtb) or die;

    return $dtb;
}

my $stdin = "";
if ($ARGV[0] eq "--help") {
    usage();
    exit(1);
} elsif ($ARGV[0] eq "adt-to-dtp") {
    my $dtp = "";
    run(["adtp", $ARGV[1]], \$stdin, \$dtp) or die;
    write_file($ARGV[2], $dtp) or die;
} elsif ($ARGV[0] eq "dtb-to-dtp") {
    my $dts = "";
    run(["dtc", "-Idtb", "-Odts", $ARGV[1]], \$stdin, \$dts) or die;
    my $dtp = dts_to_dtp($dts);
    write_file($ARGV[2], $dtp) or die;
} elsif ($ARGV[0] eq "dts-to-dtp") {
    my $dts = read_file($ARGV[1]);
    my $dtp = dts_to_dtp($dts);
    write_file($ARGV[2], $dtp) or die;
} elsif ($ARGV[0] eq "dtp-to-dts") {
    my $dtp = read_file($ARGV[1]);
    my $dts = dtp_to_dts($dtp);
    write_file($ARGV[2], $dts) or die;
} elsif ($ARGV[0] eq "dtp-to-dtb") {
    my $dtp = read_file($ARGV[1]);
    my $dts = dtp_to_dts($dtp);
    my $dtb = dts_to_dtb($dts);
    write_file($ARGV[2], $dtb) or die;
} elsif ($ARGV[0] eq "tunable") {
} elsif ($ARGV[0] eq "extract-adt") {
} else {
    usage();
    exit(1);
}
