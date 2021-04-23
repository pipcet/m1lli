#!/usr/bin/perl
package Integer;
sub new {
    my ($class, @args) = @_;
    my $ret = { args => \@args };
    return bless $ret, $class;
}

sub print {
    my ($self) = @_;
    #return join(" + ", map { sprintf("0x%08x /* %d */", $_, $_) } @{$self->{args}});
    return join(" + ", map { sprintf("0x%08x", $_) } @{$self->{args}});
}

package Sum;
sub new {
    my ($class, @args) = @_;
    my $ret = { args => \@args };
    return bless $ret, $class;
}

sub print {
    my ($self) = @_;
    return join(" + ", map {$_->print} @{$self->{args}});
}

sub print_value {
    my ($self) = @_;
    my $sum = 0;
    for my $arg (@{$self->{args}}) {
	my $val = $arg->print;
	$val =~ s/\/\*.*?\*\///g;
	$val =~ s/ //g;
	$sum += hex $val;
    }
    return $sum;
}

package Omitted;
sub new { return bless {}, $_[0] };

sub print { "..." }

package Reference;
sub new {
    my ($class, $name) = @_;
    my $ret = { name => $name };
    return bless $ret, $class;
}

sub print {
    my ($self) = @_;
    my $name = $self->{name};
    $name =~ s/.*\.//;
    return "<\&" . ${name} . ">";
}

package Array;
sub new {
    my ($class, @args) = @_;
    my $ret = { args => \@args };
    return bless $ret, $class;
}

sub print {
    my ($self) = @_;
    return "[" . join(", ", map {$_->print} @{$self->{args}}) . "]";
}

package Strings;
sub new {
    my ($class, @args) = @_;
    my $ret = { args => \@args };
    return bless $ret, $class;
}

sub print {
    my ($self) = @_;
    my @cargs = @{$self->{args}};
    for my $i (0 .. $#cargs) {
	if (ref $cargs[$i]) {
	    $cargs[$i] = $cargs[$i]->print;
	}
    }
    return join(", ", @{$self->{args}});
}

sub string_value {
    my ($self) = @_;
    my $ret = eval $self->{args}[0];
}

package main;

use Data::Dumper;

sub print_value {
    my ($value) = @_;
    if (ref $value eq "ARRAY") {
	return "[" . join(", ", map { print_value($_) } @$value) . "]";
    }
    return $value;
}

sub parse_value {
    my ($value) = @_;
    return $value if ref $value;
    $value =~ s/\/\*.*?\*\///g;
    if ($value =~ /^\[(.*)\]$/) {
	my @value = split ", ", $1;
	map { $_ = parse_value($_) } @value;
	return new Array(@value);
    } elsif ($value =~ /^0x(.*)$/) {
	return new Integer(hex($value));
    } elsif ($value =~ /^[0-9]*$/) {
	return new Integer($value);
    } elsif ($value =~ /^\"(.*?)\"$/) {
	return new Strings(split ", ", $value);
    } elsif ($value =~ /^\{0,\}$/) {
	return new Array();
    } elsif ($value =~ /^<omitted>$/) {
	return new Omitted();
    } elsif ($value =~ /^<(.*?)>$/) {
	return new Reference($1);
    } else {
	die "unhandled value $value";
    }
}

my @lines = <>;
map { chomp } @lines;
map { s/^adt\.device-tree\./adt./ } @lines;
map { s/^adt\.arm-io\./soc./ } @lines;
my %clocks;
my $count = 500000;
push @lines, "clk.81.node[0:0] = <soc.pmgr.clk_MYSTERY>";
while (@lines) {
    my $line = shift @lines;
    if ($count-- <= 0) {
	warn $line;
    }
    my $index = @lines;
    push @lines, $line;
    $line =~ /^([^\[]*)\[(.*?):(.*?)\] = (.*)$/;
    my ($path, $off0, $off1, $value) = ($1, $2, $3, $4);
    my $pvalue = parse_value($value);
    my @path = split(".", $path);
    my $node = $path;
    $node =~ s/\.([^.]*)$//;
    my $prop = $1;
    if ($prop eq "reg" && $node !~ /.*\..*\..*\..*\..*/) {
	$off0 ^= 4;
	if ($off0 % 16 == 0) {
	    $pvalue->{args}[0]{args}[0] ||= 2;
	}
    }
    if ($path eq "soc.pmgr.devices") {
	my ($flags, $parent, $addr1, $addr0, $id, $name) = @{$pvalue->{args}};
	$id = $id->{args}[0];
	my $clkname = "clk_" . $name->string_value;
	$name = $name->{args}[0];
	$parent = $parent->{args}[0];
	$addr0 = $addr0->{args}[0];
	$addr1 = $addr1->{args}[0];
	next unless ($parent == 0) or exists($adt{"clk.$parent"}{node}{0});
	next unless exists $adt{$node}{"ps-reg"}{12 * $addr0};
	push @lines, "clk.$id.node[0:0] = <soc.$clkname>";
	if ($parent) {
	    my $parentclk = $adt{"clk.$parent"}{node}{0}{name};
	    push @lines, "soc.$clkname.power-gates[0:4] = [$parent]";
	}
	push @lines, "soc.$clkname.reg[0:4] = " . ($adt{$node}{"ps-reg"}{12 * $addr0}{args}[0]{args}[0] + 8 * $addr1);
	push @lines, "soc.$clkname.reg[4:8] = 0";
	push @lines, "soc.$clkname.reg[8:12] = 8";
	push @lines, "soc.$clkname.reg[12:16] = 0";
	push @lines, "soc.$clkname.compatible[0:0] = \"apple,pmgr-clk-gate\"";
	push @lines, "soc.$clkname.#clock-cells[0:4] = 0";
	push @lines, "soc.$clkname.clock-output-names[0:0] = \"$clkname\"";
	push @lines, "soc.$clkname.name[0:0] = \"" . $clkname . "\"";
    } elsif ($prop eq "power-gates") {
	my $id = $pvalue->{args}->[0]->{args}->[0];
	next unless exists $adt{"clk.$id"}{node}{0};
	push @lines, "$node.clk[" . ($off0 / 4) . ":" . (($off/4) + 4) . "] = <" . $adt{"clk.$id"}{node}{0}{name} . ">";
    } elsif ($prop eq "clock-gates") {
	my $id = $pvalue->{args}->[0]->{args}->[0];
	next unless exists $adt{"clk.$id"}{node}{0};
	push @lines, "$node.clk[" . ($off0 / 4) . ":" . (($off/4) + 4) . "] = <" . $adt{"clk.$id"}{node}{0}{name} . ">";
    } elsif ($path eq "soc.pmgr.ps-regs") {
	my $index = 16 * $pvalue->{args}[0]->print + 4;
	next unless exists $adt{$node}{reg}{$index};
	my $addr = ($adt{$node}{reg}{$index}{args}[0]{args}[0] +
		    $pvalue->{args}[1]{args}[0]);
	push @lines, "soc.pmgr.ps-reg[$off0:$off1] = \[$addr\]";
    } elsif ($prop eq "name") {
	my $parent = $path;
	$parent =~ s/\.[^.]*$//;
	my $child = $parent;
	$parent =~ s/\.[^.]*$//;
	push @lines, "${child}.parent[0:4] = <${parent}>";
	$parents{$child} = $parent;
    } elsif ($prop eq "reg" && ($node =~ /.*\..*\..*/ ? $off0 == 0 : $off0 == 4)) {
	my $pval = $pvalue->{args}[0];
	$pval = hex $pval->print if (ref $pval);
	$pval = sprintf("%x", $pval);
	push @lines, "${node}.print_addr[0:0] = \"$pval\"";
    } elsif ($prop eq "AAPL,phandle") {
	push @lines, "handle.$handle = <$node>";
    } elsif ($prop eq "print_addr") {
	my $name = $adt{$node}{name}{0}{args}[0];
	my $addr = $pvalue->print;
	warn "addr $addr";
	$name =~ s/^\"//;
	$name =~ s/\"$//;
	$addr =~ s/^\"//;
	$addr =~ s/\"$//;
	push @lines, "${node}.full_name[0:0] = \"" . $name . "@" . $addr . "\"";
    }
    splice @lines, $index, 1;
    $adt{$node}{$prop}{$off0} = $pvalue
	unless exists $adt{$node}{$prop}{$off0};
}

for my $node (sort keys %adt) {
    for my $prop (sort keys %{$adt{$node}}) {
	for my $off0 (sort { $a <=> $b } keys %{$adt{$node}{$prop}}) {
	    my $pvalue = $adt{$node}{$prop}{$off0};
	    next unless ref $pvalue ne "HASH";
	    print "$node.$prop\[$off0\] = " . $pvalue->print . "\n";
	}
    }
}
