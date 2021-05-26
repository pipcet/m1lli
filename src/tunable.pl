#!/usr/bin/perl
use strict;
use Carp::Always;

package DTNode;

use strict;

sub string {
    my ($self) = @_;
    my @ret;
    if (scalar($self->bytes) % 4) {
	return "<<" . join(" ", map { sprintf("0x%02x", $_) } $self->bytes) . ">>";
    }
    for my $le32 ($self->le32) {
	push @ret, $le32;
    }
    return "<" . join(" ", map { sprintf("0x%02x", $_) } @ret ) . ">";
}

sub le32 {
    my ($self) = @_;
    my @ret = unpack("L<*", pack("C*", @{$self->{bytes}}));
    return @ret;
}

sub bytes {
    my ($self) = @_;
    return @{$self->{bytes}};
}

sub addresses {
    my ($self) = @_;
    my @ret;
    if ($self->{le}) {
	@ret = unpack("Q<*", pack("C*", $self->bytes));
    } else {
	@ret = unpack("Q>*", pack("C*", $self->bytes));
    }
    return @ret;
}

sub ranges {
    my ($self) = @_;
    my @addresses = $self->addresses;
    my @ret;
    for (my $i = 0; $i < @addresses; $i += 2) {
	push @ret, [$addresses[$i], $addresses[$i+1]];
    }
    return @ret;
}

sub new {
    my ($class, $unit, @values) = @_;
    my $ret = bless {}, $class;

    if ($unit eq "str-le32") {
	if ($values[0] =~ /^<(.*)>$/) {
	    @values = map { hex($_) } split(" ", $1);
	    $unit = "le32";
	    $ret->{le} = 1;
	} elsif ($values[0] =~ /^\"(.*)\"$/) {
	    @values = map { ord($_) } split("", $1);
	    $unit = "u8";
	}
    }

    if ($unit eq "str-be32") {
	if ($values[0] =~ /^<(.*)>$/) {
	    @values = map { hex($_) } split(" ", $1);
	    $unit = "be32";
	    $ret->{le} = 0;
	} elsif ($values[0] =~ /^\"(.*)\"$/) {
	    @values = map { ord($_) } split("", $1);
	    $unit = "u8";
	}
    }

    if ($unit eq "be32") {
	@values = unpack("C*", pack("L>*", @values));
	$unit = "u8";
    } elsif ($unit eq "le32") {
	@values = unpack("C*", pack("L<*", @values));
	$unit = "u8";
    } elsif ($unit eq "be64") {
	@values = unpack("C*", pack("Q>*", @values));
	$unit = "u8";
    } elsif ($unit eq "le64") {
	@values = unpack("C*", pack("Q<*", @values));
	$unit = "u8";
    }

    if ($unit eq "u8") {
	$ret->{bytes} = \@values;
    } else {
	die;
    }

    return $ret;
}

package TunableItem;

sub new {
    my $class = shift;
    my %h = @_;
    return bless \%h, $class;
}

sub encode {
    my ($self, $lreg) = @_;

    my @ret;
    return @ret unless $lreg;

    my @ranges = $lreg->ranges;
    my $offset;
    my $ri;
    for my $i (0 .. $#ranges) {
	my $range = $ranges[$i];
	if ($self->{addr} >= $range->[0] &&
	    $self->{addr} < $range->[0] + $range->[1]) {
	    $ri = $i;
	    $offset = $self->{addr} - $range->[0];
	}
    }

    die "couldn't find " . sprintf("%x", $self->{addr}) unless defined $ri;
    push @ret, ($offset + ($ri << 28), $self->{mask}, $self->{value});

    return @ret;
}

package Tunable;

use Data::Dumper;

sub new_from_fancy {
    my ($class, %h) = @_;
    my $abuf = $h{abuf};
    my $base = $h{base};
    my $ret = bless {}, $class;

    $ret->{items} = [];

    my @abuf = $abuf->le32;

    for (my $ai = 0; $ai < @abuf; $ai++) {
	my $offs = $abuf[$ai];
	my $size = $offs >> 24;
	$offs &= 0xffffff;
	if ($size == 255) {
	    $ai += 2;
	    next;
	}
	if ($size == 0 || $size == 32) {
	    my $addr = $base + $offs;
	    my $mask = $abuf[$ai + 1];
	    my $value = $abuf[$ai + 2];
	    my $size = 32;

	    push @{$ret->{items}}, TunableItem->new(
		addr => $addr,
		mask => $mask,
		value => $value,
		size => $size,
		);
	    $ai += 2;
	}
    }

    return $ret;
}

sub new_from_legacy {
    my ($class, %h) = @_;
    my $abuf = $h{abuf};
    my $areg = $h{areg};
    my $ret = bless {}, $class;

    $ret->{items} = [];

    my @abuf = $abuf->le32;
    my @areg = $areg->ranges;

    for (my $ai = 0; $ai < @abuf; $ai += 4) {
	my $range_id = $abuf[$ai];
	my $offs = $abuf[$ai + 1];
	my $addr = $areg[$range_id][0] + $offs;
	my $mask = $abuf[$ai + 2];
	my $value = $abuf[$ai + 3];

	push @{$ret->{items}}, TunableItem->new(
	    addr => $addr,
	    mask => $mask,
	    value => $value,
	    size => 32,
	    );
    }

    return $ret;
}

sub new_from_plain {
    my ($class, %h) = @_;
    my $abuf = $h{abuf};
    my @bytes = $abuf->bytes;
    my $size = $h{size} // 1;
    my $xor = $h{xor} // ($size - 1);
    my @bytes2;
    for my $i (0 .. $#bytes) {
	$bytes2[$i] = $bytes[$i ^ $xor];
    }

    return \@bytes2;
}

sub do_read32 {
    my $addr = shift;
    my %fake;
    $fake{hex "23d2bc438"} = 0xd9336420;
    $fake{hex "23d2bc43c"} = 0x0000000a;
    $fake{hex "23d2bc418"} = 0x38488000;
    $fake{hex "23d2bc41c"} = 0x0a86874f;
    $fake{hex "23d2bc084"} = 0x00025600;
    return $fake{+$addr} if exists $fake{+$addr};
    my $val = `memtool md $addr+4`;
    chomp $val;
    /^[0-9a-f]*: ([0-9a-f]*) / && return hex $1;
}

sub new_from_fusemap {
    my ($class, %h) = @_;
    my $map = $h{map};
    my $ret = bless {}, $class;
    my $base = $h{base};
    for my $row (@$map) {
	my $value;
	my $mask;
	my ($src_addr, $dst_offs, $src_lsb, $src_width, $dst_lsb, $dst_width) = @$row;
	if ($h{doread}) {
	    $value = do_read32($src_addr);
	} else {
	    die;
	}

	warn $value;
	$value >>= $src_lsb;
	warn $value;
	$value &= (1 << $src_width) - 1;
	warn $value;
	$mask = (1 << $dst_width) - 1;
	$mask <<= $dst_lsb;
	$value <<= $dst_lsb;
	$value &= $mask;

	push @{$ret->{items}}, TunableItem->new(
	    addr => $base + $dst_offs,
	    mask => $mask,
	    value => $value,
	    );
    }

    return $ret;
}

sub new_from_pcie {
    my ($class, %h) = @_;
    my $abuf = $h{abuf};
    my $areg = $h{areg};
    return unless $areg;
    my $range = $h{range};
    my $base = $h{base};
    my $ret = bless {}, $class;
    my @abuf = $abuf->le32;
    for (my $ai = 0; $ai < @abuf; $ai += 6) {
	my $size = $abuf[$ai + 1];
	my $offs = $abuf[$ai + 0];
	my $addr = ($areg->ranges)[$range][0] + $offs + $base;
	my $mask = $abuf[$ai + 2];
	my $value = $abuf[$ai + 4];

	push @{$ret->{items}}, TunableItem->new(
	    addr => $addr,
	    mask => $mask,
	    value => $value,
	    size => $size,
	    );
    }

    return $ret;
}

sub encode_to_fancy {
    my ($self, $lreg) = @_;
    my @ret;

    for my $item (@{$self->{items}}) {
	push @ret, $item->encode($lreg);
    }

    return DTNode->new("le32", @ret)->string;
}

package main;

sub buf_to_bytes {
    my ($buf) = @_;
    my @res;
    for my $i (0 .. $#$buf) {
	$res[4*$i] = ($buf->[$i] & 255);
	$res[4*$i+1] = (($buf->[$i] >>  8) & 255);
	$res[4*$i+2] = (($buf->[$i] >> 16) & 255);
	$res[4*$i+3] = (($buf->[$i] >> 24) & 255);
    }

    return @res;
}

sub bytes_to_buf {
    my @bytes = @_;
    my @res;
    for my $i (0 .. $#bytes) {
	$res[$i/4] = 0 unless defined $res[$i/4];
	$res[$i/4] += $bytes[$i] << (8 * ($i % 4));
    }

    return @res;
}

my %adt;
my $fh;
open $fh, "./m1lli/scripts/adtp adt|" or die;
while (<$fh>) {
    my ($prop, $pval);
    my @pbuf;
    chomp;
    if (/^(.*?) = (.*)$/) {
	($prop, $pval) = ($1, $2);
	$prop =~ s/^adt\.device-tree\.//;
	$adt{$prop} = DTNode->new("str-le32", $pval);
    }
}

my %dt;
my $fh;
open $fh, "./dt/m1.dtb.dts.dtp" or die;
while (<$fh>) {
    my ($prop, $pval);
    my @pbuf;
    chomp;
    if (/^(.*?) = (.*)$/) {
	($prop, $pval) = ($1, $2);
	$dt{$prop} = DTNode->new("str-be32", $pval);
    }
}

my %tunables;
my %ltunables;

my $pcie_fuse_map = [
    # /* src_addr, dst_offs, src_[lsb,width], dst_[lsb,width] */
    [ 0x23d2bc084, 0x6238,  4, 6,  0, 7 ],
    [ 0x23d2bc084, 0x6220, 10, 3, 14, 3 ],
    [ 0x23d2bc084, 0x62a4, 13, 2, 17, 2 ],
    [ 0x23d2bc418, 0x522c, 27, 2,  9, 2 ],
    [ 0x23d2bc418, 0x522c, 13, 3, 12, 3 ],
    [ 0x23d2bc418, 0x5220, 18, 3, 14, 3 ],
    [ 0x23d2bc418, 0x52a4, 21, 2, 17, 2 ],
    [ 0x23d2bc418, 0x522c, 23, 5, 16, 5 ],
    [ 0x23d2bc418, 0x5278, 23, 3, 20, 3 ],
    [ 0x23d2bc418, 0x5018, 31, 1,  2, 1 ],
    [ 0x23d2bc41c, 0x1204,  0, 5,  2, 5 ],
    ];

my $acio_fuse_map = [
    # /* src_addr, dst_offs, src_[lsb,width], dst_[lsb,width] */
    [ 0x23d2bc438, 0x2a38, 19, 6,  0, 7 ],
    [ 0x23d2bc438, 0x2a38, 25, 6, 17, 7 ],
    [ 0x23d2bc438, 0x2aa4, 31, 1, 17, 2 ],
    [ 0x23d2bc438, 0x0a04, 14, 5,  2, 5 ],
    [ 0x23d2bc43c, 0x2aa4,  0, 1, 17, 2 ],
    [ 0x23d2bc43c, 0x2a20,  1, 3, 14, 3 ],
    [ 0x23d2bc438, 0x222c,  7, 2,  9, 2 ],
    [ 0x23d2bc438, 0x222c,  4, 3, 12, 3 ],
    [ 0x23d2bc438, 0x22a4, 12, 2, 17, 2 ],
    [ 0x23d2bc438, 0x2220,  9, 3, 14, 3 ],
    [ 0x23d2bc438, 0x0a04, 14, 5,  2, 5 ],
    ];

sub tunable {
    my ($adtnode, $dtnode, $kind, %props) = @_;
    my ($adtdev, $adtprop) = ($adtnode =~ /^(.*)\.(.*?)$/);
    my ($dtdev, $dtprop) = ($dtnode =~ /^(.*)\.(.*?)$/);
    my $dtreg = $dtdev . ".reg";
    my $adtreg = $adtdev . ".reg";
    my $adtparent = $adtdev;
    $adtparent =~ s/\.[^.]*$//;

    for my $lnode (sort keys %dt) {
	my $rawnode = $lnode;
	$rawnode =~ s/\@[0-9a-f]*//;

	if ($dtreg eq $rawnode) {
	    $props{lreg} = $dt{$lnode};
	}
	my $rawdev = $rawnode;
	$rawdev =~ s/\.[^.]*$//;
	my $ldev = $lnode;
	$ldev =~ s/\.[^.]*$//;
	$props{lnode} = $ldev if $rawdev eq $dtdev;
    }
    unless ($props{lnode}) {
	warn "no lnode for $adtnode";
	return;
    }

    for my $anode (sort keys %adt) {
	if ($adtreg eq $anode) {
	    $props{areg} = $adt{$anode};
	}
	if ($adtnode eq $anode) {
	    $props{abuf} = $adt{$anode};
	} elsif ($adtparent eq $anode) {
	    $props{aparent} = $adt{$anode};
	}
    }

    unless (exists $props{abuf}) {
	warn "no abuf for $adtnode";
	return;
    }
    my $new = "new_from_$kind";
    $tunables{$adtnode} = Tunable->$new(%props);
    if (ref $tunables{$adtnode} eq "Tunable") {
	$tunables{$adtnode} = $tunables{$adtnode}->encode_to_fancy($props{lreg});
    } else {
	$tunables{$adtnode} = DTNode->new("u8", @{$tunables{$adtnode}})->string;
    }
    $ltunables{$props{lnode} . "." . $dtprop} = $tunables{$adtnode} if $props{lnode};
}

for my $v ([0, 0x380000000], [1, 0x500000000]) {
    my $i = $v->[0];
    my $base = $v->[1];

    tunable("arm-io.atc-phy${i}.tunable_ATC0AXI2AF",
	    "soc.usb_drd${i}.tunable-ATC0AXI2AF",
	    fancy => base => $base);
    tunable("arm-io.usb-drd${i}.tunable",
	    "soc.usb_drd${i}.tunable",
	    legacy =>);
    tunable("arm-io.atc-phy${i}.tunable_ATC0AXI2AF",
	    "soc.atcphy${i}.tunable-ATC0AXI2AF",
	    fancy => base => $base);
    tunable("arm-io.atc-phy${i}.tunable_ATC_FABRIC",
	    "soc.atcphy${i}.tunable-ATC_FABRIC",
	    fancy => base => $base + 0x3045000);
    tunable("arm-io.atc-phy${i}.tunable_AUS_CMN_SHM",
	    "soc.atcphy${i}.tunable-AUS_CMN_SHM",
	    fancy => base => $base + 0x3000a00);
    tunable("arm-io.atc-phy${i}.tunable_AUS_CMN_TOP",
	    "soc.atcphy${i}.tunable-AUS_CMN_TOP",
	    fancy => base => $base + 0x3000800);
    tunable("arm-io.atc-phy${i}.tunable_AUSPLL_CORE",
	    "soc.atcphy${i}.tunable-AUSPLL_CORE",
	    fancy => base => $base + 0x3002200);
    tunable("arm-io.atc-phy${i}.tunable_AUSPLL_TOP",
	    "soc.atcphy${i}.tunable-AUSPLL_TOP",
	    fancy => base => $base + 0x3002000);
    tunable("arm-io.atc-phy${i}.tunable_CIO3PLL_CORE",
	    "soc.atcphy${i}.tunable-CIO3PLL_CORE",
	    fancy => base => $base + 0x3002a00);
    tunable("arm-io.atc-phy${i}.tunable_CIO3PLL_TOP",
	    "soc.atcphy${i}.tunable-CIO3PLL_TOP",
	    fancy => base => $base + 0x3002800);
    tunable("arm-io.atc-phy${i}.tunable_CIO_LN0_AUSPMA_RX_EQ",
	    "soc.atcphy${i}.tunable-CIO_LN0_AUSPMA_RX_EQ",
	    fancy => base => $base + 0x300a000);
    tunable("arm-io.atc-phy${i}.tunable_USB_LN0_AUSPMA_RX_EQ",
	    "soc.atcphy${i}.tunable-USB_LN0_AUSPMA_RX_EQ",
	    fancy => base => $base + 0x300a000);
    tunable("arm-io.atc-phy${i}.tunable_CIO_LN0_AUSPMA_RX_SHM",
	    "soc.atcphy${i}.tunable-CIO_LN0_AUSPMA_RX_SHM",
	    fancy => base => $base + 0x300b000);
    tunable("arm-io.atc-phy${i}.tunable_USB_LN0_AUSPMA_RX_SHM",
	    "soc.atcphy${i}.tunable-USB_LN0_AUSPMA_RX_SHM",
	    fancy => base => $base + 0x300b000);
    tunable("arm-io.atc-phy${i}.tunable_CIO_LN0_AUSPMA_RX_TOP",
	    "soc.atcphy${i}.tunable-CIO_LN0_AUSPMA_RX_TOP",
	    fancy => base => $base + 0x3009000);
    tunable("arm-io.atc-phy${i}.tunable_USB_LN0_AUSPMA_RX_TOP",
	    "soc.atcphy${i}.tunable-USB_LN0_AUSPMA_RX_TOP",
	    fancy => base => $base + 0x3009000);
    tunable("arm-io.atc-phy${i}.tunable_CIO_LN0_AUSPMA_TX_TOP",
	    "soc.atcphy${i}.tunable-CIO_LN0_AUSPMA_TX_TOP",
	    fancy => base => $base + 0x300c000);
    tunable("arm-io.atc-phy${i}.tunable_DP_LN0_AUSPMA_TX_TOP",
	    "soc.atcphy${i}.tunable-DP_LN0_AUSPMA_TX_TOP",
	    fancy => base => $base + 0x300c000);
    tunable("arm-io.atc-phy${i}.tunable_USB_LN0_AUSPMA_TX_TOP",
	    "soc.atcphy${i}.tunable-USB_LN0_AUSPMA_TX_TOP",
	    fancy => base => $base + 0x300c000);
    tunable("arm-io.atc-phy${i}.tunable_CIO_LN1_AUSPMA_RX_EQ",
	    "soc.atcphy${i}.tunable-CIO_LN1_AUSPMA_RX_EQ",
	    fancy => base => $base + 0x3011000);
    tunable("arm-io.atc-phy${i}.tunable_USB_LN1_AUSPMA_RX_EQ",
	    "soc.atcphy${i}.tunable-USB_LN1_AUSPMA_RX_EQ",
	    fancy => base => $base + 0x3011000);
    tunable("arm-io.atc-phy${i}.tunable_CIO_LN1_AUSPMA_RX_SHM",
	    "soc.atcphy${i}.tunable-CIO_LN1_AUSPMA_RX_SHM",
	    fancy => base => $base + 0x3012000);
    tunable("arm-io.atc-phy${i}.tunable_USB_LN1_AUSPMA_RX_SHM",
	    "soc.atcphy${i}.tunable-USB_LN1_AUSPMA_RX_SHM",
	    fancy => base => $base + 0x3012000);
    tunable("arm-io.atc-phy${i}.tunable_CIO_LN1_AUSPMA_RX_TOP",
	    "soc.atcphy${i}.tunable-CIO_LN1_AUSPMA_RX_TOP",
	    fancy => base => $base + 0x3010000);
    tunable("arm-io.atc-phy${i}.tunable_USB_LN1_AUSPMA_RX_TOP",
	    "soc.atcphy${i}.tunable-USB_LN1_AUSPMA_RX_TOP",
	    fancy => base => $base + 0x3010000);
    tunable("arm-io.atc-phy${i}.tunable_CIO_LN1_AUSPMA_TX_TOP",
	    "soc.atcphy${i}.tunable-CIO_LN1_AUSPMA_TX_TOP",
	    fancy => base => $base + 0x3013000);
    tunable("arm-io.atc-phy${i}.tunable_DP_LN1_AUSPMA_TX_TOP",
	    "soc.atcphy${i}.tunable-DP_LN1_AUSPMA_TX_TOP",
	    fancy => base => $base + 0x3013000);
    tunable("arm-io.atc-phy${i}.tunable_USB_LN1_AUSPMA_TX_TOP",
	    "soc.atcphy${i}.tunable-USB_LN1_AUSPMA_TX_TOP",
	    fancy => base => $base + 0x3013000);
    tunable("arm-io.atc-phy${i}.tunable_USB_ACIOPHY_TOP",
	    "soc.atcphy${i}.tunable-USB_ACIOPHY_TOP",
	    fancy => base => $base + 0x3000000);
    tunable("arm-io.acio${i}.fw_int_ctl_management_tunables",
	    "soc.acio${i}.tunable-fw_int_ctl_management",
	    pcie => range => 0, base => 0x04000);
    tunable("arm-io.acio${i}.hbw_fabric_tunables",
	    "soc.acio${i}.tunable-hbw_fabric",
	    pcie => range => 3);
    tunable("arm-io.acio${i}.hi_dn_merge_fabric_tunables",
	    "soc.acio${i}.tunable-hi_dn_merge_fabric",
	    pcie => range => 0, base => 0xfc000);
    tunable("arm-io.acio${i}.hi_up_merge_fabric_tunables",
	    "soc.acio${i}.tunable-hi_up_merge_fabric",
	    pcie => range => 0, base => 0xf8000);
    tunable("arm-io.acio${i}.hi_up_tx_desc_fabric_tunables",
	    "soc.acio${i}.tunable-hi_up_tx_desc_fabric",
	    pcie => range => 0, base => 0xf0000);
    tunable("arm-io.acio${i}.hi_up_tx_data_fabric_tunables",
	    "soc.acio${i}.tunable-hi_up_tx_data_fabric",
	    pcie => range => 0, base => 0xec000);
    tunable("arm-io.acio${i}.hi_up_rx_desc_fabric_tunables",
	    "soc.acio${i}.tunable-hi_up_rx_desc_fabric",
	    pcie => range => 0, base => 0xe8000);
    tunable("arm-io.acio${i}.hi_up_wr_fabric_tunables",
	    "soc.acio${i}.tunable-hi_up_wr_fabric",
	    pcie => range => 0, base => 0xf4000);
    tunable("arm-io.acio${i}.lbw_fabric_tunables",
	    "soc.acio${i}.tunable-lbw_fabric",
	    pcie => range => 4);
    tunable("arm-io.acio${i}.pcie_adapter_regs_tunables",
	    "soc.acio${i}.tunable-pcie_adapter_regs",
	    pcie => range => 5);
    tunable("arm-io.acio${i}.top_tunables",
	    "soc.acio${i}.tunable-top",
	    pcie => range => 2);
    tunable("arm-io.acio${i}.thunderbolt-drom",
	    "soc.acio${i}.thunderbolt-drom",
	    plain => size => 4);
    tunable("arm-io.apciec${i}.atc-apcie-debug-tunables",
	    "soc.pciec${i}.tunable-debug",
	    pcie => range => 6);
    tunable("arm-io.apciec${i}.atc-apcie-fabric-tunables",
	    "soc.pciec${i}.tunable-fabric",
	    pcie => range => 4);
    tunable("arm-io.apciec${i}.atc-apcie-oe-fabric-tunables",
	    "soc.pciec${i}.tunable-oe-fabric",
	    pcie => range => 5);
    tunable("arm-io.apciec${i}.atc-apcie-rc-tunables",
	    "soc.pciec${i}.tunable-rc",
	    pcie => range => 0);
    tunable("arm-io.apciec${i}.pcic${i}-bridge.apcie-config-tunables",
	    "soc.pciec${i}.tunable-port0-config",
	    pcie => range => 3, parent => 1);
    tunable("arm-io.apcie.apcie-axi2af-tunables",
	    "soc.pcie.tunable-axi2af",
	    pcie => range => 4);
    tunable("arm-io.apcie.apcie-common-tunables",
	    "soc.pcie.tunable-common",
	    pcie => range => 1);
    tunable("arm-io.apcie.apcie-phy-ip-auspma-tunables",
	    "soc.pcie.tunable-phy-ip-auspma",
	    pcie => range => 3);
    tunable("arm-io.apcie.apcie-phy-ip-pll-tunables",
	    "soc.pcie.tunable-phy-ip-pll",
	    pcie => range => 3);
    tunable("arm-io.apcie.apcie-phy-tunables",
	    "soc.pcie.tunable-phy",
	    pcie => range => 2);
    tunable("arm-io.apcie.pci-bridge0.apcie-config-tunables",
	    "soc.pcie.tunable-port0-config",
	    pcie => parent => 1, range => 6);
    tunable("arm-io.apcie.pci-bridge0.pcie-rc-gen3-shadow-tunables",
	    "soc.pcie.tunable-port0-gen3-shadow",
	    pcie => parent => 1, range => 0);
    tunable("arm-io.apcie.pci-bridge0.pcie-rc-gen4-shadow-tunables",
	    "soc.pcie.tunable-port0-gen4-shadow",
	    pcie => parent => 1, range => 0);
    tunable("arm-io.apcie.pci-bridge0.pcie-rc-tunables",
	    "soc.pcie.tunable-port0",
	    pcie => parent => 1, range => 0);
    tunable("arm-io.apcie.pci-bridge1.apcie-config-tunables",
	    "soc.pcie.tunable-port1-config",
	    pcie => parent => 1, range => 10);
    tunable("arm-io.apcie.pci-bridge1.pcie-rc-gen3-shadow-tunables",
	    "soc.pcie.tunable-port1-gen3-shadow",
	    pcie => parent => 1, range => 0, base => 0x8000);
    tunable("arm-io.apcie.pci-bridge1.pcie-rc-gen4-shadow-tunables",
	    "soc.pcie.tunable-port1-gen4-shadow",
	    pcie => parent => 1, range => 0, base => 0x8000);
    tunable("arm-io.apcie.pci-bridge1.pcie-rc-tunables",
	    "soc.pcie.tunable-port1",
	    pcie => parent => 1, range => 0, base => 0x8000);
    tunable("arm-io.apcie.pci-bridge2.apcie-config-tunables",
	    "soc.pcie.tunable-port2-config",
	    pcie => parent => 1, range => 14);
    tunable("arm-io.apcie.pci-bridge2.pcie-rc-gen3-shadow-tunables",
	    "soc.pcie.tunable-port2-gen3-shadow",
	    pcie => parent => 1, range => 0, base => 0x10000);
    tunable("arm-io.apcie.pci-bridge2.pcie-rc-gen4-shadow-tunables",
	    "soc.pcie.tunable-port2-gen4-shadow",
	    pcie => parent => 1, range => 0, base => 0x10000);
    tunable("arm-io.apcie.pci-bridge2.pcie-rc-tunables",
	    "soc.pcie.tunable-port2",
	    pcie => parent => 1, range => 0, base => 0x10000);
    tunable("chosen.mac-address-ethernet0",
	    "chosen.hwaddr-eth0",
	    plain =>);
    tunable("arm-io.pmgr.voltage-states1",
	    "soc.cpufreq.tunable-ecpu-states",
	    plain => xor => 0);
    tunable("arm-io.pmgr.voltage-states5",
	    "soc.cpufreq.tunable-pcpu-states",
	    plain => xor => 0);
    tunable("arm-io.pmgr.mcx-fast-pcpu-frequency",
	    "soc.cpufreq.tunable-pcpu-fast-freq",
	    plain => xor => 0);
    tunable("arm-io.mcc.dramcfg-data",
	    "soc.cpufreq.tunable-pcpu-fast-dcfg",
	    plain => xor => 0);
    tunable("chosen.mac-address-wifi0",
	    "chosen.hwaddr-wlan0",
	    plain =>);
    tunable("chosen.mac-address-bluetooth0",
	    "chosen.hwaddr-bt0",
	    plain =>);
    tunable("arm-io.wlan.module-instance",
	    "chosen.module-wlan0",
	    plain =>);

    tunable("arm-io.atc-phy${i}.reg",
	    "soc.atcphy${i}.tunable-fuse",
	    fusemap => map => $acio_fuse_map, base => $base + 0x3000000, doread => 1);

    tunable("arm-io.apcie.reg",
	    "soc.pcie.tunable-fuse",
	    fusemap => map => $pcie_fuse_map, base => 0x6800c0000, doread => 1);
}

my %lines;
for my $key (sort keys %ltunables) {
    $lines{"$key = $ltunables{$key}"} = 1
	unless $ltunables{$key} eq "<>";
}

my %props;
my $fh;
open $fh, "./m1lli/scripts/adtp adt|" or die;
while (<$fh>) {
    my ($prop, $pval);
    my @pbuf;
    chomp;
    if (/^(.*?) = (.*)$/) {
	($prop, $pval) = ($1, $2);
	$props{$prop} = DTNode->new("str-le32", $pval);
    }
}
my $fh;
open $fh, "./dt/-tunable.dtp" or die;
while (<$fh>) {
    chomp;

    print "$_\n" if exists $lines{$_};
    delete $lines{$_};
}

for my $line (keys %lines) {
    warn "never saw $line";
}
