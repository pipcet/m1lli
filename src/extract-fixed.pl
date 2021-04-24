my %types;

sub setup {
    my($type, $str) = @_;
    $types{$str} = $type;
}

sub setup_tunable {
    setup("tunable", $_[0]);
}

sub setup_adt {
    setup("adt", $_[0]);
}

sub setup_framebuffer {
    setup("framebuffer", $_[0]);
}

sub setup_hwaddr {}
sub setup_chosen {}

for my $acio ("soc.acio1\@501f00000") {
    setup_tunable("${acio}.thunderbolt-drom");
    setup_tunable("${acio}.tunable-fw_int_ctl_management");
    setup_tunable("${acio}.tunable-hbw_fabric");
    setup_tunable("${acio}.tunable-lbw_fabric");
    setup_tunable("${acio}.tunable-fw_int_ctl_management");
    setup_tunable("${acio}.tunable-hi_up_merge_fabric");
    setup_tunable("${acio}.tunable-lbw_merge_fabric");
    setup_tunable("${acio}.tunable-hi_dn_merge_fabric");
    setup_tunable("${acio}.tunable-hi_up_rx_desc_fabric");
    setup_tunable("${acio}.tunable-hi_up_tx_data_fabric");
    setup_tunable("${acio}.tunable-hi_up_tx_desc_fabric");
    setup_tunable("${acio}.tunable-hi_up_wr_fabric");
    setup_tunable("${acio}.tunable-pcie_adapter_regs");
    setup_tunable("${acio}.tunable-top");
}
for my $atcphy ("soc.atcphy1\@500000000") {
    setup_tunable("${atcphy}.tunable-ATC0AXI2AF");
    setup_tunable("${atcphy}.tunable-ATC_FABRIC");
    setup_tunable("${atcphy}.tunable-AUSPLL_CORE");
    setup_tunable("${atcphy}.tunable-AUSPLL_TOP");
    setup_tunable("${atcphy}.tunable-AUS_CMN_SHM");
    setup_tunable("${atcphy}.tunable-AUS_CMN_TOP");
    setup_tunable("${atcphy}.tunable-CIO3PLL_CORE");
    setup_tunable("${atcphy}.tunable-CIO3PLL_TOP");
    setup_tunable("${atcphy}.tunable-USB_ACIOPHY_TOP");
    setup_tunable("${atcphy}.tunable-fuse");
    for my $i (0, 1) {
	setup_tunable("${atcphy}.tunable-CIO_LN${i}_AUSPMA_RX_EQ");
	setup_tunable("${atcphy}.tunable-CIO_LN${i}_AUSPMA_RX_SHM");
	setup_tunable("${atcphy}.tunable-CIO_LN${i}_AUSPMA_RX_TOP");
	setup_tunable("${atcphy}.tunable-CIO_LN${i}_AUSPMA_TX_TOP");
	setup_tunable("${atcphy}.tunable-DP_LN${i}_AUSPMA_TX_TOP");
	setup_tunable("${atcphy}.tunable-USB_LN${i}_AUSPMA_RX_SHM");
	setup_tunable("${atcphy}.tunable-USB_LN${i}_AUSPMA_RX_TOP");
	setup_tunable("${atcphy}.tunable-USB_LN${i}_AUSPMA_RX_TOP");
	setup_tunable("${atcphy}.tunable-USB_LN${i}_AUSPMA_TX_TOP");
    }
}
for my $cpufreq ("soc.cpufreq\@210e00000") {
    setup_tunable("${cpufreq}.tunable-ecpu-states");
    setup_tunable("${cpufreq}.tunable-pcpu-states");
    setup_tunable("${cpufreq}.tunable-pcpu-fast-freq");
    setup_tunable("${cpufreq}.tunable-pcpu-fast-dcfg");
}
for my $pcie ("soc.pcie\@690000000") {
    setup_tunable("${pcie}.tunable-axi2af");
    setup_tunable("${pcie}.tunable-common");
    setup_tunable("${pcie}.tunable-fuse");
    setup_tunable("${pcie}.tunable-phy");
    setup_tunable("${pcie}.tunable-phy-ip-auspma");
    setup_tunable("${pcie}.tunable-phy-ip-pll");
    setup_tunable("${pcie}.tunable-port0");
    setup_tunable("${pcie}.tunable-port0-config");
    setup_tunable("${pcie}.tunable-port0-gen3-shadow");
    setup_tunable("${pcie}.tunable-port0-gen4-shadow");
}
for my $pciec ("soc.pciec0\@3b0000000", "soc.pciec1\@530000000") {
    setup_tunable("${pciec}.tunable-debug");
    setup_tunable("${pciec}.tunable-fabric");
    setup_tunable("${pciec}.tunable-port0-config");
    setup_tunable("${pciec}.tunable-oe-fabric");
    setup_tunable("${pciec}.tunable-ec-fabric");
    setup_tunable("${pciec}.tunable-rc");
}
for my $usb_drd ("soc.usb_drd1\@502280000") {
    setup_tunable("${usb_drd}.tunable");
    setup_tunable("${usb_drd}.tunable-ATC0AXI2AF");
}

setup_adt("adt.contents");
setup_adt("reserved-memory.adt\@800000000");
setup("hwaddr", "chosen.hwaddr-wlan0");
setup("hwaddr", "chosen.hwaddr-bt0");
setup("chosen", "chosen.bootargs");
setup("chosen", "chosen.cmdline");
setup("framebuffer", "framebuffer\@9e0df8000.*");
setup("random", "chose.kaslr-seed");
setup("normal", "soc.applestart\@23b754004.reg");

  LOOP:
while (<STDIN>) {
    chomp;
    my $type = "normal";
    for my $str (keys %types) {
	# yes, yes, this matches the string as a regexp. Good enough for now (TM)
	$type = $types{$str} if /^$str /;
    }
    if (!$fh{$type}) {
	open $fh{$type}, "> $ARGV[0]-$type.dtp";
    }
    $fh{$type}->print("$_\n");
}
