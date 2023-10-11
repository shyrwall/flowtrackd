#!/usr/bin/perl
use Net::Pcap;
use NetPacket::Ethernet qw(:strip);
use NetPacket::IP qw(:strip);
use NetPacket::TCP;
use Net::RawIP;
use Net::Subnet qw(subnet_matcher);
use Data::Dumper;

# Implement Cloudflares TCP Reset Cookies in Perl

my $nic = $ARGV[0]; 

my $ipset = "/usr/sbin/ipset";
my $ipset_whitelist = $nic;
$ipset_whitelist =~ s/\./_/;
$ipset_whitelist = "shield_whitelist_$ipset_whitelist";

# Flush whitelist
system qq($ipset flush $ipset_whitelist);

my $debug = 0;
my $err = '';

my %states;

my %tcp_flags=(FIN => FIN,
               SYN => SYN,
               RST => RST,
               PSH => PSH,
               ACK => ACK,
               URG => URG,
               ECE => ECE,
               CWR => CWR);

# Ignore CF
my $ignored_pfxs = subnet_matcher("103.31.4.0/22","173.245.48.0/20","162.158.0.0/15","197.234.240.0/22","172.64.0.0/13","198.41.128.0/17","104.24.0.0/14","131.0.72.0/22","104.16.0.0/13",
                    "141.101.64.0/18","108.162.192.0/18","103.21.244.0/22","103.22.200.0/22","188.114.96.0/20","190.93.240.0/20");


my $pcap = pcap_open_live("$nic", 74, 0, 1000, \$err);
my $filter;
pcap_compile($pcap, \$filter, "tcp and (tcp[tcpflags] & (tcp-syn|tcp-rst) != 0)", 1, 0);
pcap_setfilter($pcap, $filter);
pcap_loop($pcap, 0, \&callback, "get em");

pcap_close($pcap);


sub callback {
        my ($user_data, $hdr, $pkt) = @_;
        my $eth_data = eth_strip($pkt);
        my $ip_data = ip_strip($eth_data);
        my $ip_data_dec = NetPacket::IP->decode($eth_data);
        my $tcp_data_dec = NetPacket::TCP->decode($ip_data);
	my $tcp_flags = $tcp_data_dec->{flags};
        my $src_ip = $ip_data_dec->{src_ip};
	return if $ignored_pfxs->($src_ip);
        my $dst_ip = $ip_data_dec->{dest_ip};
        my $src_port = $tcp_data_dec->{src_port};
        my $dst_port = $tcp_data_dec->{dest_port};
	my $winsize = $tcp_data_dec->{winsize};
	my $seqnum = $tcp_data_dec->{seqnum};
	my %options = $tcp_data_dec->parse_tcp_options;

	my $epoch = time();

	if($tcp_flags == 2 && ($epoch - $whitelisted{$src_ip}{$dst_ip}{$dst_port}) >= 3600 ) {
		delete($whitelisted{$src_ip}{$dst_ip}{$dst_port});
		send_packet($src_ip,$dst_ip,$src_port,$dst_port,$winsize,$seqnum,$options{ts},$options{mss},$epoch);
		print "Sent invalid cookie to $src_ip\n" if $debug;
	}
	if($tcp_flags == 4) {
		return if $states{$src_ip}{$dst_ip}{$dst_port} != $seqnum;
		whitelist($src_ip,$dst_ip,$dst_port,$epoch);
		delete($states{$src_ip}{$dst_ip}{$dst_port});
		print "Whitelisted $src_ip - $dst_ip - $dst_port\n";
	}
}

sub whitelist() {
	my ($src_ip,$dst_ip,$dst_port,$epoch) = @_;
	system qq($ipset add $ipset_whitelist $src_ip,$dst_port,$dst_ip);
	$whitelisted{$src_ip}{$dst_ip}{$dst_port} = $epoch;
}

sub send_packet() {
	my ($src_ip,$dst_ip,$src_port,$dst_port,$winsize,$seqnum,$ts,$mss,$epoch) = @_;
	
	$n = Net::RawIP->new({
	                      ip => {
	                              saddr => $dst_ip,
	                              daddr => $src_ip,
	                             },
	                      tcp => {
	                              source => $dst_port,
	                              dest   => $src_port,
	                              syn    => 1,
	                              ack    => 1,
				      seq    => $ts,
				      ack_seq => $seqnum - 1,
				      window => $winsize,
	                             },
	                     });	

	# Not needed for RST
	#my $hex_mss = pack ("n", $mss);
	#my $ts = pack ("NN", $epoch, $ts);
	#$n->optset(tcp => { type => [ (2, 4, 8, 1, 3) ], data => [ "$hex_mss", "", $ts, "", "\x07" ] });
	$n->send;
	$states{$src_ip}{$dst_ip}{$dst_port} = $seqnum -1;
}

