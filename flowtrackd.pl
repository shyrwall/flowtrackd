#!/usr/bin/perl
use Net::Pcap;
use NetPacket::Ethernet qw(:strip);
use NetPacket::IP qw(:strip);
use NetPacket::TCP;
use Net::RawIP;

# Implement Cloudflares TCP Reset Cookies in Perl

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

my $pcap = pcap_open_live("eth0", 1024, 0, 1000, \$err);
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
        my $dst_ip = $ip_data_dec->{dest_ip};
        my $src_port = $tcp_data_dec->{src_port};
        my $dst_port = $tcp_data_dec->{dest_port};
	my $winsize = $tcp_data_dec->{winsize};
	my $seqnum = $tcp_data_dec->{seqnum};
	my %options = $tcp_data_dec->parse_tcp_options;

	if($tcp_flags == 2) {
		send_packet($src_ip,$dst_ip,$src_port,$dst_port,$winsize,$seqnum,$options{ts},$options{mss});
	}
	if($tcp_flags == 4) {
		return if $states{$src_ip}{$src_port}{$dst_ip}{$dst_port} != $seqnum;
		whitelist($src_ip,$src_port,$dst_ip,$dst_port);
		delete($states{$src_ip}{$src_port}{$dst_ip}{$dst_port});
	}
}

sub whitelist() {
	my ($src_ip,$src_port,$dst_ip,$dst_port) = @_;
	system qq(echo ipset add shield_whitelist $src_ip,$src_port,$dst_ip,$dst_port);
}

sub send_packet() {
	my ($src_ip,$dst_ip,$src_port,$dst_port,$winsize,$seqnum,$ts,$mss) = @_;
	
	my $epoch = time(); 
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
				      ack_seq => $seqnum -1 ,
				      window => $winsize,
	                             },
	                     });	

	my $hex_mss = pack ("n", $mss);
	my $ts = pack ("NN", $epoch, $ts);
	$n->optset(tcp => { type => [ (2, 4, 8, 1, 3) ], data => [ "$hex_mss", "", $ts, "", "\x07" ] });
	$n->send;
	$states{$src_ip}{$src_port}{$dst_ip}{$dst_port} = $seqnum -1;
}
