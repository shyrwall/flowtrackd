#!/usr/bin/perl
use Net::Pcap;
use NetPacket::Ethernet qw(:strip);
use NetPacket::IP qw(:strip);
use NetPacket::TCP;
use Net::RawIP;
use Net::Subnet qw(subnet_matcher);
use Redis::Fast;
use Data::Dumper;

# Implement Cloudflares TCP Reset Cookies in Perl

my $pcap_filter = "tcp and (tcp[tcpflags] & (tcp-syn|tcp-rst) != 0)";

my $nic = $ARGV[0]; 
my $total_instances = $ARGV[1];
my $instance = $ARGV[2] - 1;

my $ipset = "/usr/sbin/ipset";
my $ipset_whitelist = $nic;
$ipset_whitelist =~ s/\./_/;
$ipset_whitelist = "shield_whitelist_$ipset_whitelist";

# Flush whitelist
system qq($ipset flush $ipset_whitelist);

my %states;

my $redis = Redis::Fast->new;

my $debug = 0;
my $err = '';

# Ignore CF
my $ignored_pfxs = subnet_matcher("103.31.4.0/22","173.245.48.0/20","162.158.0.0/15","197.234.240.0/22","172.64.0.0/13","198.41.128.0/17","104.24.0.0/14","131.0.72.0/22","104.16.0.0/13",
                    "141.101.64.0/18","108.162.192.0/18","103.21.244.0/22","103.22.200.0/22","188.114.96.0/20","190.93.240.0/20");


my $pcap = pcap_open_live("$nic", 96, 0, 1000, \$err);
my $filter;
pcap_compile($pcap, \$filter, "$pcap_filter", 1, 0);
pcap_setfilter($pcap, $filter);
pcap_loop($pcap, 0, \&callback, "get em");

pcap_close($pcap);


sub callback {
        my ($user_data, $hdr, $pkt) = @_;

	my $ts = $hdr->{tv_usec};
	return if ($ts % $total_instances != $instance);
 
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

	my $redis_key = $src_ip."_".$dst_ip."_".$dst_port;
	return if $redis->exists($redis_key);
	
	if($tcp_flags == 2 && !$redis->exists($redis_key)) {
		send_packet($src_ip,$dst_ip,$src_port,$dst_port,$winsize,$seqnum,$options{ts},$options{mss},$epoch);
		print "Sent invalid cookie to $src_ip\n" if $debug;
	}
	if($tcp_flags == 4) {
		return if $states{$src_ip}{$dst_ip}{$dst_port} != $seqnum;
		whitelist($src_ip,$dst_ip,$dst_port,$epoch);
		$redis->set($redis_key, $epoch);
		$redis->expire($redis_key, 3600);
		delete($states{$src_ip}{$dst_ip}{$dst_port});
		print "Whitelisted $src_ip - $dst_ip - $dst_port\n";
	}
}

sub whitelist() {
	my ($src_ip,$dst_ip,$dst_port,$epoch) = @_;
	system qq($ipset add $ipset_whitelist $src_ip,$dst_port,$dst_ip);
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

	$n->send;
	$states{$src_ip}{$dst_ip}{$dst_port} = $seqnum -1;
}

